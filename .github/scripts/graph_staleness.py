#!/usr/bin/env python3
"""Fail a scheduled run when the published knowledge graph predates HEAD.

The published graphs live at https://ai.imkoris.info/graph/<slug>/ and are
refreshed by hand. This script is the thing that notices when that did not
happen.

Why this cannot just read graphify-out/graph.json:

  * graphify-out/ is gitignored (.gitignore) and untracked -- `git ls-files
    graphify-out` is empty in both repos -- so a GitHub-hosted checkout never
    contains graphify-out/graph.json. A job that greps for it can only fail.
  * graph.json is not published either: /graph/<slug>/graph.json is a 404. The
    publish step is a manual `cp graph.html index.html` plus `cp
    GRAPH_REPORT.md`, so only those two files are reachable over HTTPS.
  * index.html is byte-identical to graph.html, which does embed RAW_NODES /
    RAW_EDGES but strips built_at_commit.

So the graph's commit is read from the first carrier that actually carries it,
and staleness is decided against whatever is reachable:

  1. graphify-out/graph.json -> built_at_commit          [exact]
     Only present when the VPS filesystem is visible: a self-hosted runner, or
     a rebuild artifact downloaded from the graph-rebuild workflow.
  2. published GRAPH_REPORT.md -> "Built from commit: <hash>"   [exact]
     That section is written by graphify's own deterministic
     `cluster-only --no-label`, so it is provenance from the same source as
     (1). The published copies predate the section today, which is why (3)
     exists.
  3. no provenance reachable -> content check              [fallback]
     Run the deterministic, keyless AST pass over HEAD and require every HEAD
     node id to be present in the published graph. A node that exists at HEAD
     but not in the published graph proves the published graph predates it.

Exit codes: 0 graph is current, 1 stale or unverifiable. Never a silent pass.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

COMMIT_IN_REPORT = re.compile(r"Built from commit:\s*`?([0-9a-f]{7,40})`?")
RAW_NODES_MARKER = "const RAW_NODES = "
PUBLISHED_BASE = "https://ai.imkoris.info/graph/{slug}/"


def emit(level: str, message: str) -> None:
    if level != "info" and os.environ.get("GITHUB_ACTIONS"):
        print(f"::{level}::{message}")
    prefix = {"info": "", "warning": "WARNING: ", "error": "ERROR: "}[level]
    print(f"{prefix}{message}", flush=True)


def head_commit(repo_root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read().decode("utf-8", "replace")


def commit_from_graph_json(repo_root: Path) -> str | None:
    path = repo_root / "graphify-out" / "graph.json"
    if not path.is_file():
        emit("info", f"no graphify-out/graph.json at {path} (expected on a hosted runner)")
        return None
    commit = json.loads(path.read_text(encoding="utf-8")).get("built_at_commit")
    if commit:
        emit("info", f"provenance source: {path}")
    return commit


def commit_from_published_report(base: str) -> str | None:
    try:
        text = fetch(base + "GRAPH_REPORT.md")
    except OSError as exc:
        emit("warning", f"could not fetch {base}GRAPH_REPORT.md: {exc}")
        return None
    match = COMMIT_IN_REPORT.search(text)
    if match:
        emit("info", f"provenance source: {base}GRAPH_REPORT.md")
        return match.group(1)
    return None


def published_node_ids(base: str) -> set[str]:
    html = fetch(base + "index.html")
    index = html.index(RAW_NODES_MARKER)
    nodes, _ = json.JSONDecoder().raw_decode(html[index + len(RAW_NODES_MARKER) :])
    return {node["id"] for node in nodes}


def head_node_ids(repo_root: Path, graphify_bin: str, workdir: Path) -> set[str]:
    subprocess.run(
        [
            graphify_bin,
            "extract",
            str(repo_root),
            "--code-only",
            "--no-cluster",
            "--out",
            str(workdir),
        ],
        check=True,
    )
    data = json.loads((workdir / "graphify-out" / "graph.json").read_text(encoding="utf-8"))
    return {node["id"] for node in data["nodes"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--slug", default=None, help="published path segment, e.g. ovnode")
    parser.add_argument("--published-base", default=None)
    parser.add_argument("--graphify-bin", default="graphify")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    slug = args.slug or repo_root.name.lower()
    base = args.published_base or PUBLISHED_BASE.format(slug=slug)

    head = head_commit(repo_root)
    emit("info", f"repo {repo_root.name}  HEAD {head}")
    emit("info", f"published graph {base}")

    built = commit_from_graph_json(repo_root) or commit_from_published_report(base)

    if built:
        # Prefix, not equality: graph.json carries all 40 characters but the
        # published report can only ever carry graphify's 8-char short hash
        # (report.py slices [:8]), and an 8-char stamp on a current graph must
        # not read as "differ".
        if head.startswith(built):
            emit("info", f"OK: graph built from {built[:8]}, HEAD is {head[:8]}")
            return 0
        emit(
            "error",
            f"STALE: published graph was built from {built} "
            f"but HEAD is {head} -- rebuild and republish the graph",
        )
        return 1

    # No carrier exposes the graph's commit. Fall back to content: the AST pass
    # is deterministic and needs no API key, so HEAD can always be re-derived.
    emit(
        "warning",
        f"{base}GRAPH_REPORT.md carries no 'Built from commit' line, so the "
        "graph's commit cannot be named. Falling back to a content check.",
    )
    emit(
        "warning",
        "fix: regenerate the report with `graphify cluster-only . --no-label "
        "--no-viz`, which writes the Graph Freshness section, then republish.",
    )

    try:
        published = published_node_ids(base)
    except (OSError, ValueError) as exc:
        emit("error", f"cannot read the published graph at {base}index.html: {exc}")
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        head_nodes = head_node_ids(repo_root, args.graphify_bin, Path(tmp))

    missing = sorted(head_nodes - published)
    emit("info", f"HEAD AST nodes {len(head_nodes)}, published nodes {len(published)}")
    if not missing:
        emit(
            "warning",
            f"no provenance to compare, but all {len(head_nodes)} HEAD AST nodes "
            "are present in the published graph -- treating as current",
        )
        return 0

    emit(
        "error",
        f"STALE: {len(missing)} node(s) exist at HEAD {head} but are absent from "
        f"the published graph at {base}, which was last built from an older "
        f"commit (its commit is not published, so only HEAD can be named). "
        f"examples: {', '.join(missing[:5])}",
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
