# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The real-system-paths guard belongs to the controller, once per run.

A session-scoped fixture ran in every xdist worker: one host event became N
worker errors, and a worker that started late took its before-snapshot after
the damage, so its window covered less than the run. The guard now lives in
pytest_configure/pytest_sessionfinish, skipped in workers (PYTEST_XDIST_WORKER
is set by xdist before conftest loads), and these tests pin that behavior:
snapshot only on the controller, one verdict per run, exit status 1 on a
genuine write.
"""

import conftest


class _PluginManager:
    def get_plugin(self, name):
        return None  # no terminalreporter: the hooks must still fail the run


class _Config:
    def __init__(self):
        self.pluginmanager = _PluginManager()


class _Session:
    def __init__(self, config):
        self.config = config
        self.exitstatus = 0


def test_controller_snapshots_on_configure(monkeypatch):
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    monkeypatch.setattr(conftest, "_snapshot", lambda: {"p": "v"})
    config = _Config()
    conftest.pytest_configure(config)
    assert config._ovnode_paths_before == {"p": "v"}


def test_worker_skips_the_snapshot(monkeypatch):
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    config = _Config()
    conftest.pytest_configure(config)
    assert not hasattr(config, "_ovnode_paths_before")


def test_a_clean_run_keeps_its_exit_status(monkeypatch):
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    monkeypatch.setattr(conftest, "_snapshot", lambda: {"p": "same"})
    config = _Config()
    conftest.pytest_configure(config)
    session = _Session(config)
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 0


def test_a_changed_path_fails_the_run(monkeypatch, capsys):
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    snapshots = iter([{"p": "before"}, {"p": "after"}])
    monkeypatch.setattr(conftest, "_snapshot", lambda: next(snapshots))
    config = _Config()
    conftest.pytest_configure(config)
    session = _Session(config)
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 1
    # The verdict must be visible in the run's output, not only in the code.
    assert "modified real system paths" in capsys.readouterr().err


def test_a_worker_session_is_never_failed_by_the_guard(monkeypatch):
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw1")
    session = _Session(_Config())
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 0
