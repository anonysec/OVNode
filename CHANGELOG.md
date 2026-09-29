# Changelog

## 1.0.0 — 2026-09-29

First public release.

One installer and one manager per project, with a single source of truth for the
shared shell helpers: `install.sh` sources the library beside it, or fetches it and
sources it only once the whole set has arrived.

**Install**
- Interactive and unattended installs take the same code path, so the two cannot
  configure the machine differently.
- Only three flags: `-y/--yes`, `--docker`, `-h/--help`. Everything else is a
  setting with an `OVN_*` variable, and the older flag spellings still work.
- The installer fetches a verified release archive; nothing is built from source.
- Installing the node no longer disturbs a panel on the same host, even though both
  keep a certificate in `/etc/ssl/self-signed`.

**Manage**
- `ovn credentials` reprints the node name, API key and panel bundle at any time.
- `ovn restore` lists data backups and restores one, taking a safety copy first.
- `ovn completion` installs shell completion.
- `ovn version-script` reports which installer was actually run.
- Read-only commands report an unreadable `.env` as an error instead of reporting
  defaults that look like data.
- Uninstall keeps data unless `--purge`, and defaults to No.
