# Architecture

## Layout

```
fckmaleware.php           Bootstrap: constants, PSR-4-style autoloader, hooks
uninstall.php             Removes every table, option, cron hook and the data folder
includes/
  class-plugin.php        Service container, cron wiring, lifecycle (activate/upgrade)
  class-schema.php        Tables (schema v3) and migrations
  class-store.php         Options wrapper: network options on multisite, non-autoloaded otherwise
  class-lock.php          Atomic locks (INSERT IGNORE into the main options table)
  class-paths.php         Safe path resolution, symlink refusal, atomic writes, private data folder
  class-settings.php      Typed settings schema and sanitisation
  class-findings.php      Findings table: upsert, re-infection, stale resolution, queries
  class-activity-log.php  Security event log
  class-signatures.php    Rule loading, validation, ReDoS probes, matching
  detection/              Engine + layers (integrity, location, signature, heuristic), checksums, baselines
  class-scanner.php       File scans: modes, work units, byte-offset resume, cache
  class-file-cache.php    Incremental cache (size, mtime, hash, engine fingerprint)
  class-db-scanner.php    Posts, options and comments on every site
  class-persistence.php   Behaviour and persistence checks (BEH-001 … BEH-011)
  class-monitor.php       Event-driven protection (uploads, installs, users, options)
  class-quarantine.php    Verified isolation, backups, restore
  class-remediation.php   Quarantine, official-copy repair, accept, restore points, auto-quarantine
  class-feed.php          Ed25519 manifest signing and verification
  class-signature-updater.php  Feed download, verification, install, rollback
  class-updater.php       Plugin updates from GitHub releases
  class-notifier.php      E-mail and webhook alerts, grouping, cooldowns, SSRF guard
  class-hardening.php     Optional rules and report-only checks
  class-health.php        Health score with listed deductions
  class-feedback.php      Opt-in GitHub issue links and anonymous statistics
  class-imunify.php       Imunify360 agent adapter (read-only)
  ai/                     Redactor, provider interface, Anthropic and OpenAI-compatible providers, reviewer
  admin/                  UI helpers, action handler, one class per dashboard section
  class-cli.php           WP-CLI commands
signatures/               Shipped database (signatures.json) and its sources
feed/                     Signed update feed published from main
tools/                    Maintainer tools: build, corpus scan, feed keys and publishing, release, intel
tests/                    Unit tests, fixtures (inert malware and clean samples)
```

## Detection

Each file passes through the layers in a fixed order. A file that is verified by integrity, or that belongs to FCK Malware itself, skips the later layers.

1. **Integrity:** core files against `api.wordpress.org` checksums, wordpress.org plugins against `downloads.wordpress.org` checksums, other components against their local baseline, and FCK Malware against its own `checksums.json`.
2. **Location:** PHP in uploads, and hidden dot-PHP files.
3. **Signatures:** regex, byte and hash rules. A confidence of 70 or more is *malicious*; lower is *suspicious*.
4. **Heuristics:** PHP only, and only when no signature matched. The code is tokenised with `token_get_all`, with per-function taint tracking from request input to sinks. A file is reported when it meets the threshold *and* its strongest indicator is at least 40 *and* it has two or more indicators or one of 80 or more.

Every result is upserted into `fckmw_findings`. The outcome is one of:

- *new*;
- *updated*;
- *reinfection*: the finding was resolved or quarantined before;
- *ignored*: the admin accepted it and the file hash is unchanged.

After a complete scan, findings that were not seen again are resolved.

## Scanning

A scan is a state machine in `fckmw_scan_state`:

1. **Listing:** walk the work units, one directory level at a time, appending to a file list in the data folder.
2. **Scanning:** read the list from a byte offset in batches of 100.
3. **Finalize:** missing core files, stale resolution, the `fckmw_scan_complete` action.

Each step stops at its time budget or at 80% of the memory limit, and saves the exact position. Steps are driven by admin AJAX, WP-Cron (`fckmw_scan_continue`) or WP-CLI, under a lock so two steps never overlap.

## Storage

Tables use `base_prefix`, so there is one set per network:

| Table | Holds |
|---|---|
| `fckmw_findings` | Findings |
| `fckmw_files` | Incremental cache |
| `fckmw_baseline` | Local integrity baselines |
| `fckmw_events` | Activity log |

Settings and state live in network options on multisite, and in non-autoloaded options otherwise.

The data folder is `uploads/fckmaleware-<20 random characters>/`. It holds the scan list, the quarantine and downloaded signature databases, and it is protected with deny rules and empty index files.

## Signature updates

1. The maintainer signs `feed/manifest.json` with an Ed25519 key that is kept offline.
2. Sites fetch the manifest twice daily and verify the signature against `SignatureUpdater::PUBLIC_KEYS`.
3. They then check, in turn:
   - the expiry;
   - that the version is newer (anti-replay);
   - the minimum plugin version;
   - the SHA-256 of the database file.
4. Every rule is re-validated, then the database is installed atomically.

The three newest databases are kept for rollback. Any failure keeps the current database and is logged.

## Admin

`Admin` registers the menu (Network Admin on multisite) and dispatches to `admin/pages/*`.

All state changes are POST requests to a single handler, `Admin\Actions`. It checks the capability, then the command against an allowlist, then a per-command nonce, and redirects back with a notice. Scan progress uses AJAX with its own nonce.

The capability is `manage_network_options` on multisite and `manage_options` otherwise.

## Extension points

| Hook | Purpose |
|---|---|
| `fckmw_signature_file` (filter) | Replace the signature database with a self-managed file |
| `fckmw_signature_feed_url`, `fckmw_signature_feed_keys` (filters) | Self-hosted feed and keys |
| `fckmw_scan_exclude_dirs` (filter) | Extra excluded directories |
| `fckmw_trusted_callback_roots` (filter) | Trusted roots for hook-callback checks |
| `fckmw_detection`, `fckmw_finding_recorded`, `fckmw_scan_complete`, `fckmw_db_scan_complete`, `fckmw_event` (actions) | React to results |
