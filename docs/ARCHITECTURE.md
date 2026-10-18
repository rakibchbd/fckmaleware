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
  class-bulk-job.php      Bulk operations on findings: preview, batched resumable jobs, retry
  class-scan-history.php  Newest 100 file and database scans
  class-server-integrations.php  Imunify360 / ImunifyAV / cPGuard detection, tests, status
  class-diagnostics.php   Environment and health checks (no secrets)
  class-secrets.php       Encryption at rest for stored API keys
  class-feedback.php      Opt-in GitHub issue links and anonymous statistics
  class-imunify.php       Imunify360 agent adapter (read-only)
  ai/                     Redactor, provider interface, Anthropic and OpenAI-compatible providers, reviewer
  admin/                  UI components, action handler, one class per tab (admin/pages)
assets/                   admin.css (design system, scoped to .fckmw) and admin.js (dialog, scans, bulk jobs)
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
3. **Signatures:** regex, byte and hash rules. A rule may carry a `prefilter`: literals of which one must occur (case-insensitive) before the regex runs. The build derives it only when every branch of the pattern reduces to plain literals, so it never hides a match. A confidence of 70 or more is *malicious*; lower is *suspicious*.
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

The data folder is `uploads/fckmaleware-<20 random characters>/`. It holds the scan list, the quarantine and downloaded signature databases, and it is protected with deny rules and empty index files. `FCKMW_DATA_DIR` moves it, ideally outside the web root; stored files are migrated with byte-for-byte verification (`Paths::migrate_data_dir`). Quarantine removal renames the original, re-hashes it and only then deletes it; restores of quarantined files use exclusive create and never overwrite.

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

`Admin` registers one top-level menu (Network Admin on multisite) with five sections:

- Overview;
- Scan & Threats: Scanner, Threat Findings, Quarantine, Schedule;
- Protection: Real-Time Protection, Hardening, Signatures, Threat Intelligence, AI Intelligence;
- Integrations: Server Security, Webhooks & Updates;
- Settings & Logs: Settings, Activity Log, Reports, Diagnostics.

A section's tabs are chosen with `&tab=`. `Admin::sections()` is the single source of this structure. `Ui::url( $key )` takes a tab key, which is the pre-1.1 page slug, so every old link and redirect target still works. Requests for the old page slugs are redirected from `admin_page_access_denied`.

`Admin\Ui` holds the shared components:

- the page shell: brand bar, breadcrumbs, title and actions, tabs, flash notice;
- cards, metrics, status pills and badges;
- callouts and empty states;
- form fields (accessible switches, selects, inputs, textareas);
- disclosures and pagination.

CSS and JS are enqueued only on FCK screens, which get the body class `fckmw-screen`. All CSS is scoped.

All state changes go through `Admin\Actions`:

- **POST commands.** Each one checks the capability, then the command against an allowlist, then a per-command nonce, and redirects back with a notice.
- **AJAX.**
  - Scans use the `fckmw_scan` nonce.
  - Bulk jobs use the `fckmw_bulk` nonce.
  - Every step re-checks the capability.

### Automatic removal

`Remediation::maybe_auto_quarantine()` listens to `fckmw_detection`, which fires for scans, event checks, the uploads check and Imunify imports. A finding passing `Remediation::is_verified()` is handed to `auto_remove()`:

- the quarantine runs with the identity re-check;
- the copy carries an `expires` time, honoured by the daily maintenance;
- with 0 days the copy is purged at once.

`sweep_verified()` (cron `fckmw_auto_remove_sweep`) handles verified findings that are already open. It is time-boxed and runs under a lock.

### Bulk jobs

`BulkJob` holds one job at a time in `fckmw_bulk_job`.

1. **Selection.** Either explicit IDs (at most 2,000) or whitelisted filters. Filtered selections are always limited to open findings.
2. **Preview.** Counts what would be processed and why the rest would be skipped. Nothing changes.
3. **Steps.** Each step runs under a lock for about 6 s and handles 25 rows at a time, in ID order. Every row is re-read before it is acted on.
4. **Results.**
   - "Already handled" and "file missing" count as skipped.
   - Permission, lock and disk errors are recoverable failures, which **Retry** turns into a new ID job.
   - Starting and finishing are logged, and a quarantine job records one restore point.

The bulk safety policy is `Remediation::quarantine_eligibility()`.

The capability is `manage_network_options` on multisite and `manage_options` otherwise.

## Extension points

| Hook | Purpose |
|---|---|
| `fckmw_signature_file` (filter) | Replace the signature database with a self-managed file |
| `fckmw_signature_feed_url`, `fckmw_signature_feed_keys` (filters) | Self-hosted feed and keys |
| `fckmw_scan_exclude_dirs` (filter) | Extra excluded directories (absolute); the `scan_exclusions` setting is applied first |
| `fckmw_trusted_callback_roots` (filter) | Trusted roots for hook-callback checks |
| `fckmw_detection`, `fckmw_finding_recorded`, `fckmw_scan_complete`, `fckmw_db_scan_complete`, `fckmw_event` (actions) | React to results |
