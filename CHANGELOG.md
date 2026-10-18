# Changelog

## 1.1.0 (2026-10-17)

A redesign of the whole admin plus safety, protection and integration work. Data from 1.0.x is kept; see `docs/MIGRATION.md` and `docs/AUDIT-1.1.md`.

### Admin
- **FCK Security**: one menu with five sections and contextual tabs instead of 14 submenus and a 14-button bar. Old screen addresses redirect to their new tab.
- New scoped design system:
  - brand bar with protection state and last/next scan;
  - breadcrumbs, tabs, cards, metrics, status pills, empty states;
  - an accessible confirmation dialog instead of browser `confirm()`;
  - switches, responsive layout down to 390 px, visible focus states.
- Overview rebuilt:
  - security score ring with its deductions;
  - confirmed malware, suspicious files, quarantined files and false positives;
  - last and next scan and signature freshness;
  - section shortcuts, recent scans, a seven-day threat breakdown and prioritised recommendations;
  - system status, quick actions and recent events.
- Threat Findings:
  - classification (confirmed, likely malicious, suspicious, unverified change);
  - filters for verdict, confidence band, file type and date;
  - live file size and hash change notice;
  - select all matching, and "Quarantine all eligible".
- New Diagnostics tab and a Webhooks & Updates tab. Settings are consolidated into groups with import, export and reset.

### Scanning and remediation
- Bulk jobs: preview, batched resumable processing, success/failed/skipped counts, cancel, retry of recoverable failures, audit log, one restore point.
- Bulk safety policy. Never core or configuration files; suspicious-only, low-confidence, injected-code and active-plugin heuristic findings are left for review.
- One-click **Quarantine all** menu on the Overview and Threat Findings, each with one preview dialog:
  - **all eligible** (recommended, the bulk safety policy);
  - **all confirmed malware**;
  - **all malicious**;
  - **every flagged file**, including suspicious ones.

  Core and configuration files are never moved, whichever scope is chosen.
- Quarantine removal re-verifies the file identity (rename, re-hash, then delete). Restores use exclusive create and never overwrite.
- `FCKMW_DATA_DIR` keeps the quarantine outside the web root, with verified migration.
- New scan modes: plugins & themes, uploads. Scan history of the newest 100 scans. Database scans can be cancelled. Scan exclusions setting. The data folder can no longer be scanned as a custom directory.
- Quarantine screen: search, type filter, pagination, bulk restore and delete, storage location notice.

### Protection
- Upload policy:
  - block mode (malicious, strict, monitor) and confidence threshold;
  - executable file types, including double extensions, refused;
  - images containing PHP refused;
  - fail mode for inspection errors;
  - a generic message to the uploader;
  - files too large to inspect are logged as not inspected.
- Temporary per-account (or per-address) upload blocks after repeated malicious uploads. Uploads only, never logins; administrators can lift them.
- Periodic uploads check for files written outside WordPress (detection).
- Real-Time Protection is organised as prevention, detection, quarantine, blocking and notifications, with a coverage table.
- Hardening grouped by area, with risk level, current and recommended state, an HTTP test of the uploads rule, and a backup of `uploads/.htaccess` before changes.

### Scheduling
- Time of day in the site time zone. Scheduled core integrity check and uploads check.
- Per-task last run and status. A task that meets a running scan is skipped and logged.

### Integrations
- Integration center for Imunify360, ImunifyAV and cPGuard: detection, connection tests (rate-limited), capabilities, setup and troubleshooting.
- A remediation-owner policy for when FCK Malware and a server scanner both run.
- AI connection test with a fixed sample containing no site data.

### Security and data
- The AI API key is encrypted at rest (libsodium); `FCKMW_AI_API_KEY` constant.
- CSV exports are streamed; formula neutralisation also covers whitespace-prefixed formulas and `|`. Activity export per category and period.
- Activity log: user, period and text filters, retention setting.
- "Keep data when the plugin is deleted" setting.
- Schema 4: indexes for filtered lists and bulk jobs.
- The schema upgrade runs on `init`, which fixes a WordPress 6.7+ early translation notice.

### Tests
- New unit checks (policies, classification, exclusions, CSV, secrets).
- A new integration suite, `tests/integration/features.php`.
- The end-to-end test was rewritten for the new navigation, dialog, bulk flow and mobile layout.

## 1.0.1 (2026-10-17)
- Plugin updates are delivered straight from the `main` branch on GitHub. A version bump pushed to `main` is offered to every site, and auto-update is on by default.

## 1.0.0 (2026-10-17)

A rewrite of 0.2.0 into a layered protection system. Data from 0.x is migrated automatically; see `docs/MIGRATION.md`.

### Detection
- Signature schema 2:
  - regex, byte-pattern and SHA-256 hash rules with family, confidence, licence and false-positive notes;
  - validation with backtracking stress probes;
  - PCRE failures recorded per scan instead of ignored.
- 45 rules, up from 26.
- New heuristic layer: token-based taint tracking from request input to execution sinks, plus obfuscation indicators. It produced 0 false positives on 40,761 clean files.
- Integrity layer:
  - core and wordpress.org plugin checksums;
  - local baselines for other components;
  - FCK Malware's own `checksums.json`;
  - missing core files.
- Location rules: PHP in uploads, hidden dot-PHP files.
- Behaviour and persistence checks (BEH-001 to BEH-011).
- Database scanner for posts, options and comments on every site.

### Scanning
- Six modes: quick, standard, deep, core, recent and custom.
- Bounded, resumable listing and scanning with byte offsets and a scan lock.
- Incremental cache.
- Files over the size limit are reported, not skipped silently.

### Protection and remediation
- Event-driven checks: upload blocking, install and update queue, administrator and option monitoring.
- Quarantine verifies its copy before removing the original, and restore preserves permissions and modification time.
- Official-copy repair from wordpress.org, checksum-verified, with a backup.
- Restore points and rollback.
- Opt-in automatic quarantine for very high-confidence cases only.
- Six optional hardening rules, each with risk, compatibility and undo notes, plus nine report-only checks.

### Updates and intelligence
- Ed25519-signed signature feed with expiry, anti-replay, hash checks, re-validation and rollback.
- Maintainer tooling for collecting, testing, approving and publishing rules from openly licensed sources (URLhaus, MalwareBazaar, signature-base). Nothing is approved automatically.
- Opt-in feedback: pre-filled GitHub issues and anonymous statistics export.

### Notifications
- Grouped e-mail alerts with cooldowns.
- HMAC-signed webhooks with a guard against private-address targets.
- Dashboard notices.

### AI (optional, off by default)
- Advisory second opinion from Anthropic Claude or an OpenAI-compatible endpoint, which can be self-hosted.
- Explicit consent, redaction and a daily limit.
- The model cannot change anything.

### Admin
- 14-section dashboard built only from real data.
- Health score with listed deductions.
- Reports with CSV export.
- Activity log.
- Network Admin on multisite.
- A visible error if the database upgrade fails.

### Other
- Plugin updates come straight from the `main` branch on GitHub: a version bump pushed to `main` is offered to every site. No release or Actions run is needed, and GitHub releases are still honoured if newer. Auto-update is on by default and can be turned off by administrators.
- WP-CLI commands for everything above.
- `uninstall.php` removes all v3 data.
- Release builds no longer need GitHub Actions (`tools/build-release.sh`).

### Changed
- Storage is network-wide on multisite.
- The data folder has a random name.
- Settings and quarantine move to network options on multisite.

## 0.2.0
- GitHub-based plugin updates.

## 0.1.0
- First version: 26 signatures, core integrity, Imunify360 sync, quarantine.
