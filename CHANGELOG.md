# Changelog

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
