# FCK Malware 1.0: Implementation Plan

Order is driven by dependencies: later layers build on the storage, locking and engine work done first. Each step is tested before the next starts, and the plugin stays installable and working after every commit.

| Step | Work | Depends on | Brief phases |
|---|---|---|---|
| 1 | Audit (`docs/AUDIT.md`) and this plan | — | 1 |
| 2 | Infrastructure: DB schema v2 (findings columns, file cache, baselines, activity log), atomic locks, private randomized data dir with migration, safe file-operation helpers, multisite capability fix | 1 | 7, 14, 15 |
| 3 | Detection engine: layer interface; signature schema v2 (regex, byte patterns, SHA-256 hashes, full metadata); token-based heuristic engine with entropy and obfuscation scoring; integrity layer (core, wordpress.org plugins, local baselines, self-integrity); location layer | 2 | 2, 3 (local mode) |
| 4 | Scanner: modes, bounded listing by work units, byte-offset resume, incremental cache, finding upserts and stale resolution, scan lock | 2, 3 | 6, 14 |
| 5 | Database scanner, behaviour and persistence checks, event-driven protection hooks | 2, 3 | 2D, 6, 9 |
| 6 | Remediation: hardened quarantine, official-copy repair, opt-in high-confidence auto-quarantine, expiry, audit trail | 2, 3 | 7 |
| 7 | Signed signature feed (Ed25519) with rollback; maintainer signing tools; local release build | 3 | 11, 17 |
| 8 | Notification engine | 2 | 13 |
| 9 | Hardening checks module | 2 | 8 |
| 10 | AI: local intelligence summary plus an optional, advisory-only external provider interface | 3 | 3 |
| 11 | Threat-intelligence collectors and candidate pipeline (maintainer side), false-positive feedback | 3, 7 | 4, 5 |
| 12 | Admin redesign (14 sections, real data only), WP-CLI additions | 2–11 | 12 |
| 13 | Test suites (unit, WordPress integration, end-to-end), security self-review, documentation, release | all | 15, 16, 17 |

## Constraints that shape the design

- **Shared hosting:** no daemons, no root, no Python or GPU. All heavy work happens in time-boxed background steps (WP-Cron, system cron, WP-CLI or admin AJAX), never on front-end requests.
- **Real-time means event-driven:** WordPress hooks fire on uploads, installs, updates and user changes. A plugin cannot watch the filesystem continuously, so changes made outside WordPress (FTP, other compromised accounts) are only caught by scheduled scans.
- **No server-side telemetry backend:** the project has no server, so "learning" works through opt-in, user-initiated reports (pre-filled GitHub issues with sanitized metadata). Maintainers review them, and accepted changes ship through the signed feed. Nothing is collected silently.
- **External AI is optional and advisory:** it receives redacted excerpts with the user's explicit consent. It can never quarantine, delete, edit or execute anything.
- **Threat intelligence sources:** only sources whose licence allows redistribution, recorded in `docs/THREAT-INTEL-SOURCES.md`. Imunify360 signatures are proprietary and are never copied.
