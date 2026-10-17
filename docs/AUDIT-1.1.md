# 1.1 audit and implementation map

This is the record of the 1.1 redesign:

- what the 1.0.1 code did;
- what changed and where;
- the defects found;
- the checklist used to make sure no feature was lost.

## 1. Starting point (1.0.1)

- Entry point `fckmaleware.php` with a PSR-4-style autoloader. `Plugin` is the service container, booted on `plugins_loaded`.
- **One** top-level menu with **14 submenus**. Every screen also showed a 14-link button bar. There were no duplicate registrations in the code; the crowding came from one entry per screen.
- All state changes went to `Admin\Actions`: capability check, command allowlist, per-command nonce, then redirect. Scans were driven by AJAX with their own nonce.
- There are no REST routes.
- Cron:
  - `fckmw_scheduled_scan`, `fckmw_scan_continue`, `fckmw_db_scan_continue`;
  - `fckmw_daily_maintenance`, `fckmw_signature_update`, `fckmw_process_queue`, `fckmw_notify_flush`.
- Tables (schema 3): `fckmw_findings`, `fckmw_files`, `fckmw_baseline`, `fckmw_events`.
- Findings lifecycle:
  - `Findings::upsert` from scans, events and Imunify sync;
  - statuses open, quarantined, ignored and resolved;
  - `Remediation` quarantines (after re-confirming against the current file), repairs from wordpress.org, accepts, restores, deletes, and keeps restore points;
  - `Quarantine` stores verified, compressed copies in `uploads/fckmaleware-<random>/quarantine`.
- Uploads were screened through `wp_handle_upload_prefilter` and `wp_handle_sideload_prefilter`, using signatures plus heuristics for PHP, with a fixed 80% threshold.

## 2. Navigation map (old slug → new location)

| 1.0 page | 1.1 section → tab | Class |
|---|---|---|
| `fckmaleware` | Overview | `Pages\Overview` |
| `fckmaleware-scanner` | Scan & Threats → Scanner | `Pages\Scanner` |
| `fckmaleware-findings` | Scan & Threats → Threat Findings | `Pages\Findings` |
| `fckmaleware-quarantine` | Scan & Threats → Quarantine | `Pages\Quarantine` |
| `fckmaleware-schedule` | Scan & Threats → Schedule | `Pages\Schedule` |
| `fckmaleware-realtime` | Protection → Real-Time Protection | `Pages\Realtime` |
| `fckmaleware-hardening` | Protection → Hardening | `Pages\Hardening` |
| `fckmaleware-signatures` | Protection → Signatures | `Pages\SignatureDatabase` |
| `fckmaleware-intel` | Protection → Threat Intelligence | `Pages\ThreatIntel` |
| `fckmaleware-ai` | Protection → AI Intelligence | `Pages\Intelligence` |
| `fckmaleware-integrations` | Integrations → Server Security; webhook, updates and CLI moved to Integrations → Webhooks & Updates | `Pages\Integrations`, `Pages\Connections` (new) |
| `fckmaleware-settings` | Settings & Logs → Settings | `Pages\SettingsPage` |
| `fckmaleware-activity` | Settings & Logs → Activity Log | `Pages\Activity` |
| `fckmaleware-reports` | Settings & Logs → Reports | `Pages\Reports` |
| new | Settings & Logs → Diagnostics | `Pages\Diagnostics` (new) |

How links keep working:

- Old slugs are no longer registered, so WordPress denies them before any page code runs. `Admin::redirect_legacy` (on `admin_page_access_denied`) sends authorised users to the new tab with their query arguments.
- `Ui::url( 'findings' )` and every other old key still resolve, so existing redirects, e-mails and notices point to the right place.

## 3. Feature-preservation checklist

Every 1.0.1 feature, and where it is now. All of them were verified by rendering the screen and, where marked, by tests.

| Feature | 1.1 location | Test |
|---|---|---|
| Health score with listed deductions | Overview (ring, "How it is calculated") | e2e |
| Six scan modes, AJAX/cron/CLI drivers, resume, cancel | Scanner (plus two new modes) | e2e, integration |
| Database scan | Scanner (now cancellable) | integration |
| Persistence check | Scanner | integration |
| Incremental cache and clearing it | Scanner | integration |
| Too-large files and unreadable files listed | Scanner → last complete scan | manual |
| Finding list, filters, evidence, excerpt, recommendation, AI badge | Threat Findings (more filters) | e2e |
| Quarantine, repair, accept, resolve, reopen, remove cron event, open in editor | Threat Findings → row actions | integration, e2e |
| Bulk quarantine, accept or resolve (≤ 200 ids, POST) | Kept as the no-JS fallback; the AJAX job replaces it in the UI | integration, e2e |
| False-positive and confirm-malware GitHub links | Threat Findings → detail | manual |
| Quarantine list, restore, delete, restore points, rollback | Quarantine | e2e, integration |
| Event-driven toggles, pending queue, recent events | Real-Time Protection | e2e |
| Automatic quarantine (narrow) | Real-Time Protection → Quarantine | existing integration |
| Six rules and nine checks with risk, compatibility and undo | Hardening (grouped, with risk level) | e2e |
| Heuristic engine description and indicator table | AI Intelligence | render |
| External AI review, consent, redaction, daily limit, usage | AI Intelligence, Settings → Privacy & AI | existing unit |
| Signature list, search, updates, rollback, problems | Signatures (plus verify and history) | integration |
| Intel pipeline, sources, anonymous statistics export | Threat Intelligence (plus source status) | render |
| Schedule, mode, database-after-scan, throttle, size limit | Schedule, Settings → Performance | integration |
| Upcoming cron events | Schedule → task table and queued work | render |
| Reports per period, bars, top rules, CSV exports, print | Reports (more categories) | render |
| Activity log, type and severity filters, CSV | Activity Log (more filters) | render |
| Imunify360 sync and scan | Integrations → Server Security | integration |
| Webhook URL, secret, test, rotation, delivery log | Integrations → Webhooks & Updates | render |
| Plugin updates from GitHub | Integrations → Webhooks & Updates | existing integration |
| WP-CLI reference | Integrations → Webhooks & Updates | render |
| Notification settings | Settings → Notifications | e2e |
| Storage note and uninstall behaviour | Settings → Advanced | render |
| Admin notice when the schema upgrade fails | Unchanged | — |
| Network Admin on multisite | Unchanged (`network_admin_menu`, `edit.php?action=fckmw`) | not run (no multisite site) |

Nothing was removed.

## 4. Defects and risks found, and what was done

| # | Finding | Fix |
|---|---|---|
| 1 | Quarantine read the file, stored a copy, then `unlink()`ed the path. A file replaced between those steps (time-of-check/time-of-use) would be deleted without a copy. | The original is renamed to a hidden name in the same directory (atomic), re-hashed against the stored copy, and only then removed. If it changed or became a symlink, it is put back and nothing is removed. |
| 2 | Restore checked `file_exists()` and then wrote with `rename()`. A file created in between would be overwritten. | Quarantined files are restored with exclusive create (`fopen 'x'`). Only repair backups replace a file, which is their purpose. |
| 3 | `Hardening::set` wrote the whole settings array back. That was harmless in 1.0, but with encrypted secrets it would have stored the decrypted key. | It now goes through `Settings::update`. |
| 4 | The AI API key was stored in plain text in the options table. | Encrypted at rest with libsodium secretbox; `FCKMW_AI_API_KEY` constant supported; plain values written by 1.0 are still read. |
| 5 | Upload blocking used a fixed 80% threshold. Executable extensions relied on WordPress's own file-type check, which `ALLOW_UNFILTERED_UPLOADS` or plugins that widen the allowed types switch off. The visitor was told which signature fired. | A configurable policy, dangerous-extension and image/PHP-mismatch rules, a generic message, and an explicit fail mode. |
| 6 | No repeated-abuse handling for uploads. | Temporary per-account (or per-address) upload blocks; never logins; admins can lift them. |
| 7 | CSV exports loaded up to 10,000 findings into memory. The formula guard missed leading whitespace and `|`. | Exports stream in pages of 500; the guard covers whitespace-prefixed formulas and `|`. |
| 8 | Bulk actions were limited to 200 ticked rows in one request. There was no way to act on "all matching". | AJAX bulk jobs walk any selection by ID in time-boxed batches, with preview, counts, retry, cancel and an audit log. |
| 9 | Uploads written outside WordPress (FTP, other plugins) were only found by the next full scan. | Periodic uploads check of files changed since the last run, clearly labelled as detection. |
| 10 | Scheduled scans started one hour after a settings save, at a random time of day. A scheduled scan that collided with a running scan failed silently. | Time-of-day scheduling in the site time zone; every task records ok/skipped/error with a message; integrity runs retry an hour later when skipped. |
| 11 | Scan history was only in the activity log, with no per-scan rows. | `ScanHistory` keeps the newest 100 file and database scans (complete, cancelled, failed). |
| 12 | The quarantine could only live inside uploads. | `FCKMW_DATA_DIR` with verified migration; Diagnostics and Quarantine show where it is. |
| 13 | Uninstall always deleted all data. | "Keep data when the plugin is deleted" setting. |
| 14 | The activity log retention was fixed at 180 days. | `log_retention_days` (30–365). |
| 15 | No index for filtered finding lists. | Schema 4 adds `(status, severity)`, `detected_at` and `quarantine_key` indexes. |
| 16 | The schema upgrade ran on `plugins_loaded`, so its translated log message loaded the text domain too early (a WordPress 6.7+ notice). | The upgrade runs on `init`. |
| 17 | `window.confirm()` for every destructive action. | An accessible `<dialog>` (focus return, Esc to cancel, destructive styling, preview details). |
| 18 | Image/PHP mismatch rule (found while testing 1.1): unknown extensions such as `.txt` fell back to the "image" type. | The rule only applies to real raster-image extensions; a regression test covers it. |

Security model, unchanged and verified:

- every state change checks the capability and a per-command nonce;
- AJAX checks the capability and its own nonce on every step;
- SQL uses `$wpdb->prepare`;
- output is escaped;
- paths are resolved under the root, with symlinks refused;
- server agents run without a shell.

The WPCS security sniffs (EscapeOutput, NonceVerification, ValidatedSanitizedInput, PreparedSQL, SafeRedirect) report 0 issues, and PHPCompatibility (`testVersion 7.4-`) reports 0 issues.
