# Configuration

All settings are in the dashboard under **FCK Security**; the screen is given for each one below. **Settings & Logs → Settings** shows every group in one place (general, scanning, automatic protection, quarantine, notifications, integrations, performance, privacy, advanced) and can export settings as JSON (API keys excluded), import them (validated value by value) and reset them to defaults (API keys kept). They are stored in the `fckmw_settings` option, as a network option on multisite. Values are validated against a typed schema (`includes/class-settings.php`), and out-of-range numbers are clamped.

## Scanning (Scan & Threats → Schedule, Settings)

| Setting | Default | Range | Effect |
|---|---|---|---|
| `schedule` | `daily` | off, hourly, twicedaily, daily, weekly | Automatic file scan frequency |
| `scheduled_mode` | `standard` | quick, standard, deep | Mode used by scheduled scans |
| `scheduled_db_scan` | on | | Database scan and persistence check after each scheduled file scan |
| `throttle_ms` | 0 | 0–500 | Pause between files, to reduce load on shared hosting |
| `max_file_size_mb` | 4 | 1–64 | Larger files are listed as not checked |
| `scan_images` | off | | Check images in standard and quick scans (deep scans always do) |
| `core_integrity` | on | | Compare core files with official checksums |
| `plugin_integrity` | on | | Compare wordpress.org plugins with official checksums |
| `heuristics` | on | | Heuristic layer |
| `heuristic_threshold` | 60 | 30–95 | Minimum heuristic score to report |
| `scan_exclusions` | empty | one path per line | Directories (relative to the WordPress root) skipped by every scan. `..`, absolute drive paths, NUL bytes and unusual characters are dropped. Malware in an excluded folder is never found. |
| `schedule_hour` | 3 | 0–23 | Hour (site time zone) at which daily and weekly scans start; the integrity check runs two hours later, cleanup one hour later |
| `integrity_schedule` | `weekly` | off, daily, weekly | Scheduled WordPress core integrity scan |
| `uploads_watch` | `twicedaily` | off, hourly, twicedaily, daily | Periodic check of files added to uploads since the previous run (detection, not prevention) |

## Event-driven protection (Protection → Real-Time Protection)

| Setting | Default | Effect |
|---|---|---|
| `realtime_uploads` | on | Inspect uploads (media library, REST API, sideloads) before WordPress stores them |
| `upload_block_mode` | `malicious` | `malicious`: refuse malicious detections at or above the threshold. `strict`: also refuse suspicious detections (≥ 60%). `monitor`: never refuse, only record findings |
| `upload_block_confidence` | 80 (50–100) | Threshold for `malicious` mode |
| `block_dangerous_extensions` | on | Refuse executable types (`.php`, `.phtml`, `.phar`, `.cgi`, `.pl`, `.py`, `.asp(x)`, `.jsp`, `.sh`, `.shtml`, …) anywhere in the name, plus `.htaccess`, `.user.ini`, `php.ini`, `web.config` |
| `block_mime_mismatch` | on | Refuse files with a raster-image extension whose first 2 MB contain a PHP open tag |
| `upload_fail_mode` | `allow` | If inspection throws an error: `allow` accepts and logs a warning; `reject` refuses the upload |
| `upload_rate_limit` | 3 (0–20) | Refused uploads within one hour that trigger a temporary upload block for that account (logged-in) or connection address (anonymous). 0 disables blocking |
| `upload_block_minutes` | 60 (5–1440) | Length of a temporary upload block. Only uploads are blocked, never logins or page views |
| `realtime_installs` | on | Queue a check after plugin or theme install, update or activation |
| `monitor_users` | on | Alert on new administrators, promotions and super-admin grants |
| `monitor_options` | on | Alert on changes to site or home URL, admin email, registration, default role, role capabilities, active plugins and theme |
| `auto_quarantine` | **off** | See below |

`auto_quarantine` only acts on **malicious** detections outside core, and only in these cases:

- a signature with confidence ≥ 90 that is an exact hash, an image, or a file in uploads;
- a heuristic detection with confidence ≥ 95 in uploads.

Each action is logged and can be restored.

Upload failure behaviour, per case:

| Case | Result |
|---|---|
| Refused by policy | Rejected with a generic message; details in the activity log |
| Account or address temporarily blocked | Rejected |
| File larger than `max_file_size_mb` | Accepted, logged as `upload.not_inspected` |
| Inspection error (e.g. corrupt signature database) | `upload_fail_mode` |
| Written outside WordPress's upload API | Not seen at write time; found by the uploads check or the next scan |

## Remediation (Protection → Real-Time Protection, Settings → Quarantine)

| Setting | Default | Range | Effect |
|---|---|---|---|
| `quarantine_retention` | 0 | 0–3650 days | Delete quarantined copies after N days; 0 keeps them until deleted |
| `bulk_min_confidence` | 80 | 50–100 | Minimum confidence for "Quarantine all eligible" and filtered bulk quarantine |

The one-click **Quarantine all** menu (Overview and Threat Findings) has four scopes:

| Scope | Selects | Skips |
|---|---|---|
| All eligible (recommended) | Open findings | Everything listed below |
| All confirmed malware | Malicious, 90%+ from signatures or a server scanner | Hard rules, integrity differences, injected-code findings |
| All malicious | Every malicious verdict | Hard rules, integrity differences, injected-code findings |
| Every flagged file | Every open file finding, suspicious ones included | Hard rules only |

The hard rules always apply: no database records, missing files, core files or configuration files. Every scope shows a preview with counts and skip reasons before anything moves, and records one restore point.

Bulk quarantine of filtered or "all eligible" findings skips: non-file findings, missing files, core files (except unknown files in core folders), critical configuration files (`.htaccess`, `.user.ini`, `php.ini`, `web.config`, `wp-config.php` at the root), integrity differences, injected-code findings (`clean`/`repair`), suspicious-only verdicts, confidence below `bulk_min_confidence`, and heuristic matches in active plugins, must-use plugins or the active theme. Explicitly ticked findings only get the hard rules (non-file, missing, core, configuration).

### Data folder outside the web root

Define in `wp-config.php`:

```php
define( 'FCKMW_DATA_DIR', '/home/account/fckmw-data' );
```

The path must be absolute and writable by PHP. Existing quarantine copies and downloaded signature databases are copied to the new folder, verified byte-for-byte and removed from the old one on the next admin page load. Without it, data lives in `uploads/fckmaleware-<random>/` with deny rules and non-executable, compressed storage.

## Notifications (Settings, Integrations)

| Setting | Default | Effect |
|---|---|---|
| `email_alerts` | on | E-mail alerts |
| `alert_email` | empty | Recipient; empty means the site or network admin e-mail |
| `notify_min_severity` | `high` | Lowest finding severity that alerts |
| `notify_cooldown_hours` | 24 (1–168) | Do not repeat the same alert within this time |
| `notify_scan_complete` | off | Summary after scheduled scans |
| `dashboard_notices` | on | Admin notice while high or critical findings are open, or after a critical event |
| `webhook_url` | empty | JSON webhook signed with HMAC-SHA256 (`X-FCKMW-Signature`); public addresses only |

Alerts within two minutes of each other are grouped into one message.

## Updates

| Setting | Default | Effect |
|---|---|---|
| `signature_updates` | on | Check the signed feed twice daily |

Self-hosted feeds can be configured with filters (`docs/ARCHITECTURE.md`):

- `fckmw_signature_feed_url`
- `fckmw_signature_feed_keys`
- `fckmw_signature_file`, to replace the database outright

## Server scanners (Integrations → Server Security)

| Setting | Default | Effect |
|---|---|---|
| `imunify_enabled` | off | Import the Imunify360 / ImunifyAV malicious-file list for this site |
| `imunify_binary` | auto | Agent path; one of the four known install paths, nothing else |
| `imunify_use_sudo` | off | Run through `sudo -n`. Only if the host granted a rule for that binary. |
| `imunify_sync_scan` | on | Sync after every FCK Malware scan |
| `primary_scanner` | `fckmw` | `server` pauses FCK Malware's automatic quarantine while the server scanner is enabled, so two products never move the same file |

See [INTEGRATIONS.md](INTEGRATIONS.md).

The agent is queried with `proc_open`. If that function is disabled, the integration is unavailable, and the dashboard says so.

## External AI review (Settings → External AI review)

| Setting | Default | Effect |
|---|---|---|
| `ai_provider` | `none` | none, anthropic, openai_compatible |
| `ai_consent` | off | Required before anything is sent |
| `ai_api_key` | empty | Stored encrypted (libsodium secretbox, key derived from the site's auth salt). Leave empty to keep the stored key; enter `-` to remove it. `define( 'FCKMW_AI_API_KEY', '…' )` in wp-config.php overrides it. If the salts change, re-enter the key. |
| `ai_model` | empty | Anthropic default: `claude-opus-5-5`. Required for OpenAI-compatible endpoints. |
| `ai_endpoint` | empty | OpenAI-compatible chat completions URL, e.g. a local Ollama or vLLM server |
| `ai_max_chars` | 6000 (500–20000) | Maximum excerpt length sent |
| `ai_daily_limit` | 25 (1–1000) | Maximum reviews per day |

## Logs and data (Settings → Advanced)

| Setting | Default | Effect |
|---|---|---|
| `log_retention_days` | 180 (30–365) | Activity log age limit; at most 20,000 entries are kept regardless |
| `keep_data_on_uninstall` | off | When on, deleting the plugin removes only its scheduled events, so a reinstall keeps findings, quarantine, logs and settings |

## Hardening (Protection → Hardening)

Stored in `fckmw_hardening`. All rules are off by default. Turning a rule off undoes it.

| Rule | Mechanism |
|---|---|
| `uploads_php` | Marked block in `uploads/.htaccess` (Apache/LiteSpeed); the file is backed up to the data folder (newest five kept) before every change. **Test** writes a harmless probe to uploads, requests it over HTTP and deletes it, to show whether the server enforces the rule. The nginx rule is shown in the dashboard. |
| `disallow_file_edit` | Defines `DISALLOW_FILE_EDIT` at runtime |
| `disable_xmlrpc` | Disables XML-RPC, including all methods |
| `rest_users` | Hides `/wp/v2/users` from anonymous requests |
| `author_enum` | Blocks `?author=N` enumeration |
| `security_headers` | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |

## WP-Cron

Scheduled work needs WP-Cron. With `DISABLE_WP_CRON`, add a system cron, for example:

```
*/5 * * * * wp --path=/var/www/site cron event run --due-now >/dev/null 2>&1
```
