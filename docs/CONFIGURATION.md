# Configuration

All settings are in the dashboard; the section is given for each one below. They are stored in the `fckmw_settings` option, as a network option on multisite. Values are validated against a typed schema (`includes/class-settings.php`), and out-of-range numbers are clamped.

## Scanning (Scan Schedule, Settings)

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

## Event-driven protection (Real-Time Protection)

| Setting | Default | Effect |
|---|---|---|
| `realtime_uploads` | on | Refuse uploads matching a malicious signature with ≥ 80% confidence; record others |
| `realtime_installs` | on | Queue a check after plugin or theme install, update or activation |
| `monitor_users` | on | Alert on new administrators, promotions and super-admin grants |
| `monitor_options` | on | Alert on changes to site or home URL, admin email, registration, default role, role capabilities, active plugins and theme |
| `auto_quarantine` | **off** | See below |

`auto_quarantine` only acts on **malicious** detections outside core, and only in these cases:

- a signature with confidence ≥ 90 that is an exact hash, an image, or a file in uploads;
- a heuristic detection with confidence ≥ 95 in uploads.

Each action is logged and can be restored.

## Remediation

| Setting | Default | Range | Effect |
|---|---|---|---|
| `quarantine_retention` | 0 | 0–3650 days | Delete quarantined copies after N days; 0 keeps them until deleted |

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

## Imunify360 (Integrations)

| Setting | Default | Effect |
|---|---|---|
| `imunify_enabled` | off | Import Imunify360's malicious-file list for this site |
| `imunify_binary` | auto | Agent path; one of the known install paths |
| `imunify_use_sudo` | off | Run through `sudo`. Only if the host granted a rule for that binary. |
| `imunify_sync_scan` | on | Sync after every FCK Malware scan |

The agent is queried with `proc_open`. If that function is disabled, the integration is unavailable, and the dashboard says so.

## External AI review (Settings → External AI review)

| Setting | Default | Effect |
|---|---|---|
| `ai_provider` | `none` | none, anthropic, openai_compatible |
| `ai_consent` | off | Required before anything is sent |
| `ai_api_key` | empty | Stored in the options table. Leave empty to keep the stored key; enter `-` to remove it. |
| `ai_model` | empty | Anthropic default: `claude-opus-5-5`. Required for OpenAI-compatible endpoints. |
| `ai_endpoint` | empty | OpenAI-compatible chat completions URL, e.g. a local Ollama or vLLM server |
| `ai_max_chars` | 6000 (500–20000) | Maximum excerpt length sent |
| `ai_daily_limit` | 25 (1–1000) | Maximum reviews per day |

## Hardening (Security Hardening)

Stored in `fckmw_hardening`. All rules are off by default. Turning a rule off undoes it.

| Rule | Mechanism |
|---|---|
| `uploads_php` | Marked block in `uploads/.htaccess` (Apache/LiteSpeed). The nginx rule is shown in the dashboard. |
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
