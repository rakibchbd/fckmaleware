# Installation, upgrade, rollback and troubleshooting

## Requirements

| | |
|---|---|
| WordPress | 5.8 or later (tested on 7.1.3) |
| PHP | 7.4 or later (run on 8.3; 7.4–8.2 checked statically) |
| PHP extensions | `tokenizer`, `json`, `hash` (required). `zlib`, `openssl`/`curl` are recommended. libsodium comes from PHP or WordPress's bundled `sodium_compat`. |
| Database | MySQL or MariaDB through `$wpdb` (tested on SQLite through WordPress's SQLite integration) |
| Cron | WP-Cron, or a system cron calling `wp-cron.php` when `DISABLE_WP_CRON` is set |
| Optional | `proc_open` for server-scanner agents |

No shell access, root or daemon is needed. **Settings & Logs → Diagnostics** checks all of this on your server.

## Install

1. Upload `fckmaleware.zip` in **Plugins → Add New → Upload Plugin**, then activate it (network-activate on multisite).
2. Open **FCK Security → Scan & Threats** and run a **Full** scan.
3. Review **Protection** (upload policy, automatic quarantine) and **Protection → Hardening**.
4. Optional: define `FCKMW_DATA_DIR` in `wp-config.php` to keep the quarantine outside the web root ([CONFIGURATION.md](CONFIGURATION.md)).

## Upgrade from 1.0.x

The upgrade is automatic and keeps everything: findings, the quarantine, restore points, logs, settings, baselines and hardening state. See [MIGRATION.md](MIGRATION.md).

## Roll back to 1.0.x

1. Deactivate 1.1, then install the 1.0.1 zip over it. Do **not** delete the plugin, because that runs the uninstaller.
2. 1.0.1 reads all the data, with these differences:
   - The schema-4 indexes are harmless to it.
   - It ignores the new settings.
   - Bookmarked new URLs (`?page=fckmaleware-scan&tab=…`) do not exist in 1.0.1.
3. An AI API key saved by 1.1 is stored encrypted, and 1.0.1 cannot read it. Re-enter it in 1.0.1, or define `FCKMW_AI_API_KEY` before downgrading.
4. Quarantine items moved to `FCKMW_DATA_DIR` are not visible to 1.0.1, which only knows the uploads data folder. Restore them before downgrading, or move the `quarantine/` folder back by hand.

## Uninstall

Deleting the plugin from **Plugins** removes:

- all tables and options;
- scheduled events;
- the uploads `.htaccess` rule;
- the data folder, including quarantined files.

With **Settings → Advanced → Keep data when the plugin is deleted**, only the scheduled events are removed. In a folder set with `FCKMW_DATA_DIR`, only FCK Malware's own entries are removed.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Scheduled scans never run | WP-Cron needs visits. With `DISABLE_WP_CRON`, add a system cron (`*/5 * * * * wp --path=/var/www/site cron event run --due-now`). **Scan & Threats → Schedule** shows overdue tasks. |
| Scan stops at the same point | The progress is saved after every step. Check **Diagnostics** for memory, and lower `throttle_ms` / `max_file_size_mb` if needed. The scan resumes on the next step. |
| "The file or its directory is not writable" on quarantine | Fix ownership or permissions (the web server user must be able to rename the file), then use **Retry recoverable failures**. |
| Restore says a file exists at the original location | Something (a reinstall, or reinfection) created the file again. Restoring never overwrites; remove or rename the new file first. |
| PHP in uploads still runs after the rule | nginx and some LiteSpeed setups ignore `.htaccess`. Run **Test** on the rule and add the server rule shown on the card. |
| Uploads are refused for one user | They hit the temporary block after repeated malicious uploads. **Protection → Temporary upload blocks → Lift all blocks**. |
| Imunify360 or ImunifyAV test fails | See [INTEGRATIONS.md](INTEGRATIONS.md#permissions). |
| AI key "stored" but reviews fail with an authentication error | The site salts changed, so the encrypted key can no longer be read. Re-enter it. |
| Database upgrade error notice | The database user needs CREATE and ALTER. The upgrade retries on every request until it succeeds. |
| Old links such as `?page=fckmaleware-findings` | They redirect to the new tab automatically. |
