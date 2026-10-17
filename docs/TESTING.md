# Testing

## Suites

| Suite | Command | Needs |
|---|---|---|
| Unit | `php tests/run.php` | PHP 7.4+ only. WordPress functions are stubbed. |
| Signature database | `php tools/build-signatures.php --check` | PHP |
| WordPress integration | `wp --path=<test site> eval-file tests/integration/run.php` | A disposable site with FCK Malware active |
| WordPress integration (1.1 features) | `wp --path=<test site> eval-file tests/integration/features.php` | Same |
| End-to-end (admin UI) | `node tests/e2e/ui.js <screenshot dir>` | Playwright and a disposable site (see the header of `tests/e2e/ui.js`) |
| False-positive calibration | `php -d memory_limit=2G tools/corpus-scan.php <clean dirs>` | A clean corpus |

**Run the integration and end-to-end suites only against a throwaway site.** They write sample files, quarantine and restore them, and change settings.

## Results for 1.1.0 (2026-10-17)

Environment: PHP 8.3.6, WordPress 7.1.3 on SQLite (single site), PHP built-in web server, Chromium through Playwright 1.56.1.

| Suite | Result |
|---|---|
| Unit | **975 checks passed**: the 918 from 1.0, plus upload name rules, blocking policy, classification, exclusion parsing, CSV neutralisation and secret encryption. |
| Signature database | Up to date: 45 signatures, v2026.10.17.4. |
| WordPress integration (1.0 suite) | **39 of 39 passed.** |
| WordPress integration (1.1 features) | **58 of 58 passed.** Covered: <ul><li>navigation and legacy slugs;</li><li>scan history;</li><li>refusal to scan the data folder;</li><li>bulk preview arithmetic;</li><li>bulk job with a file deleted mid-run (skipped, not failed), single-job lock, restore point and audit;</li><li>restore refusing to overwrite, then byte-identical restore;</li><li>exclusive create;</li><li>every bulk-policy rule;</li><li>uploads: clean accepted, double extension, PHP in image, malicious content, monitor mode, `.txt` not treated as an image;</li><li>temporary block and lifting it;</li><li>the uploads check finding a dropped file;</li><li>rescheduling without duplicates at the chosen hour;</li><li>a task skipped while a scan runs;</li><li>API key encrypted at rest, export without secrets, import validation and reset;</li><li>integration listing, cPGuard status-only, missing agent reported as not connected, test rate limit;</li><li>CSV formula cells.</li></ul> |
| End-to-end UI | **37 of 37 passed, no JavaScript errors, no native dialogs.** Covered: <ul><li>login, score and metrics, five-section menu, legacy redirect;</li><li>custom scan through AJAX to completion and into the history;</li><li>classification badges;</li><li>the confirmation dialog opening and Esc cancelling;</li><li>quarantine and restore through the dialog;</li><li>select-all-matching bulk quarantine with preview and progress counts;</li><li>settings round-trip of a switch on and off;</li><li>hardening apply and revert;</li><li>all remaining tabs rendering with the shell;</li><li>the integration center;</li><li>keyboard focus ring;</li><li>no horizontal overflow at 390 px.</li></ul> |
| All 16 tabs with `WP_DEBUG` on | Rendered from WP-CLI and in the browser; `debug.log` stayed empty for the whole run, including the browser session. |
| PHP compatibility | PHPCompatibilityWP (PHPCompatibility 10.0.0-alpha2), `testVersion 7.4-`: 0 issues. |
| Security sniffs | WPCS 3 (EscapeOutput, NonceVerification, ValidatedSanitizedInput, PreparedSQL, SafeRedirect): 0 issues. Checked against a deliberately bad sample to confirm the sniffs run. |
| Uninstall | On copies of the test site: <ul><li>default: options, tables and data folder removed;</li><li>"keep data": options, findings and data folder kept;</li><li>cron events removed in both cases.</li></ul> |

Not run for 1.1:

- multisite;
- MySQL/MariaDB;
- PHP 7.4–8.2 at runtime;
- Apache, nginx or LiteSpeed. The uploads-rule HTTP test ran against PHP's built-in server, which ignores `.htaccess`: it correctly reported that PHP in uploads executes, and the probe file was removed.
- real Imunify360, ImunifyAV or cPGuard;
- a live AI provider.

Checked by hand on a copy of the test site: setting `FCKMW_DATA_DIR` to a folder outside the web root moved 122 quarantined copies (0 failures). All 122 still passed their SHA-256 check from the new location, and the Diagnostics check reported the folder as outside the web root.

## Results for 1.0.0 (2026-10-17)

Environment: PHP 8.3.6 and WordPress 7.1.3 on SQLite (single site), with Chromium through Playwright 1.56.

| Suite | Result |
|---|---|
| Unit | **918 checks passed.** Signature validation and ReDoS probes, heuristics, 28 malware and 10 clean fixtures, Imunify JSON parsing, feed signing and verification, notifier, redactor. |
| Signature database | Up to date: 45 signatures, v2026.10.17.4. |
| WordPress integration | **39 of 39 passed.** Plugin updater (version from main, release precedence, GitHub offline, auto-update default). Scan, detection, no duplicate findings, quarantine and byte-identical restore, restore points, refusals, accept-until-changed, scope confinement, database scan, persistence, settings validation, health arithmetic, hardening toggles, webhook SSRF guard, failed signature update keeping the active database. |
| End-to-end UI | **20 of 20 passed, no JavaScript errors.** Login; overview; 14-section navigation; custom scan through AJAX to completion; findings list; quarantine from the UI; restore from the Quarantine screen; settings round-trip, including unticked checkboxes; hardening toggle; every remaining section renders. |
| Admin pages with `WP_DEBUG` on | All 14 sections load with no PHP errors, warnings or notices. |
| PHP compatibility | PHPCompatibility 10.0.0-alpha2, `testVersion 7.4-`: 0 issues. Deprecated-in-8.4/8.5 calls (`fputcsv` default escape, `curl_close`) fixed. |
| Security sniffs | WPCS 3 (EscapeOutput, NonceVerification, ValidatedSanitizedInput, PreparedSQL, SafeRedirect): 0 errors after review. Seven reports were annotated as false positives, each with a reason. |
| Calibration | 0 heuristic false positives on 40,761 clean files: WordPress core, 30 popular plugins, 6 themes. All 28 malware fixtures detected. |
| Uninstall | On a copy of the test site: all tables, options, transients, cron hooks and the data folder removed. The plugin source was untouched. |

These scenarios were checked by hand earlier in development, on the same test site:

- the upgrade from 0.2.0 data;
- every scan mode, plus resume after interruption, locking and cancellation;
- integrity: core, wordpress.org plugins, local baselines, and self-check from the release zip;
- upload blocking;
- the install and update queue;
- user and option events;
- official-copy repair and rollback;
- automatic quarantine limits;
- 15 attacks on the signed feed: bad signature, unknown key, expired, replayed older version, hash mismatch, oversized, invalid rules, and others;
- e-mail grouping and cooldown;
- webhook HMAC;
- hardening rules over HTTP;
- the AI review against a mocked Claude API, including refusal and overload handling.

## Not tested, and why

| Area | Status |
|---|---|
| Multisite | Code paths exist (network options, Network Admin menu, per-site database scan) but were **not exercised on a live network** in this release cycle. |
| MySQL/MariaDB | Tested on SQLite only. The SQL is standard and goes through `$wpdb`. `FIELD()` ordering and `LEFT()` in the 0.x migration rely on WordPress's SQLite translation layer here and are native on MySQL. |
| PHP 7.4–8.2 | Not run. Only PHP 8.3 was executed. Static analysis with PHPCompatibility 10 (`testVersion 7.4-`) reports no issues; the two PHP 8 token constants the heuristics use are behind `defined()` guards. |
| Real Imunify360 | Tested against a fake agent that returns recorded JSON. No real CloudLinux server was available. |
| Live Anthropic API | No API key was available. Tested against a mock that returns the documented response shapes. |
| MalwareBazaar collection | Needs a free abuse.ch key, which was not available. |
| GitHub Actions | The account's Actions runs fail before starting. The workflows are present, but releases are built locally with `tools/build-release.sh`. |
| nginx / LiteSpeed | The uploads rule was tested with Apache semantics only. nginx users get the rule to add by hand. |
