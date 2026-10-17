# Testing

## Suites

| Suite | Command | Needs |
|---|---|---|
| Unit | `php tests/run.php` | PHP 7.4+ only. WordPress functions are stubbed. |
| Signature database | `php tools/build-signatures.php --check` | PHP |
| WordPress integration | `wp --path=<test site> eval-file tests/integration/run.php` | A disposable site with FCK Malware active |
| End-to-end (admin UI) | `node tests/e2e/ui.js <screenshot dir>` | Playwright and a disposable site (see the header of `tests/e2e/ui.js`) |
| False-positive calibration | `php -d memory_limit=2G tools/corpus-scan.php <clean dirs>` | A clean corpus |

**Run the integration and end-to-end suites only against a throwaway site.** They write sample files, quarantine and restore them, and change settings.

## Results for 1.0.0 (2026-10-17)

Environment: PHP 8.3.6 and WordPress 7.1.3 on SQLite (single site), with Chromium through Playwright 1.56.

| Suite | Result |
|---|---|
| Unit | **918 checks passed.** Signature validation and ReDoS probes, heuristics, 28 malware and 10 clean fixtures, Imunify JSON parsing, feed signing and verification, notifier, redactor. |
| Signature database | Up to date: 45 signatures, v2026.10.17.4. |
| WordPress integration | **33 of 33 passed.** Scan, detection, no duplicate findings, quarantine and byte-identical restore, restore points, refusals, accept-until-changed, scope confinement, database scan, persistence, settings validation, health arithmetic, hardening toggles, webhook SSRF guard, failed signature update keeping the active database. |
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
