# FCK Malware 0.2.0: Codebase Audit

Scope: every file in the repository at commit `7fde417` (plugin version 0.2.0): 14 PHP classes (~2,400 lines), admin JS/CSS, signature build tool, standalone tests and two GitHub Actions workflows.

Severity scale:
- **High**: exploitable, or causes silent loss of protection or data.
- **Medium**: wrong behaviour that a realistic site will hit.
- **Low**: quality or efficiency.

Findings are grouped by area. Each one says whether it is fixed in 1.0 and how.

## 1. Security of the plugin itself

| # | Severity | Finding | Resolution in 1.0 |
|---|---|---|---|
| S1 | **High** | **Multisite privilege escalation.** All admin screens and actions check `manage_options`, which every *sub-site* administrator has. On a network, a sub-site admin could scan the shared filesystem, read malicious-code excerpts from any site, and quarantine other sites' files. | One capability helper: `manage_network_options` on multisite, `manage_options` otherwise. Admin screens move to the Network Admin on multisite. |
| S2 | **High** | **The plugin never scans itself.** The scanner excludes the plugin's own directory, so a backdoor injected into FCK Malware's files (attackers do target security plugins) is never detected. | The plugin's own files are checked against a SHA-256 manifest built at release time. Signatures are still not run on our own signature data. |
| S3 | Medium | **Quarantine follows symlinks.** `Paths::resolve()` uses `realpath()`, so quarantining a symlink reads and **unlinks the link's target**. Restore writes through a dangling symlink at the original path. | Symlinks are refused (`lstat`/`is_link`) for every file operation. Writes use a temporary file plus an atomic `rename()`. |
| S4 | Medium | **Any quarantine command other than `restore` deletes.** `handle_quarantine()` treated a missing or garbage `command` as "delete permanently". It is CSRF- and capability-protected, but destructive by default. | Commands are allowlisted; unknown commands are rejected. |
| S5 | Medium | **Predictable, web-reachable data directory.** `uploads/fckmaleware/` is protected only by `.htaccess`/`web.config`. On nginx, the scan file list (`scan-files.txt`, which reveals the site's file layout) and quarantined payloads are downloadable at a guessable URL. | The data directory gets a random suffix stored in an option. Existing data is migrated. Scan lists live in the database or the private directory. Quarantine copies stay compressed and non-executable. |
| S6 | Medium | **Silent regex failures.** `preg_match()` returning `false` (backtrack/JIT limit) is treated as "no match", hiding detections and potential ReDoS. That doesn't matter much for bundled signatures, but it becomes critical once remote signature updates exist. | PCRE errors are recorded per signature and shown in the admin. Feed signatures must pass a ReDoS/timing check and length limits before they are accepted. |
| S7 | Low | **Unbounded Imunify output.** Agent stdout is buffered without limit. | Output is capped (8 MB). |
| S8 | Low | **Plugin packages are not checksum-verified.** The updater relies only on GitHub TLS. | The release asset's SHA-256 `digest` (GitHub API) is verified before installation when available. Signature updates use a separate Ed25519-signed channel (see §5). |

Checked and found OK:
- **Requests:** every state-changing request uses a nonce and a capability check.
- **SQL:** all queries are prepared.
- **Output:** escaped with `esc_html`/`esc_attr`/`esc_url`.
- **Process execution:** the Imunify agent runs through `proc_open` with an argv array (no shell), and the binary path is allowlisted.
- **Code execution:** no `eval`/`unserialize` of untrusted data anywhere.

## 2. Detection quality

| # | Severity | Finding | Resolution |
|---|---|---|---|
| D1 | Medium | **Single regex layer.** Detection is 26 regexes. Anything that does not match a pattern exactly (new obfuscation, renamed shells) is missed. | Multi-layer engine: signatures (regex, byte patterns, SHA-256 hashes), a token-based weighted heuristic engine, integrity, location and behaviour layers. |
| D2 | Medium | **Signatures lack metadata**: no family, confidence, provenance or licence, remediation, false-positive history or version. | Signature schema v2 with all of these. v1 files still load. |
| D3 | Medium | **Integrity covers core only.** Plugins and themes are not verified. Missing core files are not reported. | WordPress.org plugin checksums (`downloads.wordpress.org/plugin-checksums`), local baselines for themes and premium plugins (with stated limitations), and missing-core-file detection. |
| D4 | Medium | **No database scanning.** Injected scripts in posts and options, malicious cron entries and rogue admins are invisible. | Database scanner (read-only, with previews) plus behaviour/persistence checks. |
| D5 | Low | **Some signatures can flag legitimate code** (FMW-PHP-011 large base64 blob, FMW-PHP-014 admin creation, FMW-CFG-001 `auto_prepend_file` used by WAFs). | Each signature now has a confidence level. Low-confidence signatures report as `suspicious`, not `malicious`, and never trigger auto-remediation. |

## 3. Scanning engine and performance

| # | Severity | Finding | Resolution |
|---|---|---|---|
| P1 | **High** | **Findings disappear while a scan runs.** `start()` deletes all open findings, so the dashboard and alerts report "0 threats" until the scan finishes. If the scan dies, they stay gone until the next complete scan. | Findings are upserted per scan and only marked resolved after a *completed* scan that covered the file and no longer detects it. |
| P2 | Medium | **File listing is not bounded.** `start()` walks the whole tree in one request. On large sites this can exceed `max_execution_time`, and the scan never starts. | The tree is split into work units (root, `wp-admin`, `wp-includes`, each plugin, theme and uploads year), and listing happens step by step. |
| P3 | Medium | **Resume is O(n²).** `SplFileObject::seek($position)` re-reads the list from the top on every step. | A byte offset is stored instead (`ftell`/`fseek`). |
| P4 | Medium | **No incremental scanning.** Every file is re-read and re-matched on every scan. | File cache table (size, mtime, SHA-256, engine and signature version). Unchanged clean files are skipped in Quick/Standard modes. Deep mode ignores the cache. |
| P5 | Medium | **No scan lock.** An AJAX step and a cron continuation can process the same batch at the same time, producing duplicate findings. | Atomic lock (`add_option` with expiry) around each step. |
| P6 | Low | **One DB query per finding.** The `is_ignored()` lookups for each finding, and `file` has no index. | Batched lookups and an index on `file(191)`. |
| P7 | Low | **One scan mode only.** | Quick, Standard, Deep, Custom directory, Core integrity, Recently modified, Database. |

## 4. Remediation and quarantine

| # | Severity | Finding | Resolution |
|---|---|---|---|
| R1 | Medium | **No way to repair modified core/plugin files.** The user is told to reinstall WordPress. | Replace with the official copy (core: `core.svn.wordpress.org`; wordpress.org plugins: `plugins.svn.wordpress.org`), verified against the official checksum before writing, with a backup first. |
| R2 | Medium | **Quarantine metadata is an ever-growing option**, with no expiry, no ownership/mtime preservation, and no backup verification before unlinking. | Metadata is preserved (perms, mtime, owner noted). The copy is verified by decompressing and hashing it *before* the original is removed. Optional expiry policy. Every action goes to the audit log. |
| R3 | Low | **No audit history** of who quarantined, restored or deleted what. | Activity log table. |

## 5. Updates, notifications, operations

| # | Severity | Finding | Resolution |
|---|---|---|---|
| O1 | Medium | **Alert storms.** Every scheduled scan with open findings re-sends the same email (daily, or hourly with the hourly schedule). | Notification engine with fingerprinted events, cooldowns, grouping, retries and a delivery log. |
| O2 | Medium | **Signatures only update with plugin releases.** | Separate Ed25519-signed signature feed with version checks, atomic install, rollback and an offline fallback to the bundled database. |
| O3 | Medium | **CI has never executed.** Every GitHub Actions job on this account fails before its first step (an account/billing restriction, not code). Nothing currently guarantees releases are tested. | Local `tools/build-release.sh` runs every test suite and builds the zip plus checksums. The CI workflows remain for when Actions works. |
| O4 | Low | **Imunify field names unverified.** The JSON field names and status values for Imunify detections are based on documentation, not a live agent. | Still unverified (no Imunify server available). Parsing is defensive, and the admin shows raw agent errors. Documented as a known limitation. |
| O5 | Low | **Uninstall deletes quarantined files without warning.** | Documented in the readme and on the Quarantine screen. |

## 6. Missing functionality (from the 1.0 brief)

- **Real-time protection:** no event-driven scanning (uploads, plugin/theme install/update, role changes).
- **Hardening:** only one rule (block PHP in uploads); no exposure checks (debug, listing, XML-RPC, backups, headers, file editing).
- **AI:** no AI-assisted analysis. Local or external.
- **Threat intelligence:** no collection or curation pipeline, and no false-positive feedback channel.
- **Admin UI:** a single page with tabs, and no security overview or activity log.
- **Tests:** no WordPress integration tests, no PHPUnit, no malware/clean regression corpus.

## 7. What 0.2.0 does well and keeps

- **Resumable scanning design:** time-boxed steps driven by AJAX, cron or WP-CLI.
- **Defensive Imunify adapter:** no shell, binary allowlist, timeout.
- **Quarantine format:** compressed, non-executable, hash-verified on restore, with a core-file guard.
- **Ignore semantics:** an ignore is bound to the file's content hash.
- **GitHub updater:** works with release assets and zipballs.
- **Standalone signature tests:** every signature has a positive sample, plus benign samples.

The settings option, findings table and quarantine data from 0.2.0 must keep working after the upgrade. See `docs/MIGRATION.md`.
