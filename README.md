# FCK Malware

Free, open-source malware protection for WordPress. It needs no paid service, no API key and no account.

- It scans files and the database with several independent detection layers.
- It watches the events attackers use to get in and stay in.
- It cleans up safely: every change can be undone.
- Detection rules are updated through a signed feed.
- Imunify360 and an AI second opinion are optional add-ons.

Requires WordPress 5.8+ and PHP 7.4+. Works on single sites and multisite networks (network-activated, managed from Network Admin), and on shared hosting: no daemons, no root, no extra PHP extensions beyond what WordPress needs. Signature verification uses libsodium: PHP's `sodium` extension, or WordPress's bundled `sodium_compat` where the extension is missing.

## What it does

| Area | How |
|---|---|
| **Signatures** | 45 hand-written rules (44 regex, 1 byte pattern) for PHP backdoors, web shells, obfuscated loaders, JavaScript and SEO-spam injections, malicious `.htaccess`/`.user.ini` rules and PHP hidden in images. Every rule is validated, stress-tested for catastrophic backtracking, and checked against 40,761 clean WordPress files before release. The engine also matches exact SHA-256 hashes of known malware; feed updates can add them, though none ship yet. |
| **Heuristics** | A token-based analyser that finds *unknown* malware by what the code does: request input reaching `eval`/shell functions, assembled or hidden function names, decoded payloads being executed, packed lines, high-entropy blobs and more. It never runs the code. Calibration: 0 false positives on the 40,761-file clean corpus; all 28 malware fixtures detected. |
| **Integrity** | WordPress core and wordpress.org plugins are compared with official checksums. Other plugins and themes get a local baseline on the first standard scan, so later changes stand out. Missing core files and unknown PHP in core folders are reported. |
| **Behaviour and persistence** | Hidden or newly created administrators, role and capability takeover, a changed `default_role` or site URL, `auto_prepend_file`, malicious cron payloads and hook callbacks built with `eval`. |
| **Database** | Posts, options and comments on every site are checked for injected scripts, hidden links and PHP. Findings link to the right editor. Serialized data is never search-and-replaced. |
| **Event-driven protection** | Malicious uploads are refused before they are saved. Plugins and themes are checked right after install or update. Administrator and security-option changes trigger alerts. |
| **Remediation** | Quarantine keeps a compressed copy that is verified before the original is removed. "Replace with official copy" downloads the wordpress.org original, verifies its checksum and backs up the old file first. Restore points cover every action and bulk action. Automatic quarantine is opt-in and limited to very high-confidence cases. |
| **Hardening** | Six optional rules, each with risk, compatibility and undo notes, plus nine report-only checks. |
| **Updates** | Plugin releases come from GitHub through the normal WordPress update screen. Signature databases come from an Ed25519-signed feed with expiry, anti-replay and rollback. |
| **Notifications** | Grouped e-mail alerts with cooldowns, plus HMAC-signed webhooks (public addresses only). |
| **Dashboard** | 14 sections: overview with an explained health score, scanner, findings, quarantine, real-time, hardening, AI, signatures, threat intel, schedule, reports, activity log, integrations, settings. Every number comes from the site's own records. |
| **Imunify360** (optional) | If the agent is on the server, its malicious-file list for the site is imported as findings. Its proprietary signatures are never copied. |
| **AI second opinion** (optional, off by default) | An administrator can send a redacted excerpt of one finding to Anthropic Claude or any OpenAI-compatible endpoint, including a self-hosted model. The answer is advisory: the model cannot change, delete or run anything. |

## Install

1. Download `fckmaleware.zip` from the [latest release](https://github.com/rakibchbd/fckmaleware/releases/latest).
2. Upload it in **Plugins → Add New → Upload Plugin**, then activate it (network-activate on multisite).
3. Open **FCK Malware → Malware Scanner** and run a **Standard** scan. It records integrity baselines for plugins and themes that are not on wordpress.org.

Updates come from this GitHub repository. When a higher version is pushed to `main`, sites see it in **Dashboard → Updates** within 6 hours and install it automatically: auto-update is on by default, and can be turned off on the Plugins screen. See [docs/RELEASING.md](docs/RELEASING.md).

## Scan modes

| Mode | Reads | Use |
|---|---|---|
| Quick | PHP, `.htaccess`, `.ini`; skips files unchanged since they were found clean | Frequent checks |
| Standard | Every scannable file; skips unchanged clean files | Default, scheduled |
| Deep | Every file including images, no cache | After a compromise |
| Core | WordPress core against official checksums | After a core update or suspicion |
| Recent | Files modified in the last N days | Incident triage |
| Custom | One directory | Investigating a plugin or folder |

Scans run in steps of a few seconds through AJAX, WP-Cron or WP-CLI. They resume exactly where they stopped and never hit PHP time limits. Files over the size limit are listed in the scan result, not silently skipped.

## WP-CLI

```sh
wp fckmaleware scan [--mode=quick|standard|deep|core|recent|custom] [--dir=<path>] [--days=<n>] [--format=table|json]
wp fckmaleware findings [--status=open|quarantined|ignored|resolved] [--source=<layer>] [--format=json]
wp fckmaleware db-scan
wp fckmaleware persistence
wp fckmaleware quarantine <finding-id>      # verified copy kept
wp fckmaleware repair <finding-id>          # official wordpress.org copy
wp fckmaleware accept <finding-id>
wp fckmaleware restore <key>
wp fckmaleware quarantine-list
wp fckmaleware rollback [<point>]
wp fckmaleware signatures
wp fckmaleware signature-updates status|update|rollback
wp fckmaleware hardening status|enable <rule>|disable <rule>
wp fckmaleware ai-review <finding-id> [--show-request]
wp fckmaleware feedback report|export
wp fckmaleware notify-test
wp fckmaleware imunify status|sync|scan
```

`wp fckmaleware scan` exits with status 1 when critical or high findings remain, so it can gate a deploy.

## Limits, stated plainly

- **Real-time protection is event-driven.** WordPress has no file-system hooks, so files changed outside WordPress (FTP, another account on the server) are found by the next scheduled scan, not instantly.
- **WP-Cron needs traffic** or a system cron calling `wp-cron.php`. With `DISABLE_WP_CRON` and no system cron, scheduled scans do not run. The dashboard warns about this.
- **Plugins and themes not on wordpress.org** have no official checksums. Their baseline records whatever is on disk at the first standard scan, so a component that was already infected then is only covered by the signature and heuristic layers.
- **Heuristics flag behaviour, not intent.** A legitimate file-manager or backup plugin can look like a web shell. Review findings before acting; "Accept as safe" remembers your decision until the file changes.
- **The signature set is small and new.** It complements, not replaces, server-side scanners and a clean backup.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Threat-intelligence sources and licences](docs/THREAT-INTEL-SOURCES.md)
- [Attribution](docs/ATTRIBUTION.md)
- [Upgrading from 0.x](docs/MIGRATION.md)
- [Releasing and signing](docs/RELEASING.md)
- [Testing and results](docs/TESTING.md)
- [Changelog](CHANGELOG.md)
- [1.0 audit](docs/AUDIT.md) and [plan](docs/ROADMAP.md)

## Reporting

- **False positives and missed malware:** use the links on each finding, which open a pre-filled GitHub issue you review before sending.
- **Security issues in the plugin itself:** please report them privately through GitHub's *Report a vulnerability* on this repository.

## Licence

GPL-3.0-or-later. Third-party rule content keeps its own licence; see [docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).
