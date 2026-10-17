# fckmaleware
Experience the power of AI-optimized malware protection, proudly crafted from bamboo (because steel is way beyond our budget). Feel the difference. Embrace the innovation. Take it inside.™

---

FckMaleware is a WordPress plugin that finds, reports and quarantines malware using three sources:

1. **Built-in signatures**: 26 regex signatures (`signatures/signatures.json`) for PHP backdoors and web shells, obfuscated loaders, JavaScript injections, malicious `.htaccess` / `.user.ini` rules and PHP hidden inside images.
2. **Core integrity**: every file in `wp-admin/`, `wp-includes/` and the root is compared with the official WordPress.org checksums for your version, and unknown PHP files in core directories are flagged.
3. **Imunify360 / ImunifyAV**: if the agent is installed on the server, its malicious-file list for this site is pulled into the same findings list, and you can start an Imunify on-demand scan of the site from WordPress.

There's also a location rule (PHP files inside `wp-content/uploads`) and an optional hardening switch that blocks PHP execution in uploads.

## Install

Copy this repository into `wp-content/plugins/fckmaleware/` and activate **FckMaleware**. Requires WordPress 5.8+ and PHP 7.4+.

## Updates

Installed sites update straight from this GitHub repository. Updates appear on *Dashboard → Updates* and the Plugins screen like any wordpress.org plugin, with "View details", one-click update and the auto-update toggle.

To ship an update:

1. Bump the version in `fckmaleware.php`, in **both** the `Version:` header and `FCKMW_VERSION`.
2. Merge to `main`.

The **Release** workflow (`.github/workflows/release.yml`) then:

- runs the tests;
- builds `fckmaleware.zip` (without `tests/`, `tools/` and `.github/`, see `.distignore`);
- publishes a GitHub release `v<version>` with generated notes.

Pushes that don't change the version publish nothing.

Sites check the latest release every 6 hours. *Check again* on Dashboard → Updates checks immediately. If a release has no `fckmaleware.zip` asset, the source zipball is used and its folder is renamed to match the installed plugin. Releases marked as drafts or pre-releases are never offered.

## Using it

**Admin → FckMaleware**

- **Findings**: severity summary, a *Scan now* button with live progress, and the findings table. For each finding you can:
  - **Quarantine** the file (all findings on that file move with it).
  - **Ignore** it. It stays ignored until the file content changes.
  - Mark it **Resolved**. It comes back on the next scan if the problem is still there.
- **Quarantine**: restore or permanently delete quarantined files.
- **Imunify360**: agent status, *Sync detections now*, *Start Imunify360 scan of this site*.
- **Signatures**: the loaded signature database.
- **Settings**: scan schedule, file size limit, core integrity, image scanning, uploads PHP blocking, email alerts, and the Imunify options.

**WP-CLI**

```sh
wp fckmaleware scan                 # full scan; exits 1 if critical/high findings remain
wp fckmaleware findings --status=open --format=json
wp fckmaleware quarantine <finding-id>
wp fckmaleware signatures
wp fckmaleware imunify status|sync|scan
```

The scan exit code makes `wp fckmaleware scan` usable as a deploy or CI gate.

## How it works

- **Resumable scanning.** A scan first writes the list of candidate files to a private directory, then processes it in time-boxed steps: 8 s per AJAX request in the admin, 20 s per WP-Cron run (re-queued every 30 s until done), or a single loop under WP-CLI. Long scans therefore survive shared-hosting time limits.
- **What gets scanned.** PHP-like files (`.php`, `.phtml`, `.phar`, `.inc`, …), JS, HTML/SVG, `.htaccess`, `.user.ini`/`php.ini` and `.ico` files. PNG/JPG/GIF/WebP are added if *Scan images* is enabled. Symlinks, VCS folders, files over the size limit, the plugin itself and its data folder are skipped. Add more exclusions with the `fckmw_scan_exclude_dirs` filter.
- **Quarantine.** The file is compressed into `wp-content/uploads/fckmaleware/quarantine/`. That directory is protected by deny rules, and the stored copies are not valid PHP. The original is then deleted. Restore checks the SHA-256 of the copy and never overwrites an existing file.
- **Core and config files are never quarantined.** WordPress core files and `wp-config.php` are refused, because deleting them takes the site down; reinstall core from *Dashboard → Updates* or clean `wp-config.php` by hand instead. Unknown files sitting in core directories *can* be quarantined.
- **Data.** Findings live in `{prefix}fckmw_findings`; settings and quarantine metadata live in options. Uninstalling removes all of it, including quarantined files and the uploads `.htaccess` rule.

## Imunify360 setup

The plugin talks to the local agent CLI (`/usr/bin/imunify360-agent` or `/usr/bin/imunify-antivirus`) with `--json`. It is called without a shell, and the binary path is restricted to those known locations. Commands used:

| Purpose | Command |
| --- | --- |
| Status | `imunify360-agent version` |
| Sync detections | `imunify360-agent malware malicious list --json --limit 1000` |
| Scan this site | `imunify360-agent malware on-demand start --path <ABSPATH>` |

Only detections whose path is inside this WordPress install are imported. Entries Imunify has already cleaned are skipped.

The agent usually requires root. If the PHP user cannot run it, enable **Run through sudo** in Settings and add a sudoers rule that allows exactly these commands, for example (`visudo -f /etc/sudoers.d/fckmaleware`, adjust the user and path):

```
www-data ALL=(root) NOPASSWD: /usr/bin/imunify360-agent version, \
  /usr/bin/imunify360-agent malware malicious list --json --limit 1000, \
  /usr/bin/imunify360-agent malware on-demand start --path /var/www/html/
```

`proc_open` must not be in `disable_functions`.

## Blocking PHP in uploads on nginx

The *Block PHP in uploads* setting writes an `.htaccess` rule, so it only works on Apache/LiteSpeed. On nginx, add this to the server block instead:

```nginx
location ~* ^/wp-content/uploads/.*\.(?:php[0-9]?|phtml|phar|pht)$ { deny all; }
```

## Signatures

Signatures are defined in `tools/build-signatures.php` and compiled to `signatures/signatures.json`:

```sh
php tools/build-signatures.php
```

Each entry has an `id`, `name`, `severity` (`critical`/`high`/`medium`/`low`), `targets` (`php`, `js`, `html`, `htaccess`, `ini`, `image` or `any`) and a PCRE `pattern`. A pattern that does not compile is skipped and reported on the Signatures tab rather than breaking scans. To use your own database file, point the `fckmw_signature_file` filter at it.

## Tests

```sh
php tests/run.php
```

These standalone tests need no WordPress. They check that every pattern compiles, that every signature has a matching sample, that a set of ordinary WordPress code produces no findings, and that Imunify's JSON is parsed correctly.

## Hooks

- `fckmw_signature_file` (filter): path to the signature JSON.
- `fckmw_scan_exclude_dirs` (filter): absolute directories to skip.
- `fckmw_scan_complete` (action): fires with the final scan state after a full scan.
