# Threat-intelligence sources and pipeline

This is how new detection rules reach sites. Everything here runs on a maintainer's machine. Sites only download the signed result.

```
collect → validate → normalize → deduplicate → classify → test
        → (human) approve → build → sign → publish → sites update
```

Nothing collected automatically becomes a trusted signature. A candidate reaches the shipped database only after both of these:

- it matches nothing in the clean corpus;
- a named maintainer approves it with `tools/intel/approve.php`.

## Sources

The machine-readable list is `tools/intel/sources.json`.

| Source | Licence | Used for | Status |
|---|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) | CC0-1.0 | Hostnames from web-injection campaigns (ClearFake, SocGholish, Balada and similar, plus anything WordPress-tagged). These become host signatures for files and database content. Payload-hosting entries are ignored. | Enabled, no key needed |
| [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch) | CC0-1.0 | SHA-256 hashes of samples tagged php, webshell or wordpress. These become exact-hash signatures. | Enabled; needs a free `ABUSECH_AUTH_KEY` |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (Florian Roth, Nextron Systems) | [DRL 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) | PHP web-shell YARA rules converted to regex. Only rules with plain-text strings and an `any`/`all`/`N of them` condition are converted. Author, reference and licence are kept in every signature's `source`, `description` and `license` fields, as DRL 1.1 requires. | Enabled |
| Community | GPL-3.0-or-later | Signatures submitted by pull request to `intel/community/*.json`. | Enabled; reviewed |
| WPScan | Commercial (free tier is non-commercial only) | Not used | **Not integrated** |
| Patchstack | Commercial | Not used | **Not integrated** |
| Imunify360 signatures | Proprietary | Never copied. The plugin only imports the per-site results the local Imunify360 agent reports. | **Not integrated** |

The plugin itself contacts only two places:

- the signed feed on GitHub (`feed/manifest.json`);
- wordpress.org, for core and plugin checksums and official file copies.

It never queries the sources above at runtime.

## Maintainer workflow

```sh
# 1. Build or refresh a clean corpus: WordPress core plus popular plugins and themes.
#    The 1.0 corpus was 30 plugins and 6 themes: 40,761 files.

# 2. Collect candidates (writes intel/candidates/<date>-<source>.json).
php -d memory_limit=3G tools/intel/collect.php --source=signature-base --clean=/path/to/corpus
php tools/intel/collect.php --source=urlhaus --clean=/path/to/corpus
ABUSECH_AUTH_KEY=... php tools/intel/collect.php --source=malwarebazaar --clean=/path/to/corpus

# 3. Review what is pending.
php tools/intel/review.php intel/candidates/<file>.json

# 4. Approve selected candidates (re-validated, recorded with the reviewer's name).
php tools/intel/approve.php intel/candidates/<file>.json --ids=ID1,ID2 --reviewer="Name"

# 5. Rebuild, test, sign and publish.
php tools/build-signatures.php && php tests/run.php
php tools/feed-publish.php --key=/secure/path/fmw-2026-1.key.json
```

What each stage rejects:

- **Validate:** schema errors, oversized patterns, regexes that do not compile, and patterns that fail the backtracking stress probes.
- **Deduplicate:** IDs and patterns already in the database.
- **Test:** any match in the clean corpus.

A rejected candidate stays in the file with its reason, so it can be audited.

## The learning loop (opt-in)

Sites never send anything automatically. An administrator can do two things:

- open a pre-filled GitHub issue from a finding ("Report false positive" or "Confirm malware");
- download an anonymous statistics bundle and attach it to an issue.

The bundle is format `fckmw-feedback-1`. It holds per-rule status counts and the plugin, signature and WordPress versions. There are no paths, code, URLs or user data in it.

`tools/intel/learn.php` turns these into two outputs:

- a report: `intel/learning/report-<date>.md`;
- hash candidates confirmed by two or more reporters, for normal review.

## State as of 2026-10-17

- `intel/candidates/2026-10-17-urlhaus.json`: 2 pending.
- `intel/candidates/2026-10-17-signature-base.json`: 250 pending and 2 rejected (duplicate IDs). All 250 matched nothing in the 40,761-file clean corpus. **None have been approved.** Each one still needs human review before it can ship.
- MalwareBazaar has not been collected; it needs an auth key.
