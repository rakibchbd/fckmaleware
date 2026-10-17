# Attribution and licences

FCK Malware is licensed GPL-3.0-or-later. It bundles no third-party PHP or JavaScript libraries. It uses WordPress's own APIs, including WordPress's bundled `sodium_compat` when PHP's sodium extension is missing.

## Detection content shipped in 1.0

All 45 rules in `signatures/signatures.json` were written by the FCK Malware project and are GPL-3.0-or-later.

One rule's domain list comes from public incident write-ups (browser miners and the 2019 WordPress plugin-injection campaigns); its `source` field says so. Domains are facts and are not copied from any proprietary database.

No Imunify360, WPScan, Patchstack, Sucuri, Wordfence or other proprietary signatures or vulnerability data are included or used to derive rules.

## Candidate content not yet shipped

These are under review in `intel/candidates/`:

- **Neo23x0/signature-base** by Florian Roth (Nextron Systems), under the [Detection Rule License 1.1](https://github.com/Neo23x0/signature-base/blob/master/LICENSE). Converted rules keep the original rule name, author and reference in their `description` and `source` fields, and `DRL-1.1` in their `license` field. DRL 1.1 permits redistribution and modification on that condition. If such rules are approved, this file and the release notes will list them.
- **abuse.ch URLhaus and MalwareBazaar**, CC0-1.0. Attribution is not required, but it is given here.

## External services the plugin can call

These are not bundled, and are called only as described in `docs/PRIVACY.md`:

- WordPress.org APIs: checksums and official file copies.
- GitHub: releases and the signed feed.
- Optional, configured by the administrator:
  - an Anthropic API or OpenAI-compatible endpoint;
  - a webhook receiver;
  - the Imunify360 agent on the same server.

"Imunify360" is a trademark of CloudLinux. FCK Malware is not affiliated with CloudLinux, Anthropic, OpenAI or abuse.ch.
