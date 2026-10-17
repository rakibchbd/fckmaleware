# Privacy and data handling

FCK Malware has no server, collects no telemetry and sends nothing about a site unless an administrator explicitly starts it.

## What is stored on the site

| Data | Where | Retention |
|---|---|---|
| Findings: file path, line, a short code excerpt, hash, rule, verdict, optional AI review | `fckmw_findings` table | Resolved findings are deleted after 90 days; others stay until resolved |
| Activity log: event type, message, acting user ID; visitor IP address for blocked uploads, plugin deactivations, administrator and option changes and file-editor use | `fckmw_events` table | 180 days, at most 20,000 rows |
| File cache and integrity baselines: paths, sizes, hashes | `fckmw_files`, `fckmw_baseline` tables | Until cleared or uninstalled |
| Quarantined files and pre-repair backups | Private data folder under uploads | Until restored or deleted, or for the configured retention |
| Settings, including an optional AI API key and the webhook signing secret | Options table | Until changed or uninstalled |

Deleting the plugin from the Plugins screen removes all of the above (see `uninstall.php`).

## Outbound connections

These connections are made automatically:

| To | When | What is sent |
|---|---|---|
| `api.wordpress.org` | Core integrity checks | WordPress version and locale (standard WordPress request) |
| `downloads.wordpress.org` | Plugin integrity checks | Plugin slug and version |
| `core.svn.wordpress.org`, `plugins.svn.wordpress.org` | Only when an admin chooses "Replace with official copy" | The file path inside core or the plugin |
| `raw.githubusercontent.com` (or a configured feed) | Signature update checks, twice daily | A standard HTTP request; no site data |
| `api.github.com` | Plugin update checks, at most every 6 hours | User-Agent with the plugin version and site URL (as WordPress does for its own update checks) |

These connections are made only when an administrator sets them up:

| To | When | What is sent |
|---|---|---|
| Your e-mail server or relay | Alerts | Finding summaries and site URL to the configured address |
| Your webhook URL | Alerts | The same, as JSON, signed with HMAC |
| The configured AI provider | Only when an administrator clicks "Ask AI", after enabling it and confirming consent | See below |
| GitHub (in the admin's browser) | Only when an administrator clicks "Report false positive" or "Confirm malware" | A pre-filled issue the admin reviews and submits themselves |

## External AI review

It is off by default and requires all of the following:

- a provider is chosen;
- the consent box is ticked;
- for Anthropic, a key is entered;
- an administrator clicks "Ask AI" on one specific finding.

What is sent:

- the rule, layer, local verdict, line and evidence text;
- the file path, with the site path, domain and table prefix replaced by placeholders;
- a code excerpt limited to the configured length. Only three lines around the match are sent for `wp-config.php`.

Before sending, the redactor removes:

- database credentials and `*_KEY`, `*_SALT`, `*_SECRET`, `*_TOKEN` and `*_PASSWORD` constants;
- password, secret, token and API-key assignments;
- private keys;
- common API key formats (Anthropic, OpenAI, Stripe, AWS, GitHub, Slack, Google and JWTs);
- credentials embedded in URLs;
- e-mail addresses.

Redaction is pattern-based and cannot be perfect. A self-hosted model behind an OpenAI-compatible endpoint keeps everything on your infrastructure.

The answer is stored with the finding and is advisory only. The model has no ability to change, quarantine, delete or execute anything.

## Contributing data back

Two voluntary routes exist:

- a pre-filled GitHub issue, which contains the rule, component, version, the path inside the component and the file hash;
- an anonymous statistics file, which contains per-rule status counts and versions, identified by a random ID that is not derived from the site.

Both are reviewed by the administrator before they leave the site, and neither is automatic.
