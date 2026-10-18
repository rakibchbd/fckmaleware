# Upgrading from 1.1 to 1.2

- **Verified malware is now removed automatically, on by default.** On the first request after the upgrade, a sweep removes every open verified finding: malicious, 90%+, from a signature, hash or Imunify, whole-file only. Heuristic, suspicious and injected-code findings stay for review. Recovery copies are kept for 30 days.

  To review first instead, turn it off before upgrading, or right after, under **Protection → Real-Time Protection → Quarantine**. Every removal can be restored from the Quarantine screen until its copy expires.
- **The bundled signature database grows.** See the changelog for the new rules. They reach sites with the plugin update, not through the signed feed, until a maintainer signs a new feed.
- No database changes.

# Upgrading from 1.0.x to 1.1

The upgrade is automatic, runs once on the first request, and keeps all data.

## What happens

1. **Schema 4.** Three indexes are added to the findings table: status + severity, detection date, quarantine key. No column changes, no data rewritten.
2. **Settings.** New keys get their defaults; existing values are untouched. The AI API key is encrypted the next time settings are saved (plain values from 1.0 are still read until then).
3. **Scan history** starts with the last complete scan recorded by 1.0.
4. **Schedules** are rebuilt:
   - the file scan moves to the configured hour (default 03:00, site time zone);
   - a weekly core integrity check and a twice-daily uploads check are added.

   Turn them off under **Scan & Threats → Schedule** if you do not want them.
5. **Navigation.** The menu is now **FCK Security** with five sections. Old screen addresses (`?page=fckmaleware-findings` and so on) redirect to their new tab.
6. **Upload policy.** New defaults:
   - executable file types and images containing PHP are refused for every user, including administrators;
   - three refused uploads within an hour block that account's uploads for 60 minutes.

   Review them under **Protection → Real-Time Protection**.

## Rolling back

See [OPERATIONS.md](OPERATIONS.md#roll-back-to-10x).

# Upgrading from 0.x to 1.0

The upgrade is automatic. It runs on activation and on the first request after the plugin files change, and it is safe to repeat.

## What happens

1. **Tables.** The schema is upgraded to v3:
   - Findings move from the per-site `{prefix}fckmw_findings` table to the network-wide `{base_prefix}fckmw_findings` table.
   - New columns are added: object type and reference, family, verdict, confidence, evidence, remediation, occurrences, last seen, and AI review.
   - New tables are added for the file cache, baselines and the activity log.
   - The schema version is recorded only after every expected column is verified. If a step fails, nothing is marked done, the admin shows the error, and the next request retries.
2. **Findings.** Existing findings keep their status, so ignored ones stay ignored and quarantined ones stay quarantined.
   - Source `builtin` becomes `signature`.
   - `last_seen_at` is set from `updated_at`.
3. **Settings.** All 0.x keys keep their meaning, and new keys get their defaults. On multisite, settings, the quarantine index, the last scan and the Imunify sync time move from the main site's options to network options.
4. **Data folder.** `uploads/fckmaleware/` is renamed to `uploads/fckmaleware-<random>/` and locked down. Quarantined files keep working: the index stores keys, not paths.
5. **Scan state.** A 0.x scan that was still marked "running" is discarded, because its format changed. Start a new scan.
6. **Hardening.** The 0.x "block PHP in uploads" setting maps to the `uploads_php` hardening rule.
7. **Schedules** are re-registered: scan, daily maintenance and signature updates.

## After upgrading

- Run a **Standard** scan. It records integrity baselines for plugins and themes that are not on wordpress.org, and re-checks everything with the larger 1.0 rule set and the heuristic engine. Expect more findings than with 0.x: review them on Threat Findings before acting.
- Look at **Security Hardening**. Rules other than the uploads rule are off until you enable them.
- The admin menu is now **FCK Malware** with 14 sections. On multisite it is in Network Admin.

## Downgrading

Downgrading to 0.x is not supported, because 0.x does not read the v3 tables. Deactivating 1.0 keeps all data.
