# Releasing

Nothing here requires GitHub Actions. The workflows in `.github/workflows/` run the same scripts when Actions is available, but every step works from a local checkout.

## Plugin release

Installed sites update straight from the `main` branch. Raising the version and pushing to `main` publishes the update. No GitHub release and no Actions run are needed.

1. Make the changes, then raise the version in `fckmaleware.php`, in **both** the `Version:` header and `FCKMW_VERSION` (for example `1.0.0` to `1.0.1`). Add a section to `CHANGELOG.md`.
2. Check locally:

   ```sh
   tools/build-release.sh
   ```

   This runs the same checks a release needs:
   - the two version strings match;
   - every PHP file lints;
   - the signature database matches its sources;
   - the unit tests pass.

   It also builds `build/fckmaleware.zip` for manual installs.
3. Push to `main`.

What happens on installed sites:

- Within 6 hours, or straight away after *Dashboard → Updates → Check again*, each site reads the `Version:` header of `fckmaleware.php` on `main`. If it is higher than the installed version, the update appears on Dashboard → Updates and the Plugins screen.
- Auto-update is switched on for FCK Malware by default, so WordPress installs the update on its next background update run, normally within 12 hours. Administrators can turn auto-update off on the Plugins screen; their choice is kept.
- The package is GitHub's archive of `main`. `.gitattributes` keeps development files out of it: `tests/`, `tools/`, `intel/`, `feed/`, `signatures/src/`, `.github/` and the internal docs.

**Only push a version bump to `main` when the code on `main` is ready to ship.** Every site with auto-update on installs it. Work on a branch and merge when it is done.

GitHub releases are optional and still supported. If a release with a higher version than `main` exists, sites take the release, preferring its `fckmaleware.zip` asset. Use `tools/build-release.sh --publish` or create one by hand.

Packages installed from the `main` archive have no `checksums.json`. The plugin then covers its own files with a local baseline, like other plugins that are not on wordpress.org. The release zip from `tools/build-release.sh` includes `checksums.json` for a stronger self-check.

## Signature release

1. Edit `signatures/src/fckmw-core.php`, or approve candidates with `tools/intel/approve.php`.
2. Rebuild and test:

   ```sh
   php tools/build-signatures.php
   php tests/run.php
   php -d memory_limit=2G tools/corpus-scan.php /path/to/clean/corpus   # must report 0 detections
   ```

3. Sign and write the feed:

   ```sh
   php tools/feed-publish.php --key=/secure/path/fmw-2026-1.key.json [--days=60]
   ```

   This writes `feed/signatures-<version>.json`, `feed/manifest.json` and `feed/manifest.json.sig`. It then verifies them with the public keys compiled into the plugin.
4. Commit `signatures/` and `feed/` to `main`. Sites pick the update up on their next twice-daily check.

**Republish before the feed expires** (60 days by default), even if nothing changed. Sites keep their current database when the feed expires and log a warning, but they stop receiving updates.

## Signing keys

- Generate a key with `php tools/feed-keygen.php <key-id> <path outside the repo>`. The file is written with mode `0600`.
- **Never commit the secret key.** Keep it offline, or in a password manager or hardware-backed store, with a backup.
- **Rotation:**
  1. Generate a new key.
  2. Add its public key to `SignatureUpdater::PUBLIC_KEYS` next to the old one, and ship a plugin release.
  3. After most sites have updated, sign feeds with the new key.
  4. Remove the old public key in a later release.
- **Compromise:** release a plugin version that removes the compromised public key, and sign the feed with a new key. Sites accept feeds only with a strictly newer version and only before expiry, so an old signed feed cannot be replayed to roll sites back.
