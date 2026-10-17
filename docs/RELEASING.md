# Releasing

Nothing here requires GitHub Actions. The workflows in `.github/workflows/` run the same scripts when Actions is available, but every step works from a local checkout.

## Plugin release

1. Set the version in `fckmaleware.php`, in **both** the `Version:` header and `FCKMW_VERSION`. Add a section to `CHANGELOG.md`.
2. Build:

   ```sh
   tools/build-release.sh
   ```

   This:
   - checks that the two version strings match;
   - lints every PHP file;
   - checks that `signatures/signatures.json` matches its sources;
   - runs `tests/run.php`;
   - copies the files not excluded by `.distignore` into `build/fckmaleware/`;
   - writes `checksums.json` (the SHA-256 of every shipped file, used by the plugin's self-integrity check);
   - zips the result to `build/fckmaleware.zip` and writes `build/SHA256SUMS`.
3. Install the zip on a test site and run a Standard scan. FCK Malware's own files must verify, with no findings in `wp-content/plugins/fckmaleware/`.
4. Publish:
   - With an authenticated `gh` CLI, run `tools/build-release.sh --publish`.
   - Without it, create release `v<version>` on GitHub by hand and attach `fckmaleware.zip` and `SHA256SUMS`.
5. Merge to `main`. Sites see the update within 6 hours, or straight away after *Dashboard → Updates → Check again*. Drafts and pre-releases are never offered.

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
