#!/usr/bin/env bash
#
# Build a release package locally (no GitHub Actions required).
#
#   tools/build-release.sh            Lint, test, build build/fckmaleware.zip
#   tools/build-release.sh --publish  ...then create the GitHub release with `gh`
#
# The package contains checksums.json (SHA-256 of every shipped file), which
# the plugin uses to detect tampering with its own files.
#
# Requirements: php (7.4+), zip, and for --publish an authenticated `gh` CLI.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
cd "$ROOT"

header=$(sed -n 's/^ \* Version: *//p' fckmaleware.php | tr -d '[:space:]')
constant=$(sed -n "s/^define( 'FCKMW_VERSION', '\(.*\)' );/\1/p" fckmaleware.php)
if [ "$header" != "$constant" ]; then
	echo "Version header ($header) and FCKMW_VERSION ($constant) differ." >&2
	exit 1
fi
VERSION="$header"

echo "==> Lint"
find . -name '*.php' -not -path './.git/*' -not -path './build/*' -print0 | xargs -0 -n1 -P4 php -l >/dev/null

echo "==> Signature database"
php tools/build-signatures.php --check

echo "==> Unit tests"
php tests/run.php

echo "==> Package"
rm -rf "$BUILD"
mkdir -p "$BUILD/fckmaleware"
tar -C "$ROOT" -cf - --exclude-from="$ROOT/.distignore" . | tar -C "$BUILD/fckmaleware" -xf -

php -r '
$dir   = $argv[1];
$files = array();
$it    = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	if ( $f->isFile() ) {
		$rel = substr( str_replace( "\\", "/", $f->getPathname() ), strlen( $dir ) + 1 );
		if ( "checksums.json" !== $rel ) {
			$files[ $rel ] = hash_file( "sha256", $f->getPathname() );
		}
	}
}
ksort( $files );
file_put_contents( $dir . "/checksums.json", json_encode( array( "version" => $argv[2], "files" => $files ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
echo count( $files ) . " files in manifest\n";
' "$BUILD/fckmaleware" "$VERSION"

(cd "$BUILD" && zip -qr "fckmaleware.zip" fckmaleware)
cp "$BUILD/fckmaleware.zip" "$BUILD/fckmaleware-$VERSION.zip"
(cd "$BUILD" && sha256sum fckmaleware.zip "fckmaleware-$VERSION.zip" > SHA256SUMS)

echo
echo "Built FCK Malware $VERSION:"
ls -l "$BUILD"/*.zip
cat "$BUILD/SHA256SUMS"

if [ "${1:-}" = "--publish" ]; then
	if ! command -v gh >/dev/null; then
		echo "gh CLI not found. Publish manually: create release v$VERSION on GitHub and attach build/fckmaleware.zip." >&2
		exit 1
	fi
	if gh release view "v$VERSION" >/dev/null 2>&1; then
		echo "Release v$VERSION already exists." >&2
		exit 1
	fi
	gh release create "v$VERSION" "$BUILD/fckmaleware.zip" "$BUILD/SHA256SUMS" --title "FCK Malware $VERSION" --generate-notes
else
	echo
	echo "To publish: tools/build-release.sh --publish  (or create release v$VERSION on GitHub and attach build/fckmaleware.zip)"
fi
