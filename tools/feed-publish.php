<?php
/**
 * Publish signatures/signatures.json to the signed detection-update feed.
 *
 * Writes feed/signatures-<version>.json, feed/manifest.json and
 * feed/manifest.json.sig, then verifies the result with the public keys
 * compiled into the plugin (so a key mismatch is caught before pushing).
 *
 * Usage:
 *   php tools/feed-publish.php --key=/secure/path/fmw-2026-1.key.json [--days=60] [--min-plugin=0.9.0]
 *
 * Commit the feed/ directory to main to publish. Sites pick it up on their
 * next update check (twice daily).
 */

$root = dirname( __DIR__ );
require $root . '/includes/class-signatures.php';
require $root . '/includes/class-feed.php';

use Fckmaleware\Feed;
use Fckmaleware\Signatures;

$options = getopt( '', array( 'key:', 'days::', 'min-plugin::' ) );
if ( empty( $options['key'] ) || ! is_readable( $options['key'] ) ) {
	fwrite( STDERR, "Usage: php tools/feed-publish.php --key=<secret key file> [--days=60] [--min-plugin=<version>]\n" );
	exit( 2 );
}
$key = json_decode( (string) file_get_contents( $options['key'] ), true );
if ( ! is_array( $key ) || empty( $key['secret_key'] ) || empty( $key['key_id'] ) ) {
	fwrite( STDERR, "Invalid key file.\n" );
	exit( 2 );
}

$db_raw   = (string) file_get_contents( $root . '/signatures/signatures.json' );
$document = json_decode( $db_raw, true );
$errors   = Signatures::validate( (array) $document );
if ( $errors ) {
	fwrite( STDERR, "Refusing to publish an invalid database:\n  " . implode( "\n  ", $errors ) . "\n" );
	exit( 1 );
}

// The plugin's trusted keys, read from source so the check matches what sites will do.
preg_match_all( "/'([a-z0-9._-]+)'\\s*=>\\s*'([A-Za-z0-9+\\/=]{40,})'/i", (string) file_get_contents( $root . '/includes/class-signature-updater.php' ), $m, PREG_SET_ORDER );
$trusted = array();
foreach ( $m as $pair ) {
	$trusted[ $pair[1] ] = $pair[2];
}

$version = (string) $document['version'];
$file    = "signatures-{$version}.json";
$days    = max( 7, (int) ( $options['days'] ?? 60 ) );
$plugin  = preg_match( "/define\\( 'FCKMW_VERSION', '([^']+)' \\);/", (string) file_get_contents( $root . '/fckmaleware.php' ), $pv ) ? $pv[1] : '0';

$manifest = array(
	'schema'     => Feed::SCHEMA,
	'channel'    => 'stable',
	'issued'     => gmdate( 'Y-m-d\TH:i:s\Z' ),
	'expires'    => gmdate( 'Y-m-d\TH:i:s\Z', time() + $days * 86400 ),
	'signatures' => array(
		'version'    => $version,
		'file'       => $file,
		'sha256'     => hash( 'sha256', $db_raw ),
		'size'       => strlen( $db_raw ),
		'count'      => count( $document['signatures'] ),
		'db_schema'  => (int) ( $document['schema'] ?? 1 ),
		'min_plugin' => (string) ( $options['min-plugin'] ?? $plugin ),
	),
);
$manifest_json = json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
$signature     = Feed::sign( $manifest_json, (string) base64_decode( $key['secret_key'], true ), $key['key_id'] );

if ( null === Feed::verify( $manifest_json, $signature, $trusted ) ) {
	fwrite( STDERR, "The signature does not verify with the public keys in SignatureUpdater::PUBLIC_KEYS. Add the key's public half there first.\n" );
	exit( 1 );
}

@mkdir( $root . '/feed' );
// Keep only the current database file in the feed directory.
foreach ( glob( $root . '/feed/signatures-*.json' ) ?: array() as $old ) {
	if ( basename( $old ) !== $file ) {
		unlink( $old );
	}
}
file_put_contents( $root . "/feed/{$file}", $db_raw );
file_put_contents( $root . '/feed/manifest.json', $manifest_json );
file_put_contents( $root . '/feed/manifest.json.sig', $signature . "\n" );

echo "Published signatures v{$version} ({$manifest['signatures']['count']} signatures), signed with {$key['key_id']}, expires {$manifest['expires']}.\n";
echo "Commit feed/ to main to release it.\n";
