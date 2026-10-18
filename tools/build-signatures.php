<?php
/**
 * Compile signatures/src into signatures/signatures.json.
 *
 * Sources:
 *   signatures/src/fckmw-*.php          Project-authored signatures (PHP arrays).
 *   signatures/src/approved/*.json      Signatures approved through the threat-intel
 *                                       pipeline (tools/intel/approve.php).
 *
 * Every entry is validated with Fckmaleware\Signatures::validate() (schema,
 * compilation, ReDoS stress probes). The build fails on any error.
 *
 * Usage:
 *   php tools/build-signatures.php            Build; bump the version if the content changed.
 *   php tools/build-signatures.php --check    Exit 1 if signatures.json is not up to date.
 */

require dirname( __DIR__ ) . '/includes/class-signatures.php';

use Fckmaleware\Signatures;

$root   = dirname( __DIR__ );
$target = $root . '/signatures/signatures.json';
$check  = in_array( '--check', $argv, true );

$signatures = require $root . '/signatures/src/fckmw-core.php';
foreach ( glob( $root . '/signatures/src/fckmw-*.php' ) ?: array() as $file ) {
	if ( 'fckmw-core.php' !== basename( $file ) ) {
		$signatures = array_merge( $signatures, require $file );
	}
}
foreach ( glob( $root . '/signatures/src/approved/*.json' ) ?: array() as $file ) {
	$batch = json_decode( (string) file_get_contents( $file ), true );
	if ( ! is_array( $batch ) || ! isset( $batch['signatures'] ) ) {
		fwrite( STDERR, "Invalid approved batch: {$file}\n" );
		exit( 1 );
	}
	foreach ( $batch['signatures'] as $sig ) {
		$signatures[] = $sig;
	}
}

usort(
	$signatures,
	static function ( $a, $b ) {
		return strcmp( $a['id'], $b['id'] );
	}
);
$signatures = array_map( array( Signatures::class, 'normalize' ), $signatures );
// Literal prefilters make pattern-heavy rules cheap on files that cannot match.
foreach ( $signatures as &$signature ) {
	if ( 'regex' === $signature['technique'] && ! $signature['prefilter'] ) {
		$signature['prefilter'] = Signatures::derive_prefilter( $signature['pattern'] );
	}
}
unset( $signature );

$previous = is_readable( $target ) ? json_decode( (string) file_get_contents( $target ), true ) : null;
$changed  = ! is_array( $previous ) || ( $previous['signatures'] ?? null ) !== $signatures;

// Versions are YYYY.MM.DD.N and only move forward when the content changes.
$version = is_array( $previous ) ? (string) $previous['version'] : '';
if ( $changed ) {
	$today = gmdate( 'Y.m.d' );
	$n     = 1;
	if ( preg_match( '/^(\d{4}\.\d{2}\.\d{2})(?:\.(\d+))?$/', $version, $m ) && $m[1] === $today ) {
		$n = (int) ( $m[2] ?? 0 ) + 1;
	}
	$version = "{$today}.{$n}";
}

$document = array(
	'schema'     => Signatures::SCHEMA,
	'version'    => $version,
	'signatures' => $signatures,
);

$errors = Signatures::validate( $document );
if ( $errors ) {
	fwrite( STDERR, "Signature validation failed:\n  " . implode( "\n  ", $errors ) . "\n" );
	exit( 1 );
}

if ( $check ) {
	if ( $changed ) {
		fwrite( STDERR, "signatures/signatures.json is out of date; run php tools/build-signatures.php\n" );
		exit( 1 );
	}
	echo 'signatures.json is up to date (' . count( $signatures ) . " signatures, v{$version})\n";
	exit( 0 );
}

if ( ! $changed ) {
	echo 'No changes (' . count( $signatures ) . " signatures, v{$version})\n";
	exit( 0 );
}

file_put_contents( $target, json_encode( $document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
echo 'Wrote ' . count( $signatures ) . " signatures to signatures/signatures.json (v{$version})\n";
