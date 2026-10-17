<?php
/**
 * Signed detection-update feed: manifest format and verification.
 *
 * Free of WordPress calls so the maintainer tools and unit tests use exactly
 * the same checks as the plugin.
 *
 * Feed layout (any HTTPS location):
 *   manifest.json       Manifest (below), signed byte-for-byte.
 *   manifest.json.sig   "<key-id>:<base64 Ed25519 detached signature>"
 *   signatures-<v>.json The signature database the manifest points to.
 *
 * Manifest:
 *   {
 *     "schema": 1,
 *     "channel": "stable",
 *     "issued": "2026-10-17T12:00:00Z",
 *     "expires": "2026-11-16T12:00:00Z",
 *     "signatures": {
 *       "version": "2026.10.17.4", "file": "signatures-2026.10.17.4.json",
 *       "sha256": "…", "size": 12345, "count": 45,
 *       "db_schema": 2, "min_plugin": "0.9.0"
 *     }
 *   }
 *
 * The feed only ever carries data. Nothing in it is executed or included.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Feed {

	public const SCHEMA       = 1;
	public const MAX_MANIFEST = 65536;
	public const MAX_DATABASE = 16777216;

	/**
	 * Verify a detached signature line against the trusted keys.
	 *
	 * @param array<string, string> $keys key id => base64 Ed25519 public key
	 * @return string|null The key id that verified, or null.
	 */
	public static function verify( string $manifest, string $signature_line, array $keys ): ?string {
		$signature_line = trim( $signature_line );
		if ( ! preg_match( '/^([a-z0-9._-]{1,64}):([A-Za-z0-9+\/=]{80,100})$/i', $signature_line, $m ) || ! isset( $keys[ $m[1] ] ) ) {
			return null;
		}
		$signature = base64_decode( $m[2], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		$public    = base64_decode( $keys[ $m[1] ], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( false === $signature || false === $public || 64 !== strlen( $signature ) || 32 !== strlen( $public ) ) {
			return null;
		}
		try {
			return sodium_crypto_sign_verify_detached( $signature, $manifest, $public ) ? $m[1] : null;
		} catch ( \Throwable $e ) {
			return null;
		}
	}

	/** Sign a manifest (maintainer tooling only). */
	public static function sign( string $manifest, string $secret_key, string $key_id ): string {
		return $key_id . ':' . base64_encode( sodium_crypto_sign_detached( $manifest, $secret_key ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	/**
	 * Check a decoded manifest against the installed state.
	 *
	 * @param string $installed_version Currently active signature database version.
	 * @return string[] Problems; empty when the manifest offers an acceptable update.
	 */
	public static function check_manifest( array $manifest, string $installed_version, string $plugin_version, int $now ): array {
		$problems = array();
		if ( self::SCHEMA !== (int) ( $manifest['schema'] ?? 0 ) ) {
			$problems[] = 'unsupported manifest schema';
		}
		$expires = strtotime( (string) ( $manifest['expires'] ?? '' ) );
		if ( false === $expires || $expires < $now ) {
			$problems[] = 'manifest expired (a stale or replayed feed)';
		}
		$sigs = $manifest['signatures'] ?? null;
		if ( ! is_array( $sigs ) ) {
			$problems[] = 'manifest lists no signature database';
			return $problems;
		}
		if ( ! preg_match( '/^\d{4}\.\d{2}\.\d{2}(?:\.\d+)?$/', (string) ( $sigs['version'] ?? '' ) ) ) {
			$problems[] = 'invalid database version';
		}
		if ( ! preg_match( '/^[a-zA-Z0-9._-]+\.json$/', (string) ( $sigs['file'] ?? '' ) ) ) {
			$problems[] = 'database file name must be a plain .json name in the feed directory';
		}
		if ( ! preg_match( '/^[a-f0-9]{64}$/', (string) ( $sigs['sha256'] ?? '' ) ) ) {
			$problems[] = 'missing database sha256';
		}
		if ( (int) ( $sigs['size'] ?? 0 ) <= 0 || (int) $sigs['size'] > self::MAX_DATABASE ) {
			$problems[] = 'database size out of range';
		}
		if ( (int) ( $sigs['db_schema'] ?? 0 ) > Signatures::SCHEMA ) {
			$problems[] = 'database needs a newer plugin (schema)';
		}
		if ( version_compare( $plugin_version, (string) ( $sigs['min_plugin'] ?? '0' ), '<' ) ) {
			$problems[] = 'database needs a newer plugin version';
		}
		return $problems;
	}

	/** True when $candidate is a strictly newer YYYY.MM.DD[.N] version than $installed. */
	public static function is_newer( string $candidate, string $installed ): bool {
		return version_compare( self::comparable( $candidate ), self::comparable( $installed ), '>' );
	}

	private static function comparable( string $version ): string {
		return preg_match( '/^\d{4}\.\d{2}\.\d{2}(?:\.\d+)?$/', $version ) ? ( substr_count( $version, '.' ) === 2 ? $version . '.0' : $version ) : '0';
	}
}
