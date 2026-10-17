<?php
/**
 * Encryption at rest for stored credentials (the external AI API key).
 *
 * Values are sealed with libsodium's secretbox (PHP's sodium extension or
 * WordPress's bundled sodium_compat) under a key derived from the site's
 * authentication salts, so a copy of the options table alone does not reveal
 * them. Values written before 1.1 are plain text and are still read; they are
 * encrypted on the next save. If the salts change, the stored value can no
 * longer be decrypted and reads as empty.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Secrets {

	private const PREFIX = 'fckmw-enc:v1:';

	private static function key(): ?string {
		if ( ! function_exists( 'sodium_crypto_secretbox' ) || ! function_exists( 'wp_salt' ) ) {
			return null;
		}
		return hash( 'sha256', wp_salt( 'auth' ) . '|fckmw-secrets', true );
	}

	public static function encrypt( string $plain ): string {
		$key = self::key();
		if ( '' === $plain || null === $key || self::is_encrypted( $plain ) ) {
			return $plain;
		}
		try {
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			return self::PREFIX . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $key ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		} catch ( \Throwable $e ) {
			return $plain;
		}
	}

	public static function decrypt( string $stored ): string {
		if ( ! self::is_encrypted( $stored ) ) {
			return $stored;
		}
		$key = self::key();
		$raw = base64_decode( substr( $stored, strlen( self::PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( null === $key || false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return '';
		}
		try {
			$plain = sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $key );
		} catch ( \Throwable $e ) {
			return '';
		}
		return false === $plain ? '' : $plain;
	}

	public static function is_encrypted( string $value ): bool {
		return 0 === strpos( $value, self::PREFIX );
	}
}
