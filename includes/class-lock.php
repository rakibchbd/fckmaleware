<?php
/**
 * Cross-request mutex stored in the options table.
 *
 * add_option() is not atomic (it upserts), so the lock row is created with
 * INSERT IGNORE and ownership is checked through affected-row counts.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Lock {

	private static function option( string $name ): string {
		return 'fckmw_lock_' . $name;
	}

	/** Locks always live in the main site's options table so they are network-wide on multisite. */
	private static function table(): string {
		global $wpdb;
		return $wpdb->base_prefix . 'options';
	}

	/** @return string|null Token to release the lock with, or null if someone else holds it. */
	public static function acquire( string $name, int $ttl ): ?string {
		global $wpdb;
		$table  = self::table();
		$option = self::option( $name );
		$token  = bin2hex( random_bytes( 8 ) );
		$value  = $token . '|' . ( time() + $ttl );

		// phpcs:disable WordPress.DB
		$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$table} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $option, $value ) );
		if ( 1 === (int) $inserted ) {
			self::flush_cache( $option );
			return $token;
		}

		// Take over an expired lock, but only if nobody else did in the meantime.
		$current = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$table} WHERE option_name = %s", $option ) );
		$expires = (int) ( explode( '|', $current )[1] ?? 0 );
		if ( $expires < time() ) {
			$taken = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET option_value = %s WHERE option_name = %s AND option_value = %s", $value, $option, $current ) );
			if ( 1 === (int) $taken ) {
				self::flush_cache( $option );
				return $token;
			}
		}
		// phpcs:enable
		return null;
	}

	public static function release( string $name, string $token ): void {
		global $wpdb;
		$table  = self::table();
		$option = self::option( $name );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s AND option_value LIKE %s", $option, $wpdb->esc_like( $token . '|' ) . '%' ) ); // phpcs:ignore WordPress.DB
		self::flush_cache( $option );
	}

	public static function is_locked( string $name ): bool {
		global $wpdb;
		$table  = self::table();
		$value = (string) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$table} WHERE option_name = %s", self::option( $name ) ) ); // phpcs:ignore WordPress.DB
		return '' !== $value && (int) ( explode( '|', $value )[1] ?? 0 ) >= time();
	}

	private static function flush_cache( string $option ): void {
		wp_cache_delete( $option, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}
}
