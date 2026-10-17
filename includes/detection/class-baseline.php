<?php
/**
 * Local file baselines for components without authoritative checksums
 * (themes, premium plugins, mu-plugins, drop-ins, configuration files).
 *
 * The first scan that sees a component at a given version records the
 * SHA-256 of its files. Later scans report files that changed, or new PHP
 * files that appeared, while the component version stayed the same.
 *
 * Limitation: a baseline only proves a file has not changed since it was
 * recorded. If the component was already infected at that moment, the
 * infection is part of the baseline; the signature and heuristic layers are
 * what catch that case.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Schema;

final class Baseline {

	/** @var array<string, bool> component@version => has rows */
	private $known = array();

	public static function table(): string {
		return Schema::table( 'baseline' );
	}

	public static function key( string $path ): string {
		return sha1( $path );
	}

	public function get( string $path ): ?array {
		global $wpdb;
		$table = self::table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE path_hash = %s", self::key( $path ) ), ARRAY_A ); // phpcs:ignore WordPress.DB
		return $row ?: null;
	}

	public function set( string $path, string $component, string $version, string $sha256 ): void {
		global $wpdb;
		$wpdb->replace( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'path_hash'         => self::key( $path ),
				'path'              => $path,
				'component'         => substr( $component, 0, 191 ),
				'component_version' => substr( $version, 0, 64 ),
				'sha256'            => $sha256,
				'recorded_at'       => time(),
			)
		);
	}

	/** Whether the component already has a baseline for exactly this version. */
	public function has( string $component, string $version ): bool {
		global $wpdb;
		$cache_key = $component . '@' . $version;
		if ( ! isset( $this->known[ $cache_key ] ) ) {
			$table                     = self::table();
			$this->known[ $cache_key ] = (bool) $wpdb->get_var( $wpdb->prepare( "SELECT 1 FROM {$table} WHERE component = %s AND component_version = %s LIMIT 1", $component, $version ) ); // phpcs:ignore WordPress.DB
		}
		return $this->known[ $cache_key ];
	}

	/** Forget a component, e.g. after it was updated or deleted, so it is re-baselined. */
	public function forget( string $component ): void {
		global $wpdb;
		$wpdb->delete( self::table(), array( 'component' => $component ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		foreach ( array_keys( $this->known ) as $key ) {
			if ( 0 === strpos( $key, $component . '@' ) ) {
				unset( $this->known[ $key ] );
			}
		}
	}

	public function mark_known( string $component, string $version ): void {
		$this->known[ $component . '@' . $version ] = true;
	}

	/** @return array{files: int, components: int} */
	public static function stats(): array {
		global $wpdb;
		$table = self::table();
		$row   = $wpdb->get_row( "SELECT COUNT(*) AS files, COUNT(DISTINCT component) AS components FROM {$table}", ARRAY_A ); // phpcs:ignore WordPress.DB
		return array( 'files' => (int) ( $row['files'] ?? 0 ), 'components' => (int) ( $row['components'] ?? 0 ) );
	}
}
