<?php
/**
 * Per-file scan cache for incremental scanning.
 *
 * A file whose size and mtime are unchanged, that was clean, and that was
 * checked with the current engine fingerprint (detection code + signatures
 * + relevant settings) is skipped by quick and standard scans. Deep scans
 * ignore the cache.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class FileCache {

	public static function table(): string {
		return Schema::table( 'files' );
	}

	/**
	 * @param string[] $paths
	 * @return array<string, array> path => row
	 */
	public function get_many( array $paths ): array {
		global $wpdb;
		if ( ! $paths ) {
			return array();
		}
		$table  = self::table();
		$hashes = array_map( 'sha1', $paths );
		$sql    = "SELECT * FROM {$table} WHERE path_hash IN (" . implode( ',', array_fill( 0, count( $hashes ), '%s' ) ) . ')';
		$out    = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( $sql, $hashes ), ARRAY_A ) as $row ) { // phpcs:ignore WordPress.DB
			$out[ $row['path'] ] = $row;
		}
		return $out;
	}

	/**
	 * @param array<int, array{path: string, size: int, mtime: int, sha256: string, engine: string, clean: bool}> $rows
	 */
	public function put_many( array $rows ): void {
		global $wpdb;
		if ( ! $rows ) {
			return;
		}
		$table  = self::table();
		$values = array();
		$args   = array();
		$now    = time();
		foreach ( $rows as $row ) {
			$values[] = '(%s, %s, %d, %d, %s, %s, %d, %d)';
			array_push( $args, sha1( $row['path'] ), $row['path'], $row['size'], $row['mtime'], $row['sha256'], $row['engine'], $row['clean'] ? 1 : 0, $now );
		}
		$wpdb->query( $wpdb->prepare( "REPLACE INTO {$table} (path_hash, path, size, mtime, sha256, engine, clean, checked_at) VALUES " . implode( ',', $values ), $args ) ); // phpcs:ignore WordPress.DB
	}

	public function forget( string $path ): void {
		global $wpdb;
		$wpdb->delete( self::table(), array( 'path_hash' => sha1( $path ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	public function clear(): void {
		global $wpdb;
		$wpdb->query( 'TRUNCATE TABLE ' . self::table() ); // phpcs:ignore WordPress.DB
	}

	/** @return array{files: int, clean: int} */
	public static function stats(): array {
		global $wpdb;
		$table = self::table();
		$row   = $wpdb->get_row( "SELECT COUNT(*) AS files, SUM(clean) AS clean FROM {$table}", ARRAY_A ); // phpcs:ignore WordPress.DB
		return array( 'files' => (int) ( $row['files'] ?? 0 ), 'clean' => (int) ( $row['clean'] ?? 0 ) );
	}
}
