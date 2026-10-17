<?php
/**
 * Findings table: one row per (file, signature) detection.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Findings {

	public const DB_VERSION = '1';

	public const STATUSES = array( 'open', 'quarantined', 'ignored', 'resolved' );

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'fckmw_findings';
	}

	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table   = self::table();
		$charset = $wpdb->get_charset_collate();

		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				scan_id varchar(32) NOT NULL DEFAULT '',
				source varchar(20) NOT NULL DEFAULT 'builtin',
				file text NOT NULL,
				file_hash char(64) NOT NULL DEFAULT '',
				signature_id varchar(191) NOT NULL DEFAULT '',
				signature_name varchar(255) NOT NULL DEFAULT '',
				severity varchar(10) NOT NULL DEFAULT 'medium',
				line int(10) unsigned NOT NULL DEFAULT 0,
				excerpt text NULL,
				status varchar(20) NOT NULL DEFAULT 'open',
				quarantine_key varchar(64) NOT NULL DEFAULT '',
				detected_at datetime NOT NULL,
				updated_at datetime NOT NULL,
				PRIMARY KEY  (id),
				KEY status (status),
				KEY source (source)
			) {$charset};"
		);

		update_option( 'fckmw_db_version', self::DB_VERSION, false );
	}

	public function add( array $row ): int {
		global $wpdb;
		$now = current_time( 'mysql', true );
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'scan_id'        => (string) ( $row['scan_id'] ?? '' ),
				'source'         => (string) ( $row['source'] ?? 'builtin' ),
				'file'           => (string) $row['file'],
				'file_hash'      => (string) ( $row['file_hash'] ?? '' ),
				'signature_id'   => (string) $row['signature_id'],
				'signature_name' => (string) ( $row['signature_name'] ?? $row['signature_id'] ),
				'severity'       => (string) ( $row['severity'] ?? 'medium' ),
				'line'           => (int) ( $row['line'] ?? 0 ),
				'excerpt'        => (string) ( $row['excerpt'] ?? '' ),
				'status'         => 'open',
				'detected_at'    => $now,
				'updated_at'     => $now,
			)
		);
		return (int) $wpdb->insert_id;
	}

	public function get( int $id ): ?array {
		global $wpdb;
		$table = self::table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB
		return $row ?: null;
	}

	/** @return array{rows: array<int, array>, total: int} */
	public function query( string $status = 'open', int $page = 1, int $per_page = 50 ): array {
		global $wpdb;
		$table  = self::table();
		$status = in_array( $status, self::STATUSES, true ) ? $status : 'open';
		$offset = max( 0, $page - 1 ) * $per_page;

		// phpcs:disable WordPress.DB
		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE status = %s", $status ) );
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE status = %s
				ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'), file ASC
				LIMIT %d OFFSET %d",
				$status,
				$per_page,
				$offset
			),
			ARRAY_A
		);
		// phpcs:enable

		return array( 'rows' => $rows ?: array(), 'total' => $total );
	}

	/** @return array<string, int> Open findings per severity, plus 'total'. */
	public function open_counts(): array {
		global $wpdb;
		$table  = self::table();
		$counts = array_fill_keys( array_keys( Signatures::SEVERITIES ), 0 );
		$rows   = $wpdb->get_results( "SELECT severity, COUNT(*) AS n FROM {$table} WHERE status = 'open' GROUP BY severity", ARRAY_A ); // phpcs:ignore WordPress.DB
		foreach ( (array) $rows as $row ) {
			$counts[ $row['severity'] ] = (int) $row['n'];
		}
		$counts['total'] = array_sum( $counts );
		return $counts;
	}

	public function set_status( int $id, string $status, string $quarantine_key = '' ): bool {
		global $wpdb;
		if ( ! in_array( $status, self::STATUSES, true ) ) {
			return false;
		}
		return false !== $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'status'         => $status,
				'quarantine_key' => $quarantine_key,
				'updated_at'     => current_time( 'mysql', true ),
			),
			array( 'id' => $id )
		);
	}

	/** Mark every other open finding on the same file with the same status (one file, many signatures). */
	public function set_status_for_file( string $file, string $status, string $quarantine_key = '' ): void {
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'status'         => $status,
				'quarantine_key' => $quarantine_key,
				'updated_at'     => current_time( 'mysql', true ),
			),
			array( 'file' => $file, 'status' => 'open' )
		);
	}

	/** Drop open findings from the given sources before they are re-detected. */
	public function clear_open( array $sources ): void {
		global $wpdb;
		$table        = self::table();
		$placeholders = implode( ',', array_fill( 0, count( $sources ), '%s' ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE status = 'open' AND source IN ({$placeholders})", $sources ) ); // phpcs:ignore WordPress.DB
	}

	public function has_open( string $file, string $signature_id ): bool {
		global $wpdb;
		$table = self::table();
		return (bool) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT 1 FROM {$table} WHERE status = 'open' AND file = %s AND signature_id = %s LIMIT 1", $file, $signature_id )
		);
	}

	/** True when an admin ignored this exact detection on this exact file content. */
	public function is_ignored( string $file, string $signature_id, string $hash ): bool {
		global $wpdb;
		$table = self::table();
		return (bool) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT 1 FROM {$table} WHERE status = 'ignored' AND file = %s AND signature_id = %s AND file_hash = %s LIMIT 1",
				$file,
				$signature_id,
				$hash
			)
		);
	}

	/** True when an admin ignored this detection, regardless of content (used for Imunify results, which carry no hash). */
	public function is_ignored_any( string $file, string $signature_id ): bool {
		global $wpdb;
		$table = self::table();
		return (bool) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT 1 FROM {$table} WHERE status = 'ignored' AND file = %s AND signature_id = %s LIMIT 1",
				$file,
				$signature_id
			)
		);
	}
}
