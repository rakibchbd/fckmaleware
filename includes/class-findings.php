<?php
/**
 * Findings store: one row per (object, signature) detection.
 *
 * A finding is upserted every time a scan sees it. A scan that covered an
 * object and no longer sees the detection marks it resolved; a detection
 * that reappears after being resolved or quarantined counts as reinfection.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Findings {

	/** @deprecated 1.0 Use Schema::VERSION. */
	public const DB_VERSION = Schema::VERSION;

	public const STATUSES = array( 'open', 'quarantined', 'ignored', 'resolved' );

	public const VERDICTS = array( 'malicious', 'suspicious' );

	/** Fields a detection may carry; anything else passed to upsert() is ignored. */
	private const FIELDS = array( 'scan_id', 'source', 'object_type', 'object_ref', 'file', 'file_hash', 'signature_id', 'signature_name', 'family', 'severity', 'verdict', 'confidence', 'line', 'excerpt', 'evidence', 'remediation' );

	public static function table(): string {
		return Schema::table( 'findings' );
	}

	/** @deprecated 1.0 Use Schema::install(). */
	public static function install(): void {
		Schema::install();
	}

	/**
	 * Record a detection. Returns the finding ID and what happened to it.
	 *
	 * @return array{id: int, outcome: string} outcome: new | updated | reinfection | ignored
	 */
	public function upsert( array $detection ): array {
		global $wpdb;
		$table = self::table();
		$row   = self::normalize( $detection );
		$now   = current_time( 'mysql', true );

		// phpcs:disable WordPress.DB
		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, status, file_hash FROM {$table} WHERE object_type = %s AND object_ref = %s AND signature_id = %s ORDER BY id DESC LIMIT 1",
				$row['object_type'],
				$row['object_ref'],
				$row['signature_id']
			),
			ARRAY_A
		);
		// phpcs:enable

		if ( $existing ) {
			$id = (int) $existing['id'];

			// An ignore is bound to the content it was made for.
			if ( 'ignored' === $existing['status'] && ( '' === $row['file_hash'] || $existing['file_hash'] === $row['file_hash'] ) ) {
				return array( 'id' => $id, 'outcome' => 'ignored' );
			}

			$outcome = 'updated';
			$update  = $row;
			unset( $update['object_type'], $update['object_ref'], $update['signature_id'] );
			$update['last_seen_at'] = $now;
			$update['updated_at']   = $now;

			if ( 'open' !== $existing['status'] ) {
				$outcome                  = in_array( $existing['status'], array( 'resolved', 'quarantined' ), true ) ? 'reinfection' : 'updated';
				$update['status']         = 'open';
				$update['quarantine_key'] = '';
			}

			$wpdb->update( $table, $update, array( 'id' => $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			if ( 'open' !== $existing['status'] ) {
				$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET occurrences = occurrences + 1 WHERE id = %d", $id ) ); // phpcs:ignore WordPress.DB
			}
			return self::recorded( $row, array( 'id' => $id, 'outcome' => $outcome ) );
		}

		$row['status']       = 'open';
		$row['detected_at']  = $now;
		$row['last_seen_at'] = $now;
		$row['updated_at']   = $now;
		$wpdb->insert( $table, $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		return self::recorded( $row, array( 'id' => (int) $wpdb->insert_id, 'outcome' => 'new' ) );
	}

	private static function recorded( array $row, array $result ): array {
		/**
		 * Fires after a detection was stored (new, updated or reinfection).
		 *
		 * @param array $row    Normalized finding.
		 * @param array $result id and outcome.
		 */
		do_action( 'fckmw_finding_recorded', $row, $result );
		return $result;
	}

	/** Backwards-compatible insert used by 0.x code paths. */
	public function add( array $row ): int {
		return $this->upsert( $row )['id'];
	}

	private static function normalize( array $d ): array {
		$row = array_intersect_key( $d, array_flip( self::FIELDS ) );

		$row['object_type'] = (string) ( $row['object_type'] ?? 'file' );
		$row['file']        = (string) ( $row['file'] ?? '' );
		$row['object_ref']  = substr( (string) ( $row['object_ref'] ?? $row['file'] ), 0, 191 );
		$row['source']      = (string) ( $row['source'] ?? 'signature' );
		$row['severity']    = isset( Signatures::SEVERITIES[ $row['severity'] ?? '' ] ) ? $row['severity'] : 'medium';
		$row['verdict']     = in_array( $row['verdict'] ?? '', self::VERDICTS, true ) ? $row['verdict'] : 'malicious';
		$row['confidence']  = max( 0, min( 100, (int) ( $row['confidence'] ?? 80 ) ) );
		$row['line']        = max( 0, (int) ( $row['line'] ?? 0 ) );
		foreach ( array( 'scan_id', 'file_hash', 'signature_id', 'signature_name', 'family', 'excerpt', 'evidence', 'remediation' ) as $text ) {
			$row[ $text ] = (string) ( $row[ $text ] ?? '' );
		}
		$row['signature_name'] = substr( '' !== $row['signature_name'] ? $row['signature_name'] : $row['signature_id'], 0, 255 );
		$row['family']         = substr( $row['family'], 0, 100 );
		return $row;
	}

	/**
	 * After a completed scan, close open findings it covered but did not see again.
	 *
	 * @param string[] $sources     Layers the scan ran.
	 * @param string   $object_type Object type the scan covered.
	 * @param string   $prefix      Limit to objects whose ref starts with this (custom-directory scans).
	 * @return int Number of findings resolved.
	 */
	public function resolve_stale( string $scan_id, array $sources, string $object_type = 'file', string $prefix = '' ): int {
		global $wpdb;
		if ( ! $sources ) {
			return 0;
		}
		$table        = self::table();
		$placeholders = implode( ',', array_fill( 0, count( $sources ), '%s' ) );
		$args         = array_merge( array( current_time( 'mysql', true ), $object_type, $scan_id ), $sources );
		$sql          = "UPDATE {$table} SET status = 'resolved', updated_at = %s WHERE status = 'open' AND object_type = %s AND scan_id <> %s AND source IN ({$placeholders})";
		if ( '' !== $prefix ) {
			$sql   .= ' AND object_ref LIKE %s';
			$args[] = $wpdb->esc_like( $prefix ) . '%';
		}
		return (int) $wpdb->query( $wpdb->prepare( $sql, $args ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Mark that the open findings of skipped (unchanged, cached) files are still current.
	 *
	 * @param string[] $refs
	 */
	public function touch( array $refs, string $scan_id ): void {
		global $wpdb;
		if ( ! $refs ) {
			return;
		}
		$table        = self::table();
		$placeholders = implode( ',', array_fill( 0, count( $refs ), '%s' ) );
		$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET scan_id = %s WHERE status = 'open' AND object_type = 'file' AND object_ref IN ({$placeholders})", array_merge( array( $scan_id ), $refs ) ) ); // phpcs:ignore WordPress.DB
	}

	public function get( int $id ): ?array {
		global $wpdb;
		$table = self::table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB
		return $row ?: null;
	}

	/** File-type filter values => LIKE suffixes on the path. */
	public const FILE_TYPES = array(
		'php'      => array( '.php', '.phtml', '.phar', '.php5', '.php7', '.inc' ),
		'js'       => array( '.js', '.mjs' ),
		'config'   => array( '.htaccess', '.user.ini', '.ini', 'web.config' ),
		'html'     => array( '.html', '.htm', '.svg' ),
		'image'    => array( '.jpg', '.jpeg', '.png', '.gif', '.ico', '.webp', '.bmp' ),
	);

	/** Confidence bands for filtering. */
	public const CONFIDENCE_BANDS = array(
		'high'   => array( 90, 100 ),
		'medium' => array( 70, 89 ),
		'low'    => array( 0, 69 ),
	);

	/**
	 * How certain a finding is: "confirmed" (exact known-malware signature or
	 * server scanner match at 90%+), "likely" (other malicious verdicts),
	 * "change" (integrity differences that are not proof of malware) or
	 * "suspicious".
	 */
	public static function classify( array $row ): string {
		$verdict    = (string) ( $row['verdict'] ?? '' );
		$source     = (string) ( $row['source'] ?? '' );
		$confidence = (int) ( $row['confidence'] ?? 0 );
		if ( 'malicious' === $verdict && $confidence >= 90 && in_array( $source, array( 'signature', 'imunify' ), true ) ) {
			return 'confirmed';
		}
		if ( 'malicious' === $verdict ) {
			return 'likely';
		}
		return 'integrity' === $source ? 'change' : 'suspicious';
	}

	/**
	 * WHERE clause for the filters shared by the list, counts and bulk jobs.
	 *
	 * @return array{0: string, 1: array}
	 */
	private static function where( array $filters ): array {
		global $wpdb;
		$where = array( 'status = %s' );
		$args  = array( in_array( $filters['status'] ?? 'open', self::STATUSES, true ) ? $filters['status'] : 'open' );

		foreach ( array( 'source', 'object_type', 'severity', 'verdict' ) as $column ) {
			if ( ! empty( $filters[ $column ] ) ) {
				$where[] = "{$column} = %s";
				$args[]  = (string) $filters[ $column ];
			}
		}
		if ( ! empty( $filters['confidence'] ) && isset( self::CONFIDENCE_BANDS[ $filters['confidence'] ] ) ) {
			$where[] = 'confidence BETWEEN %d AND %d';
			array_push( $args, self::CONFIDENCE_BANDS[ $filters['confidence'] ][0], self::CONFIDENCE_BANDS[ $filters['confidence'] ][1] );
		}
		if ( ! empty( $filters['min_confidence'] ) ) {
			$where[] = 'confidence >= %d';
			$args[]  = (int) $filters['min_confidence'];
		}
		if ( ! empty( $filters['file_type'] ) && isset( self::FILE_TYPES[ $filters['file_type'] ] ) ) {
			$likes = array();
			foreach ( self::FILE_TYPES[ $filters['file_type'] ] as $suffix ) {
				$likes[] = 'file LIKE %s';
				$args[]  = '%' . $wpdb->esc_like( $suffix );
			}
			$where[] = "object_type = 'file' AND (" . implode( ' OR ', $likes ) . ')';
		}
		if ( ! empty( $filters['since_days'] ) ) {
			$where[] = 'detected_at >= %s';
			$args[]  = gmdate( 'Y-m-d H:i:s', time() - (int) $filters['since_days'] * DAY_IN_SECONDS );
		}
		if ( ! empty( $filters['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( (string) $filters['search'] ) . '%';
			$where[] = '(file LIKE %s OR signature_name LIKE %s OR signature_id LIKE %s)';
			array_push( $args, $like, $like, $like );
		}
		return array( implode( ' AND ', $where ), $args );
	}

	/**
	 * @param array{status?: string, source?: string, object_type?: string, severity?: string, verdict?: string, confidence?: string, file_type?: string, since_days?: int, search?: string} $filters
	 * @return array{rows: array<int, array>, total: int}
	 */
	public function query( $filters = 'open', int $page = 1, int $per_page = 50 ): array {
		global $wpdb;
		$filters                  = is_array( $filters ) ? $filters : array( 'status' => (string) $filters );
		$table                    = self::table();
		list( $where_sql, $args ) = self::where( $filters );
		$per_page                 = max( 1, $per_page );
		$offset                   = max( 0, $page - 1 ) * $per_page;

		// phpcs:disable WordPress.DB
		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}", $args ) );
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE {$where_sql}
				ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'), FIELD(verdict, 'malicious', 'suspicious'), confidence DESC, file ASC
				LIMIT %d OFFSET %d",
				array_merge( $args, array( $per_page, $offset ) )
			),
			ARRAY_A
		);
		// phpcs:enable

		return array( 'rows' => $rows ?: array(), 'total' => $total );
	}

	public function count( array $filters ): int {
		global $wpdb;
		$table                    = self::table();
		list( $where_sql, $args ) = self::where( $filters );
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}", $args ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Next page of matching rows in id order, for bulk jobs that walk large
	 * result sets in bounded batches without holding them in memory.
	 *
	 * @return array<int, array>
	 */
	public function batch_after( array $filters, int $after_id, int $limit ): array {
		global $wpdb;
		$table                    = self::table();
		list( $where_sql, $args ) = self::where( $filters );
		$args                     = array_merge( $args, array( $after_id, max( 1, $limit ) ) );
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where_sql} AND id > %d ORDER BY id ASC LIMIT %d", $args ), ARRAY_A ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Findings detected since $since, bucketed for the "top threats" chart:
	 * malware, suspicious, heuristic, false positive (accepted) and other
	 * (integrity, behaviour, database).
	 *
	 * @return array<string, int>
	 */
	public function breakdown_since( int $since ): array {
		global $wpdb;
		$table = self::table();
		$out   = array( 'malware' => 0, 'suspicious' => 0, 'heuristic' => 0, 'false_positive' => 0, 'other' => 0 );
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT status, source, verdict, COUNT(*) AS n FROM {$table} WHERE detected_at >= %s GROUP BY status, source, verdict", gmdate( 'Y-m-d H:i:s', $since ) ), ARRAY_A ); // phpcs:ignore WordPress.DB
		foreach ( (array) $rows as $row ) {
			if ( 'ignored' === $row['status'] ) {
				$bucket = 'false_positive';
			} elseif ( 'heuristic' === $row['source'] ) {
				$bucket = 'heuristic';
			} elseif ( in_array( $row['source'], array( 'integrity', 'behaviour', 'database' ), true ) ) {
				$bucket = 'other';
			} else {
				$bucket = 'malicious' === $row['verdict'] ? 'malware' : 'suspicious';
			}
			$out[ $bucket ] += (int) $row['n'];
		}
		return $out;
	}

	/** @return array<string, int> Open findings per severity, plus 'total', 'malicious', 'suspicious'. */
	public function open_counts(): array {
		global $wpdb;
		$table  = self::table();
		$counts = array_fill_keys( array_merge( array_keys( Signatures::SEVERITIES ), self::VERDICTS ), 0 );
		$rows   = $wpdb->get_results( "SELECT severity, verdict, COUNT(*) AS n FROM {$table} WHERE status = 'open' GROUP BY severity, verdict", ARRAY_A ); // phpcs:ignore WordPress.DB
		foreach ( (array) $rows as $row ) {
			if ( isset( $counts[ $row['severity'] ] ) ) {
				$counts[ $row['severity'] ] += (int) $row['n'];
			}
			if ( isset( $counts[ $row['verdict'] ] ) ) {
				$counts[ $row['verdict'] ] += (int) $row['n'];
			}
		}
		$counts['total'] = $counts['malicious'] + $counts['suspicious'];
		$counts['confirmed'] = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status = 'open' AND verdict = 'malicious' AND confidence >= 90 AND source IN ('signature', 'imunify')" ); // phpcs:ignore WordPress.DB
		return $counts;
	}

	/** @return array<string, int> Number of findings per status. */
	public function status_counts(): array {
		global $wpdb;
		$table  = self::table();
		$counts = array_fill_keys( self::STATUSES, 0 );
		foreach ( (array) $wpdb->get_results( "SELECT status, COUNT(*) AS n FROM {$table} GROUP BY status", ARRAY_A ) as $row ) { // phpcs:ignore WordPress.DB
			$counts[ $row['status'] ] = (int) $row['n'];
		}
		return $counts;
	}

	public function set_status( int $id, string $status, string $quarantine_key = '' ): bool {
		global $wpdb;
		if ( ! in_array( $status, self::STATUSES, true ) ) {
			return false;
		}
		return (bool) $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'status'         => $status,
				'quarantine_key' => $quarantine_key,
				'updated_at'     => current_time( 'mysql', true ),
			),
			array( 'id' => $id )
		);
	}

	/** Move every open finding on a file to a new status (one file, many signatures). */
	public function set_status_for_file( string $file, string $status, string $quarantine_key = '' ): int {
		global $wpdb;
		return (int) $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'status'         => $status,
				'quarantine_key' => $quarantine_key,
				'updated_at'     => current_time( 'mysql', true ),
			),
			array(
				'object_type' => 'file',
				'object_ref'  => substr( $file, 0, 191 ),
				'status'      => 'open',
			)
		);
	}

	/** Move findings linked to a quarantine entry to a new status once it is restored or deleted. */
	public function release_quarantine( string $key, string $status ): void {
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'status'         => $status,
				'quarantine_key' => '',
				'updated_at'     => current_time( 'mysql', true ),
			),
			array( 'quarantine_key' => $key )
		);
	}

	/** Drop open findings from the given sources (used for full re-imports such as Imunify sync). */
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
			$wpdb->prepare( "SELECT 1 FROM {$table} WHERE status = 'open' AND object_type = 'file' AND object_ref = %s AND signature_id = %s LIMIT 1", substr( $file, 0, 191 ), $signature_id ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name only.
		);
	}

	/** True when an admin ignored this detection, regardless of content (for sources that carry no hash). */
	public function is_ignored_any( string $file, string $signature_id ): bool {
		global $wpdb;
		$table = self::table();
		return (bool) $wpdb->get_var( // phpcs:ignore WordPress.DB
			$wpdb->prepare( "SELECT 1 FROM {$table} WHERE status = 'ignored' AND object_ref = %s AND signature_id = %s LIMIT 1", substr( $file, 0, 191 ), $signature_id ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name only.
		);
	}

	/** Delete resolved findings older than $days to keep the table small. */
	public function prune_resolved( int $days ): int {
		global $wpdb;
		$table = self::table();
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE status = 'resolved' AND updated_at < %s", gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ) ) ); // phpcs:ignore WordPress.DB
	}
}
