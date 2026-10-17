<?php
/**
 * Append-only security activity log (scans, remediation, behaviour events,
 * updates, notifications). Used for the Activity Logs screen and reports.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class ActivityLog {

	public const SEVERITIES = array( 'info', 'notice', 'warning', 'critical' );

	/** Keep at most this many rows; the age limit is the log_retention_days setting. */
	private const MAX_ROWS = 20000;

	public static function table(): string {
		return Schema::table( 'events' );
	}

	/**
	 * @param string $type     Dotted event type, e.g. "scan.complete", "quarantine.restore", "user.admin_created".
	 * @param string $severity One of self::SEVERITIES.
	 */
	public static function log( string $type, string $message, array $context = array(), string $severity = 'info' ): int {
		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			self::table(),
			array(
				'created_at' => time(),
				'type'       => substr( $type, 0, 40 ),
				'severity'   => in_array( $severity, self::SEVERITIES, true ) ? $severity : 'info',
				'user_id'    => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
				'message'    => $message,
				'context'    => $context ? (string) wp_json_encode( $context, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE ) : null,
			)
		);
		$id = (int) $wpdb->insert_id;

		/**
		 * Fires after a security event has been recorded. The notification engine listens here.
		 *
		 * @param array $event Event row.
		 */
		do_action( 'fckmw_event', array( 'id' => $id, 'type' => $type, 'severity' => $severity, 'message' => $message, 'context' => $context ) );
		return $id;
	}

	/**
	 * @param array{type?: string, types?: string[], severity?: string, since?: int, until?: int, user?: int, search?: string, failed?: bool} $filters
	 *        type may end in "." to match a prefix; types is a list of such types; failed matches *.failed and *.error events.
	 * @return array{rows: array<int, array>, total: int}
	 */
	public static function query( array $filters = array(), int $page = 1, int $per_page = 50 ): array {
		global $wpdb;
		$table = self::table();
		$where = array( '1=1' );
		$args  = array();

		if ( ! empty( $filters['type'] ) ) {
			if ( '.' === substr( $filters['type'], -1 ) ) {
				$where[] = 'type LIKE %s';
				$args[]  = $wpdb->esc_like( $filters['type'] ) . '%';
			} else {
				$where[] = 'type = %s';
				$args[]  = $filters['type'];
			}
		}
		if ( ! empty( $filters['types'] ) ) {
			$any = array();
			foreach ( (array) $filters['types'] as $type ) {
				$any[]  = 'type LIKE %s';
				$args[] = '.' === substr( $type, -1 ) ? $wpdb->esc_like( $type ) . '%' : $wpdb->esc_like( $type );
			}
			$where[] = '(' . implode( ' OR ', $any ) . ')';
		}
		if ( ! empty( $filters['failed'] ) ) {
			$where[] = '(type LIKE %s OR type LIKE %s OR type LIKE %s)';
			array_push( $args, '%' . $wpdb->esc_like( '.failed' ), '%' . $wpdb->esc_like( '.error' ), '%' . $wpdb->esc_like( '.corrupt' ) );
		}
		if ( ! empty( $filters['until'] ) ) {
			$where[] = 'created_at <= %d';
			$args[]  = (int) $filters['until'];
		}
		if ( isset( $filters['user'] ) && '' !== (string) $filters['user'] ) {
			$where[] = 'user_id = %d';
			$args[]  = (int) $filters['user'];
		}
		if ( ! empty( $filters['search'] ) ) {
			$where[] = 'message LIKE %s';
			$args[]  = '%' . $wpdb->esc_like( (string) $filters['search'] ) . '%';
		}
		if ( ! empty( $filters['severity'] ) && in_array( $filters['severity'], self::SEVERITIES, true ) ) {
			$where[] = 'severity = %s';
			$args[]  = $filters['severity'];
		}
		if ( ! empty( $filters['since'] ) ) {
			$where[] = 'created_at >= %d';
			$args[]  = (int) $filters['since'];
		}
		$where_sql = implode( ' AND ', $where );
		$offset    = max( 0, $page - 1 ) * $per_page;

		// phpcs:disable WordPress.DB
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$total     = (int) $wpdb->get_var( $args ? $wpdb->prepare( $count_sql, $args ) : $count_sql );
		$rows      = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d", array_merge( $args, array( $per_page, $offset ) ) ), ARRAY_A );
		// phpcs:enable

		foreach ( (array) $rows as &$row ) {
			$row['context'] = $row['context'] ? (array) json_decode( $row['context'], true ) : array();
		}
		return array( 'rows' => $rows ?: array(), 'total' => $total );
	}

	/** @return array<string, int> Event counts per type prefix (first segment) since $since. */
	public static function summary( int $since ): array {
		global $wpdb;
		$table = self::table();
		$out   = array();
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT type, COUNT(*) AS n FROM {$table} WHERE created_at >= %d GROUP BY type", $since ), ARRAY_A ); // phpcs:ignore WordPress.DB
		foreach ( (array) $rows as $row ) {
			$out[ $row['type'] ] = (int) $row['n'];
		}
		return $out;
	}

	public static function prune(): void {
		global $wpdb;
		$table = self::table();
		// phpcs:disable WordPress.DB
		$days = max( 30, (int) Settings::get( 'log_retention_days' ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %d", time() - $days * DAY_IN_SECONDS ) );
		$cutoff = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", self::MAX_ROWS ) );
		if ( $cutoff ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", $cutoff ) );
		}
		// phpcs:enable
	}
}
