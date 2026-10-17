<?php
/**
 * Database tables and their migrations.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Schema {

	/** 1 = 0.1/0.2 findings table; 2 = findings v2, file cache, baselines, activity log; 3 = AI review column. */
	public const VERSION = '3';

	public const OPTION = 'fckmw_db_version';

	public static function table( string $name ): string {
		global $wpdb;
		return $wpdb->base_prefix . 'fckmw_' . $name;
	}

	public static function is_current(): bool {
		return self::VERSION === get_option( self::OPTION );
	}

	/** @return bool Whether the schema is now current. */
	public static function install(): bool {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$previous = (string) get_option( self::OPTION, '' );
		$charset  = $wpdb->get_charset_collate();
		$findings = self::table( 'findings' );
		$files    = self::table( 'files' );
		$baseline = self::table( 'baseline' );
		$events   = self::table( 'events' );

		// dbDelta needs two spaces after PRIMARY KEY and one column per line.
		dbDelta(
			"CREATE TABLE {$findings} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				scan_id varchar(32) NOT NULL DEFAULT '',
				source varchar(20) NOT NULL DEFAULT 'signature',
				object_type varchar(20) NOT NULL DEFAULT 'file',
				object_ref varchar(191) NOT NULL DEFAULT '',
				file text NOT NULL,
				file_hash char(64) NOT NULL DEFAULT '',
				signature_id varchar(191) NOT NULL DEFAULT '',
				signature_name varchar(255) NOT NULL DEFAULT '',
				family varchar(100) NOT NULL DEFAULT '',
				severity varchar(10) NOT NULL DEFAULT 'medium',
				verdict varchar(12) NOT NULL DEFAULT 'malicious',
				confidence tinyint(3) unsigned NOT NULL DEFAULT 80,
				line int(10) unsigned NOT NULL DEFAULT 0,
				excerpt text NULL,
				evidence text NULL,
				remediation text NULL,
				ai_review longtext NULL,
				status varchar(20) NOT NULL DEFAULT 'open',
				quarantine_key varchar(64) NOT NULL DEFAULT '',
				occurrences int(10) unsigned NOT NULL DEFAULT 1,
				detected_at datetime NOT NULL,
				last_seen_at datetime NULL DEFAULT NULL,
				updated_at datetime NOT NULL,
				PRIMARY KEY  (id),
				KEY status (status),
				KEY source (source),
				KEY file (file(191)),
				KEY object (object_type,object_ref)
			) {$charset};
			CREATE TABLE {$files} (
				path_hash char(40) NOT NULL,
				path text NOT NULL,
				size bigint(20) unsigned NOT NULL DEFAULT 0,
				mtime bigint(20) unsigned NOT NULL DEFAULT 0,
				sha256 char(64) NOT NULL DEFAULT '',
				engine varchar(64) NOT NULL DEFAULT '',
				clean tinyint(1) NOT NULL DEFAULT 0,
				checked_at bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (path_hash),
				KEY mtime (mtime)
			) {$charset};
			CREATE TABLE {$baseline} (
				path_hash char(40) NOT NULL,
				path text NOT NULL,
				component varchar(191) NOT NULL DEFAULT '',
				component_version varchar(64) NOT NULL DEFAULT '',
				sha256 char(64) NOT NULL DEFAULT '',
				recorded_at bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (path_hash),
				KEY component (component)
			) {$charset};
			CREATE TABLE {$events} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at bigint(20) unsigned NOT NULL DEFAULT 0,
				type varchar(40) NOT NULL DEFAULT '',
				severity varchar(10) NOT NULL DEFAULT 'info',
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				message text NOT NULL,
				context longtext NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY type (type)
			) {$charset};"
		);

		$missing = self::missing_columns( $findings, array( 'object_type', 'object_ref', 'verdict', 'confidence', 'family', 'evidence', 'remediation', 'occurrences', 'last_seen_at', 'ai_review' ) );
		foreach ( array( $files, $baseline, $events ) as $table ) {
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) { // phpcs:ignore WordPress.DB
				$missing[] = $table;
			}
		}
		if ( $missing ) {
			// Leave the version untouched so the upgrade is retried, and make the failure visible.
			update_option( 'fckmw_schema_error', array( 'time' => time(), 'missing' => $missing, 'db_error' => $wpdb->last_error ), false );
			return false;
		}

		if ( '1' === $previous ) {
			self::migrate_from_1( $findings );
		}
		delete_option( 'fckmw_schema_error' );
		update_option( self::OPTION, self::VERSION, false );
		return true;
	}

	/** @return string[] Columns of $table that do not exist. */
	private static function missing_columns( string $table, array $columns ): array {
		global $wpdb;
		$existing = array_map( 'strtolower', (array) $wpdb->get_col( "DESCRIBE {$table}", 0 ) ); // phpcs:ignore WordPress.DB
		return array_values( array_diff( $columns, $existing ) );
	}

	/**
	 * 0.x stored findings in {$wpdb->prefix}fckmw_findings (per-site prefix)
	 * with source "builtin". 1.0 uses one network-wide table.
	 */
	private static function migrate_from_1( string $findings ): void {
		global $wpdb;

		$legacy = $wpdb->prefix . 'fckmw_findings';
		// phpcs:disable WordPress.DB
		if ( $legacy !== $findings && $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $legacy ) ) === $legacy ) {
			$wpdb->query(
				"INSERT INTO {$findings} (scan_id, source, file, file_hash, signature_id, signature_name, severity, line, excerpt, status, quarantine_key, detected_at, last_seen_at, updated_at)
				SELECT scan_id, source, file, file_hash, signature_id, signature_name, severity, line, excerpt, status, quarantine_key, detected_at, updated_at, updated_at FROM {$legacy}"
			);
			$wpdb->query( "DROP TABLE IF EXISTS {$legacy}" );
		}
		$wpdb->query( "UPDATE {$findings} SET source = 'signature' WHERE source = 'builtin'" );
		$wpdb->query( "UPDATE {$findings} SET last_seen_at = updated_at WHERE last_seen_at IS NULL" );
		$wpdb->query( "UPDATE {$findings} SET object_ref = LEFT(file, 191) WHERE object_ref = ''" );
		// phpcs:enable
	}

	public static function drop_all(): void {
		global $wpdb;
		foreach ( array( 'findings', 'files', 'baseline', 'events' ) as $name ) {
			$wpdb->query( 'DROP TABLE IF EXISTS ' . self::table( $name ) ); // phpcs:ignore WordPress.DB
		}
	}
}
