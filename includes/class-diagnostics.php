<?php
/**
 * Environment and health checks for the Diagnostics screen and support
 * reports. Values that could help an attacker (credentials, absolute paths,
 * environment variables, keys) are never collected.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Diagnostics {

	/**
	 * Sections of [label, value, tone] rows. Tones: good, warn, bad, neutral.
	 *
	 * @return array<string, array<int, array{0: string, 1: string, 2: string}>>
	 */
	public static function collect( Plugin $plugin ): array {
		global $wpdb, $wp_version;
		$yes = __( 'Yes', 'fckmaleware' );
		$no  = __( 'No', 'fckmaleware' );

		$memory   = (string) ini_get( 'memory_limit' );
		$bytes    = wp_convert_hr_to_bytes( $memory );
		$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
		$schema   = get_option( 'fckmw_schema_error' );

		$out = array();
		$out[ __( 'Platform', 'fckmaleware' ) ] = array(
			array( __( 'FCK Malware', 'fckmaleware' ), FCKMW_VERSION, 'neutral' ),
			array( __( 'WordPress', 'fckmaleware' ), (string) $wp_version . ( is_multisite() ? ' (multisite)' : '' ), version_compare( (string) $wp_version, '5.8', '>=' ) ? 'good' : 'bad' ),
			array( __( 'PHP', 'fckmaleware' ), PHP_VERSION . ' (' . PHP_SAPI . ')', version_compare( PHP_VERSION, '8.1', '>=' ) ? 'good' : ( version_compare( PHP_VERSION, '7.4', '>=' ) ? 'warn' : 'bad' ) ),
			array( __( 'Database server', 'fckmaleware' ), method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : (string) $wpdb->db_version(), 'neutral' ),
			array( __( 'Web server', 'fckmaleware' ), isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : __( 'unknown', 'fckmaleware' ), 'neutral' ),
			array( __( 'Database schema', 'fckmaleware' ), (string) get_option( Schema::OPTION, '' ) . ( is_array( $schema ) ? ' · ' . __( 'upgrade failed', 'fckmaleware' ) : '' ), is_array( $schema ) ? 'bad' : ( Schema::is_current() ? 'good' : 'warn' ) ),
		);

		$out[ __( 'Resources', 'fckmaleware' ) ] = array(
			array( __( 'PHP memory limit', 'fckmaleware' ), $memory, $bytes < 0 || $bytes >= 128 * MB_IN_BYTES ? 'good' : 'warn' ),
			array( __( 'Max execution time', 'fckmaleware' ), (string) ini_get( 'max_execution_time' ) . ' s', 'neutral' ),
			array( __( 'Upload size limit', 'fckmaleware' ), size_format( wp_max_upload_size() ), 'neutral' ),
			array( __( 'open_basedir restriction', 'fckmaleware' ), '' !== (string) ini_get( 'open_basedir' ) ? $yes : $no, 'neutral' ),
		);

		$extensions = array(
			'tokenizer' => array( __( 'Heuristic engine', 'fckmaleware' ), true ),
			'json'      => array( __( 'Settings, signatures', 'fckmaleware' ), true ),
			'hash'      => array( __( 'Checksums', 'fckmaleware' ), true ),
			'zlib'      => array( __( 'Compressed quarantine (falls back to base64)', 'fckmaleware' ), false ),
			'mbstring'  => array( __( 'Text handling', 'fckmaleware' ), false ),
			'openssl'   => array( __( 'HTTPS downloads', 'fckmaleware' ), false ),
			'curl'      => array( __( 'HTTPS downloads', 'fckmaleware' ), false ),
		);
		$rows = array();
		foreach ( $extensions as $ext => $meta ) {
			$loaded = extension_loaded( $ext );
			$rows[] = array( $ext . ' · ' . $meta[0], $loaded ? __( 'Loaded', 'fckmaleware' ) : __( 'Missing', 'fckmaleware' ), $loaded ? 'good' : ( $meta[1] ? 'bad' : 'warn' ) );
		}
		$rows[] = array( 'sodium · ' . __( 'Signed signature updates', 'fckmaleware' ), extension_loaded( 'sodium' ) ? __( 'Loaded', 'fckmaleware' ) : ( function_exists( 'sodium_crypto_sign_verify_detached' ) ? __( 'WordPress sodium_compat', 'fckmaleware' ) : __( 'Missing', 'fckmaleware' ) ), function_exists( 'sodium_crypto_sign_verify_detached' ) ? 'good' : 'bad' );
		$proc   = function_exists( 'proc_open' ) && ! in_array( 'proc_open', $disabled, true );
		$rows[] = array( 'proc_open · ' . __( 'Server scanner agents', 'fckmaleware' ), $proc ? __( 'Available', 'fckmaleware' ) : __( 'Disabled', 'fckmaleware' ), $proc ? 'good' : 'neutral' );
		$out[ __( 'PHP extensions and functions', 'fckmaleware' ) ] = $rows;

		$data    = Paths::data_dir();
		$uploads = wp_upload_dir( null, false );
		$out[ __( 'Filesystem', 'fckmaleware' ) ] = array(
			array( __( 'WordPress directory writable', 'fckmaleware' ), wp_is_writable( Paths::root() ) ? $yes : $no, 'neutral' ),
			array( __( 'Uploads writable', 'fckmaleware' ), wp_is_writable( (string) $uploads['basedir'] ) ? $yes : $no, wp_is_writable( (string) $uploads['basedir'] ) ? 'good' : 'bad' ),
			array( __( 'Private data folder writable', 'fckmaleware' ), is_dir( $data ) && wp_is_writable( $data ) ? $yes : $no, is_dir( $data ) && wp_is_writable( $data ) ? 'good' : 'bad' ),
			array( __( 'Quarantine stored outside the web root', 'fckmaleware' ), Paths::data_dir_in_web_root() ? __( 'No (random name, deny rules, non-executable storage)', 'fckmaleware' ) : $yes, Paths::data_dir_in_web_root() ? 'warn' : 'good' ),
			array( __( 'Data folder set with FCKMW_DATA_DIR', 'fckmaleware' ), null !== Paths::custom_data_dir() ? $yes : $no, 'neutral' ),
			array( __( 'Filesystem method', 'fckmaleware' ), function_exists( 'get_filesystem_method' ) ? (string) get_filesystem_method() : ( defined( 'FS_METHOD' ) ? (string) FS_METHOD : 'direct' ), 'neutral' ),
		);

		$overdue = 0;
		foreach ( (array) _get_cron_array() as $timestamp => $hooks ) {
			foreach ( array_keys( (array) $hooks ) as $hook ) {
				if ( 0 === strpos( (string) $hook, 'fckmw_' ) && (int) $timestamp < time() - 15 * MINUTE_IN_SECONDS ) {
					$overdue++;
				}
			}
		}
		$cron_off = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		$out[ __( 'Scheduled tasks', 'fckmaleware' ) ] = array(
			array( 'DISABLE_WP_CRON', $cron_off ? __( 'Set: a system cron must call wp-cron.php', 'fckmaleware' ) : __( 'Not set', 'fckmaleware' ), $cron_off ? 'warn' : 'good' ),
			array( 'ALTERNATE_WP_CRON', defined( 'ALTERNATE_WP_CRON' ) && ALTERNATE_WP_CRON ? $yes : $no, 'neutral' ),
			array( __( 'FCK Malware tasks overdue by 15+ minutes', 'fckmaleware' ), (string) $overdue, $overdue ? 'warn' : 'good' ),
		);

		$scan    = $plugin->scanner()->state();
		$sigs    = $plugin->signatures();
		$updates = $plugin->signature_updater()->state();
		$last    = ScanHistory::latest( null, false );
		$out[ __( 'Scanner and signatures', 'fckmaleware' ) ] = array(
			array( __( 'Scanner', 'fckmaleware' ), 'running' === $scan['status'] ? __( 'Running', 'fckmaleware' ) : __( 'Idle', 'fckmaleware' ), 'good' ),
			array( __( 'Last scan', 'fckmaleware' ), $last ? ScanHistory::label( (string) $last['mode'] ) . ' · ' . $last['status'] . ' · ' . human_time_diff( (int) $last['finished'] ) : __( 'none', 'fckmaleware' ), $last && 'failed' === $last['status'] ? 'warn' : 'neutral' ),
			array( __( 'Signature database', 'fckmaleware' ), sprintf( '%s · %d rules · %d hashes', $sigs->version(), $sigs->count(), $sigs->hash_count() ), $sigs->count() ? 'good' : 'bad' ),
			array( __( 'Rejected rules', 'fckmaleware' ), (string) count( $sigs->invalid() ), $sigs->invalid() ? 'warn' : 'good' ),
			array( __( 'Signature update', 'fckmaleware' ), $updates['last_error'] ? $updates['last_error'] : ( $updates['last_success'] ? human_time_diff( (int) $updates['last_success'] ) : __( 'never', 'fckmaleware' ) ), $updates['failures'] >= 3 ? 'warn' : 'neutral' ),
		);

		$rows = array();
		foreach ( $plugin->integrations()->providers() as $provider ) {
			$rows[] = array( $provider['name'], $provider['enabled'] ? __( 'In use', 'fckmaleware' ) : ( $provider['detected'] ? __( 'Detected', 'fckmaleware' ) : __( 'Not detected', 'fckmaleware' ) ), $provider['enabled'] ? 'good' : 'neutral' );
		}
		$out[ __( 'Server integrations', 'fckmaleware' ) ] = $rows;
		return $out;
	}

	/** Plain-text report for support requests (same data, no secrets). */
	public static function report( Plugin $plugin ): string {
		$lines = array( '### FCK Malware diagnostics ' . gmdate( 'Y-m-d H:i' ) . ' UTC' );
		foreach ( self::collect( $plugin ) as $section => $rows ) {
			$lines[] = '';
			$lines[] = '## ' . $section;
			foreach ( $rows as $row ) {
				$lines[] = '- ' . $row[0] . ': ' . $row[1];
			}
		}
		return implode( "\n", $lines );
	}
}
