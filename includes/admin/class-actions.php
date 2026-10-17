<?php
/**
 * Every state-changing admin request goes through here: capability check
 * (network-level on multisite), a per-command nonce, an allowlist of commands
 * and sub-operations, and a redirect back with a notice.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin;

use Fckmaleware\ActivityLog;
use Fckmaleware\Ai\Reviewer;
use Fckmaleware\Feedback;
use Fckmaleware\Findings;
use Fckmaleware\Hardening;
use Fckmaleware\Notifier;
use Fckmaleware\Plugin;
use Fckmaleware\Settings;
use Fckmaleware\Store;

final class Actions {

	/** command => method */
	private const COMMANDS = array(
		'settings'         => 'save_settings',
		'finding'          => 'finding',
		'bulk'             => 'bulk',
		'quarantine_item'  => 'quarantine_item',
		'rollback'         => 'rollback',
		'hardening'        => 'hardening',
		'hardening_check'  => 'hardening_check',
		'imunify'          => 'imunify',
		'signatures'       => 'signatures',
		'notify_test'      => 'notify_test',
		'webhook_secret'   => 'webhook_secret',
		'persistence'      => 'persistence',
		'cache_clear'      => 'cache_clear',
		'export_findings'  => 'export_findings',
		'export_activity'  => 'export_activity',
		'feedback_export'  => 'feedback_export',
	);

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function register(): void {
		add_action( 'admin_post_fckmw', array( $this, 'handle' ) );
		add_action( 'network_admin_edit_fckmw', array( $this, 'handle' ) );
		foreach ( array( 'scan_start', 'scan_step', 'scan_cancel', 'db_start', 'db_step' ) as $ajax ) {
			add_action( 'wp_ajax_fckmw_' . $ajax, array( $this, 'ajax_' . $ajax ) );
		}
	}

	public function handle(): void {
		$command = sanitize_key( wp_unslash( $_POST['fckmw_command'] ?? '' ) ); // phpcs:ignore WordPress.Security.NonceVerification -- verified below per command.
		if ( ! Ui::can() ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'fckmaleware' ), 403 );
		}
		if ( ! isset( self::COMMANDS[ $command ] ) ) {
			wp_die( esc_html__( 'Unknown action.', 'fckmaleware' ), 400 );
		}
		check_admin_referer( 'fckmw_' . $command );
		$return = sanitize_key( wp_unslash( $_POST['return'] ?? '' ) );
		$result = $this->{self::COMMANDS[ $command ]}();

		if ( is_wp_error( $result ) ) {
			Ui::set_notice( 'error', $result->get_error_message() );
		} elseif ( is_string( $result ) ) {
			Ui::set_notice( 'success', $result );
		}
		wp_safe_redirect( Ui::url( $return ) );
		exit;
	}

	/** @return mixed */
	private static function post( string $key, $default = '' ) {
		return isset( $_POST[ $key ] ) ? wp_unslash( $_POST[ $key ] ) : $default; // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- nonce verified in handle(); callers sanitize.
	}

	// --- Commands -----------------------------------------------------------------

	private function save_settings() {
		$before = Settings::all();
		$bools  = array_map( 'sanitize_key', (array) self::post( 'fckmw_bools', array() ) );
		$after  = Settings::update( (array) self::post( 'fckmw', array() ), $bools ); // Sanitized against the schema.
		if ( $before['schedule'] !== $after['schedule'] ) {
			Plugin::reschedule();
		}
		ActivityLog::log( 'settings.saved', __( 'Settings changed.', 'fckmaleware' ), array( 'changed' => array_keys( array_diff_assoc( array_map( 'strval', $after ), array_map( 'strval', $before ) ) ) ), 'notice' );
		return __( 'Settings saved.', 'fckmaleware' );
	}

	private function finding() {
		$id          = absint( self::post( 'finding' ) );
		$op          = sanitize_key( (string) self::post( 'op' ) );
		$remediation = $this->plugin->remediation();
		switch ( $op ) {
			case 'quarantine':
				$r = $remediation->quarantine( $id );
				return is_wp_error( $r ) ? $r : __( 'File moved to quarantine (verified copy kept).', 'fckmaleware' );
			case 'repair':
				$r = $remediation->repair( $id );
				return is_wp_error( $r ) ? $r : __( 'File replaced with the verified official copy.', 'fckmaleware' );
			case 'accept':
				$r = $remediation->accept( $id );
				return is_wp_error( $r ) ? $r : __( 'Finding accepted.', 'fckmaleware' );
			case 'resolve':
				$this->plugin->findings()->set_status( $id, 'resolved' );
				return __( 'Marked as resolved. It reappears on the next scan if the problem is still there.', 'fckmaleware' );
			case 'reopen':
				$this->plugin->findings()->set_status( $id, 'open' );
				return __( 'Finding reopened.', 'fckmaleware' );
			case 'remove_cron':
				$r = $remediation->remove_cron_event( $id );
				return is_wp_error( $r ) ? $r : __( 'Scheduled event removed.', 'fckmaleware' );
			case 'ai_review':
				$r = $this->plugin->ai()->review( $id );
				return is_wp_error( $r ) ? $r : sprintf( /* translators: 1: verdict, 2: confidence */ __( 'AI review: %1$s (%2$d%%). Advisory only; nothing was changed.', 'fckmaleware' ), $r['verdict'], $r['confidence'] );
		}
		return new \WP_Error( 'fckmw_op', __( 'Unknown action.', 'fckmaleware' ) );
	}

	private function bulk() {
		$op  = sanitize_key( (string) self::post( 'op' ) );
		$ids = array_slice( array_map( 'absint', (array) self::post( 'ids', array() ) ), 0, 200 );
		if ( ! in_array( $op, array( 'quarantine', 'accept', 'resolve' ), true ) || ! $ids ) {
			return new \WP_Error( 'fckmw_op', __( 'Choose findings and an action.', 'fckmaleware' ) );
		}
		$point = 'quarantine' === $op ? $this->plugin->remediation()->create_point( __( 'Bulk quarantine', 'fckmaleware' ) ) : '';
		$done  = 0;
		$fail  = array();
		foreach ( $ids as $id ) {
			if ( 'quarantine' === $op ) {
				$r = $this->plugin->remediation()->quarantine( $id, $point );
			} elseif ( 'accept' === $op ) {
				$r = $this->plugin->remediation()->accept( $id );
			} else {
				$r = $this->plugin->findings()->set_status( $id, 'resolved' );
			}
			if ( is_wp_error( $r ) ) {
				$fail[] = '#' . $id . ': ' . $r->get_error_message();
			} else {
				$done++;
			}
		}
		/* translators: 1: done, 2: failed */
		$message = sprintf( __( '%1$d findings updated, %2$d failed.', 'fckmaleware' ), $done, count( $fail ) );
		return $fail ? new \WP_Error( 'fckmw_bulk', $message . ' ' . implode( ' ', array_slice( $fail, 0, 3 ) ) ) : $message;
	}

	private function quarantine_item() {
		$key = (string) preg_replace( '/[^a-f0-9]/', '', (string) self::post( 'key' ) );
		switch ( sanitize_key( (string) self::post( 'op' ) ) ) {
			case 'restore':
				$r = $this->plugin->remediation()->restore( $key );
				return is_wp_error( $r ) ? $r : __( 'File restored to its original location.', 'fckmaleware' );
			case 'delete':
				$r = $this->plugin->remediation()->delete( $key );
				return is_wp_error( $r ) ? $r : __( 'Quarantined copy permanently deleted.', 'fckmaleware' );
		}
		return new \WP_Error( 'fckmw_op', __( 'Unknown action.', 'fckmaleware' ) );
	}

	private function rollback() {
		$point  = (string) preg_replace( '/[^a-f0-9]/', '', (string) self::post( 'point' ) );
		$result = $this->plugin->remediation()->rollback( $point );
		/* translators: %d: count */
		$message = sprintf( __( 'Rolled back: %d files restored.', 'fckmaleware' ), $result['restored'] );
		return $result['failed'] ? new \WP_Error( 'fckmw_rollback', $message . ' ' . implode( ' ', $result['failed'] ) ) : $message;
	}

	private function hardening() {
		$rule = sanitize_key( (string) self::post( 'rule' ) );
		$on   = '1' === self::post( 'on' );
		$r    = $this->plugin->hardening()->set( $rule, $on );
		return is_wp_error( $r ) ? $r : ( $on ? __( 'Rule enabled.', 'fckmaleware' ) : __( 'Rule disabled.', 'fckmaleware' ) );
	}

	private function hardening_check() {
		$this->plugin->hardening()->status( true );
		return __( 'Hardening checks refreshed.', 'fckmaleware' );
	}

	private function imunify() {
		if ( 'scan' === sanitize_key( (string) self::post( 'op' ) ) ) {
			$r = $this->plugin->imunify()->start_scan( \Fckmaleware\Paths::root() );
			return is_wp_error( $r ) ? $r : __( 'Imunify360 scan started. Sync results once it finishes.', 'fckmaleware' );
		}
		$r = $this->plugin->sync_imunify();
		/* translators: %d: count */
		return is_wp_error( $r ) ? $r : sprintf( __( 'Synced %d Imunify360 detections.', 'fckmaleware' ), $r );
	}

	private function signatures() {
		$updater = $this->plugin->signature_updater();
		if ( 'rollback' === sanitize_key( (string) self::post( 'op' ) ) ) {
			$r = $updater->rollback();
			/* translators: %s: version */
			return is_wp_error( $r ) ? $r : sprintf( __( 'Active signature database: %s.', 'fckmaleware' ), $r );
		}
		$r = $updater->check();
		if ( 'error' === $r['status'] ) {
			return new \WP_Error( 'fckmw_update', $r['message'] );
		}
		/* translators: %s: version */
		return 'updated' === $r['status'] ? sprintf( __( 'Updated to %s.', 'fckmaleware' ), $r['version'] ) : sprintf( __( 'Signatures are current (%s).', 'fckmaleware' ), $r['version'] );
	}

	private function notify_test() {
		$this->plugin->notifier()->send_test();
		$last = ActivityLog::query( array( 'type' => 'notify.' ), 1, 1 )['rows'][0] ?? null;
		return $last && 'notify.failed' === $last['type'] ? new \WP_Error( 'fckmw_notify', $last['message'] ) : __( 'Test notification sent on the enabled channels. Check the delivery log.', 'fckmaleware' );
	}

	private function webhook_secret() {
		Store::delete( Notifier::SECRET_OPTION );
		Notifier::webhook_secret();
		return __( 'New webhook signing secret created. Update your receiver.', 'fckmaleware' );
	}

	private function persistence() {
		$r = $this->plugin->persistence()->run( 'manual' );
		/* translators: 1: findings, 2: new */
		return sprintf( __( 'Persistence check: %1$d findings (%2$d new).', 'fckmaleware' ), $r['found'], $r['new'] );
	}

	private function cache_clear() {
		$this->plugin->file_cache()->clear();
		return __( 'File cache cleared; the next scan reads every file.', 'fckmaleware' );
	}

	private function export_findings(): void {
		$status = sanitize_key( (string) self::post( 'status', 'open' ) );
		$rows   = $this->plugin->findings()->query( array( 'status' => $status ), 1, 10000 )['rows'];
		self::download_csv( 'fckmaleware-findings-' . gmdate( 'Ymd' ) . '.csv', array( 'id', 'detected_at', 'last_seen_at', 'status', 'severity', 'verdict', 'confidence', 'source', 'signature_id', 'signature_name', 'family', 'object_type', 'file', 'line', 'remediation', 'occurrences' ), $rows );
	}

	private function export_activity(): void {
		$rows = ActivityLog::query( array(), 1, 5000 )['rows'];
		foreach ( $rows as &$row ) {
			$row['created_at'] = gmdate( 'c', (int) $row['created_at'] );
			$row['context']    = wp_json_encode( $row['context'] );
		}
		self::download_csv( 'fckmaleware-activity-' . gmdate( 'Ymd' ) . '.csv', array( 'id', 'created_at', 'severity', 'type', 'user_id', 'message', 'context' ), $rows );
	}

	private function feedback_export(): void {
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="fckmaleware-feedback-' . gmdate( 'Ymd' ) . '.json"' );
		echo wp_json_encode( Feedback::stats_bundle( $this->plugin ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		exit;
	}

	private static function download_csv( string $filename, array $columns, array $rows ): void {
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fputcsv( $out, $columns );
		foreach ( $rows as $row ) {
			$line = array();
			foreach ( $columns as $column ) {
				// Neutralize spreadsheet formula injection from file names or excerpts.
				$value  = (string) ( $row[ $column ] ?? '' );
				$line[] = preg_match( '/^[=+\-@\t\r]/', $value ) ? "'" . $value : $value;
			}
			fputcsv( $out, $line );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	// --- AJAX scan driver -----------------------------------------------------------

	private function ajax_guard(): void {
		check_ajax_referer( 'fckmw_scan' );
		if ( ! Ui::can() ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'fckmaleware' ) ), 403 );
		}
	}

	public function ajax_scan_start(): void {
		$this->ajax_guard();
		$mode  = sanitize_key( wp_unslash( $_POST['mode'] ?? 'standard' ) );
		$state = $this->plugin->scanner()->start(
			$mode,
			'manual',
			array(
				'scope' => sanitize_text_field( wp_unslash( $_POST['scope'] ?? '' ) ),
				'days'  => absint( $_POST['days'] ?? 7 ),
			)
		);
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( self::public_state( $state ) );
	}

	public function ajax_scan_step(): void {
		$this->ajax_guard();
		wp_send_json_success( self::public_state( $this->plugin->scanner()->step( 8.0 ) ) );
	}

	public function ajax_scan_cancel(): void {
		$this->ajax_guard();
		wp_send_json_success( self::public_state( $this->plugin->scanner()->cancel() ) );
	}

	public function ajax_db_start(): void {
		$this->ajax_guard();
		$state = $this->plugin->db_scanner()->start( 'manual' );
		if ( is_wp_error( $state ) ) {
			wp_send_json_error( array( 'message' => $state->get_error_message() ) );
		}
		wp_send_json_success( self::public_db_state( $state ) );
	}

	public function ajax_db_step(): void {
		$this->ajax_guard();
		wp_send_json_success( self::public_db_state( $this->plugin->db_scanner()->step( 8.0 ) ) );
	}

	/** Only the fields the browser needs (no internal lists or recording state). */
	private static function public_state( array $state ): array {
		return array_intersect_key( $state, array_flip( array( 'status', 'phase', 'mode', 'total', 'position', 'skipped', 'found', 'new', 'unit', 'units_total', 'errors' ) ) ) + array( 'units_total' => count( (array) ( $state['units'] ?? array() ) ) );
	}

	private static function public_db_state( array $state ): array {
		return array_intersect_key( $state, array_flip( array( 'status', 'rows', 'found', 'new', 'table' ) ) ) + array( 'tables_total' => count( (array) ( $state['tables'] ?? array() ) ) );
	}
}
