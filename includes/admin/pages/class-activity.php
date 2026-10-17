<?php
/**
 * Activity Log: every security-relevant event the plugin recorded. The log
 * is append-only from the admin (no edit or delete), pruned by the retention
 * setting, and never contains passwords or API keys.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Settings;

final class Activity extends Page {

	private const PER_PAGE = 50;

	/** Event categories for the filter (type prefix => label). */
	public static function categories(): array {
		return array(
			''             => __( 'All events', 'fckmaleware' ),
			'failed'       => __( 'Failed operations', 'fckmaleware' ),
			'scan.'        => __( 'File scans', 'fckmaleware' ),
			'dbscan.'      => __( 'Database scans', 'fckmaleware' ),
			'threat.'      => __( 'Threat detections', 'fckmaleware' ),
			'quarantine.'  => __( 'Quarantine, restore and deletion', 'fckmaleware' ),
			'bulk.'        => __( 'Bulk actions', 'fckmaleware' ),
			'repair.'      => __( 'Repairs', 'fckmaleware' ),
			'upload.'      => __( 'Uploads and upload blocks', 'fckmaleware' ),
			'user.'        => __( 'Users', 'fckmaleware' ),
			'option.'      => __( 'Options', 'fckmaleware' ),
			'plugin.'      => __( 'Plugins', 'fckmaleware' ),
			'theme.'       => __( 'Themes', 'fckmaleware' ),
			'file.'        => __( 'File editor', 'fckmaleware' ),
			'hardening.'   => __( 'Hardening changes', 'fckmaleware' ),
			'signatures.'  => __( 'Signature updates', 'fckmaleware' ),
			'integration.' => __( 'Integration tests', 'fckmaleware' ),
			'imunify.'     => __( 'Server scanner sync', 'fckmaleware' ),
			'notify.'      => __( 'Notifications', 'fckmaleware' ),
			'ai.'          => __( 'AI reviews', 'fckmaleware' ),
			'settings.'    => __( 'Settings changes', 'fckmaleware' ),
		);
	}

	public function render( string $title ): void {
		$type     = (string) preg_replace( '/[^a-z_.]/', '', sanitize_text_field( (string) self::query( 'type' ) ) );
		$severity = sanitize_key( (string) self::query( 'severity' ) );
		$days     = absint( self::query( 'days', 0 ) );
		$search   = sanitize_text_field( (string) self::query( 's' ) );
		$user     = (string) self::query( 'user' );
		$user     = '' === $user ? '' : (string) absint( $user );
		$paged    = max( 1, absint( self::query( 'paged', 1 ) ) );
		$filters  = array( 'severity' => $severity, 'search' => $search, 'user' => $user );
		if ( 'failed' === $type ) {
			$filters['failed'] = true;
		} else {
			$filters['type'] = $type;
		}
		if ( $days ) {
			$filters['since'] = time() - $days * DAY_IN_SECONDS;
		}
		$result = ActivityLog::query( $filters, $paged, self::PER_PAGE );

		ob_start();
		Ui::form( 'export_activity', array( 'type' => $type, 'days' => $days ), 'fckmw-inline' );
		echo '<button class="button"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Export (CSV)', 'fckmaleware' ) . '</button></form>';
		$actions = (string) ob_get_clean();

		/* translators: %d: days */
		Ui::header( $title, sprintf( __( 'Kept for %d days (at most 20,000 entries), with the acting user. The visitor IP address is stored with blocked uploads, plugin deactivations, administrator and option changes and file-editor use. Passwords and API keys are never logged.', 'fckmaleware' ), (int) Settings::get( 'log_retention_days' ) ), $actions );

		$categories = self::categories();
		echo '<form method="get" class="fckmw-filters" role="search">';
		Ui::location_fields( 'activity' );
		echo '<label class="screen-reader-text" for="fckmw-type">' . esc_html__( 'Event type', 'fckmaleware' ) . '</label><select id="fckmw-type" name="type">';
		foreach ( $categories as $value => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $type, $value, false ), esc_html( $label ) );
		}
		if ( '' !== $type && ! isset( $categories[ $type ] ) ) {
			printf( '<option value="%1$s" selected>%1$s</option>', esc_attr( $type ) );
		}
		echo '</select> <label class="screen-reader-text" for="fckmw-sev">' . esc_html__( 'Severity', 'fckmaleware' ) . '</label><select id="fckmw-sev" name="severity"><option value="">' . esc_html__( 'All severities', 'fckmaleware' ) . '</option>';
		foreach ( ActivityLog::SEVERITIES as $value ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $severity, $value, false ), esc_html( ucfirst( $value ) ) );
		}
		echo '</select> <label class="screen-reader-text" for="fckmw-days">' . esc_html__( 'Period', 'fckmaleware' ) . '</label><select id="fckmw-days" name="days">';
		foreach ( array( 0 => __( 'Any time', 'fckmaleware' ), 1 => __( 'Last 24 hours', 'fckmaleware' ), 7 => __( 'Last 7 days', 'fckmaleware' ), 30 => __( 'Last 30 days', 'fckmaleware' ), 90 => __( 'Last 90 days', 'fckmaleware' ) ) as $value => $label ) {
			printf( '<option value="%d"%s>%s</option>', (int) $value, selected( $days, $value, false ), esc_html( $label ) );
		}
		echo '</select> <label class="screen-reader-text" for="fckmw-user">' . esc_html__( 'User', 'fckmaleware' ) . '</label><select id="fckmw-user" name="user"><option value="">' . esc_html__( 'Any user', 'fckmaleware' ) . '</option><option value="0"' . selected( $user, '0', false ) . '>' . esc_html__( 'System (cron, visitors)', 'fckmaleware' ) . '</option>';
		$admins = get_users( array( 'role__in' => array( 'administrator' ), 'number' => 50, 'fields' => array( 'ID', 'user_login' ), 'blog_id' => is_multisite() ? get_main_site_id() : get_current_blog_id() ) );
		foreach ( $admins as $admin ) {
			printf( '<option value="%1$d"%2$s>%3$s</option>', (int) $admin->ID, selected( $user, (string) $admin->ID, false ), esc_html( $admin->user_login ) );
		}
		echo '</select> <label class="screen-reader-text" for="fckmw-asearch">' . esc_html__( 'Search messages', 'fckmaleware' ) . '</label><input type="search" id="fckmw-asearch" name="s" value="' . esc_attr( $search ) . '" placeholder="' . esc_attr__( 'Search messages', 'fckmaleware' ) . '"> <button class="button">' . esc_html__( 'Filter', 'fckmaleware' ) . '</button></form>';

		Ui::card_start();
		if ( ! $result['rows'] ) {
			Ui::empty_state( __( 'No events match', 'fckmaleware' ), '', '', 'list-view' );
		} else {
			$tones = array( 'critical' => 'critical', 'warning' => 'warn', 'notice' => 'info', 'info' => 'neutral' );
			echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><th scope="col">' . esc_html__( 'Time', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Severity', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Event', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Details', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'User', 'fckmaleware' ) . '</th></tr></thead><tbody>';
			foreach ( $result['rows'] as $row ) {
				$actor = (int) $row['user_id'] ? get_userdata( (int) $row['user_id'] ) : null;
				echo '<tr><td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $row['created_at'] ) ) . '</td>';
				echo '<td>' . Ui::badge( ucfirst( (string) $row['severity'] ), $tones[ $row['severity'] ] ?? 'neutral' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<td><code>' . esc_html( (string) $row['type'] ) . '</code></td><td>' . esc_html( (string) $row['message'] );
				if ( $row['context'] ) {
					echo '<details><summary>' . esc_html__( 'Context', 'fckmaleware' ) . '</summary><pre class="fckmw-code">' . esc_html( (string) wp_json_encode( $row['context'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ) . '</pre></details>';
				}
				echo '</td><td>' . esc_html( $actor ? $actor->user_login : ( (int) $row['user_id'] ? '#' . (int) $row['user_id'] : __( 'system', 'fckmaleware' ) ) ) . '</td></tr>';
			}
			echo '</tbody></table></div>';
			Ui::pagination( (int) $result['total'], self::PER_PAGE, $paged );
		}
		Ui::card_end();
		Ui::footer();
	}
}
