<?php
/**
 * Activity Log: every security-relevant event the plugin recorded.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;

final class Activity extends Page {

	private const PER_PAGE = 50;

	public function render( string $title ): void {
		$type     = sanitize_text_field( (string) self::query( 'type' ) );
		$type     = (string) preg_replace( '/[^a-z_.]/', '', $type );
		$severity = sanitize_key( (string) self::query( 'severity' ) );
		$paged    = max( 1, absint( self::query( 'paged', 1 ) ) );
		$result   = ActivityLog::query( array( 'type' => $type, 'severity' => $severity ), $paged, self::PER_PAGE );

		Ui::header( $title, __( 'Kept for 180 days (at most 20,000 entries). The visitor IP address is stored with blocked uploads, plugin deactivations, administrator and option changes and file-editor use, so you can trace who made them.', 'fckmaleware' ) );

		$types = array(
			''             => __( 'All events', 'fckmaleware' ),
			'scan.'        => __( 'File scans', 'fckmaleware' ),
			'dbscan.'      => __( 'Database scans', 'fckmaleware' ),
			'threat.'      => __( 'Threats', 'fckmaleware' ),
			'quarantine.'  => __( 'Quarantine', 'fckmaleware' ),
			'repair.'      => __( 'Repairs', 'fckmaleware' ),
			'upload.'      => __( 'Uploads', 'fckmaleware' ),
			'user.'        => __( 'Users', 'fckmaleware' ),
			'option.'      => __( 'Options', 'fckmaleware' ),
			'plugin.'      => __( 'Plugins', 'fckmaleware' ),
			'theme.'       => __( 'Themes', 'fckmaleware' ),
			'file.'        => __( 'File editor', 'fckmaleware' ),
			'hardening.'   => __( 'Hardening', 'fckmaleware' ),
			'signatures.'  => __( 'Signature updates', 'fckmaleware' ),
			'notify.'      => __( 'Notifications', 'fckmaleware' ),
			'ai.'          => __( 'AI reviews', 'fckmaleware' ),
			'imunify.'     => 'Imunify360',
			'settings.'    => __( 'Settings', 'fckmaleware' ),
		);
		echo '<form method="get" class="fckmw-filters"><input type="hidden" name="page" value="' . esc_attr( Ui::SLUG . '-activity' ) . '">';
		echo '<label class="screen-reader-text" for="fckmw-type">' . esc_html__( 'Event type', 'fckmaleware' ) . '</label><select id="fckmw-type" name="type">';
		foreach ( $types as $value => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $type, $value, false ), esc_html( $label ) );
		}
		if ( '' !== $type && ! isset( $types[ $type ] ) ) {
			printf( '<option value="%1$s" selected>%1$s</option>', esc_attr( $type ) );
		}
		echo '</select> <label class="screen-reader-text" for="fckmw-sev">' . esc_html__( 'Severity', 'fckmaleware' ) . '</label><select id="fckmw-sev" name="severity"><option value="">' . esc_html__( 'All severities', 'fckmaleware' ) . '</option>';
		foreach ( ActivityLog::SEVERITIES as $value ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $value ), selected( $severity, $value, false ), esc_html( ucfirst( $value ) ) );
		}
		echo '</select> <button class="button">' . esc_html__( 'Filter', 'fckmaleware' ) . '</button></form>';

		if ( ! $result['rows'] ) {
			Ui::card_start();
			echo '<p>' . esc_html__( 'No events match.', 'fckmaleware' ) . '</p>';
			Ui::card_end();
		} else {
			$tones = array( 'critical' => 'critical', 'warning' => 'warn', 'notice' => 'neutral', 'info' => 'neutral' );
			echo '<table class="widefat striped fckmw-table"><thead><tr><th>' . esc_html__( 'Time', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Severity', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Event', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Details', 'fckmaleware' ) . '</th><th>' . esc_html__( 'User', 'fckmaleware' ) . '</th></tr></thead><tbody>';
			foreach ( $result['rows'] as $row ) {
				$user = (int) $row['user_id'] ? get_userdata( (int) $row['user_id'] ) : null;
				echo '<tr><td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $row['created_at'] ) ) . '</td>';
				echo '<td>' . Ui::badge( (string) $row['severity'], $tones[ $row['severity'] ] ?? 'neutral' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<td><code>' . esc_html( (string) $row['type'] ) . '</code></td><td>' . esc_html( (string) $row['message'] );
				if ( $row['context'] ) {
					echo '<details><summary>' . esc_html__( 'Context', 'fckmaleware' ) . '</summary><pre class="fckmw-code">' . esc_html( (string) wp_json_encode( $row['context'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ) . '</pre></details>';
				}
				echo '</td><td>' . esc_html( $user ? $user->user_login : ( (int) $row['user_id'] ? '#' . (int) $row['user_id'] : '—' ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
			Ui::pagination( (int) $result['total'], self::PER_PAGE, $paged );
		}

		echo '<p>';
		Ui::form( 'export_activity', array(), 'fckmw-inline' );
		echo '<button class="button">' . esc_html__( 'Export activity (CSV)', 'fckmaleware' ) . '</button></form></p>';
		Ui::footer();
	}
}
