<?php
/**
 * Real-Time Protection: the event-driven checks, what they caught recently and
 * the queue of pending event-triggered scans.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Monitor;
use Fckmaleware\Settings;
use Fckmaleware\Store;

final class Realtime extends Page {

	public function render( string $title ): void {
		$settings = Settings::all();
		$since    = time() - 30 * DAY_IN_SECONDS;
		$summary  = ActivityLog::summary( $since );

		Ui::header( $title, __( 'WordPress offers no file-system hooks, so protection runs on WordPress events: uploads, installs and updates, user and option changes. Files changed outside WordPress (FTP, other sites on the server) are caught by scheduled scans.', 'fckmaleware' ) );

		$count = static function ( array $types ) use ( $summary ): int {
			$total = 0;
			foreach ( $types as $type ) {
				$total += $summary[ $type ] ?? 0;
			}
			return $total;
		};
		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Uploads blocked', 'fckmaleware' ), (string) $count( array( 'upload.blocked' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'upload.' ) ) );
		Ui::stat( __( 'Install/update checks', 'fckmaleware' ), (string) $count( array( 'event.scanned' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'event.' ) ) );
		Ui::stat( __( 'Administrator changes', 'fckmaleware' ), (string) $count( array( 'user.admin_created', 'user.promoted', 'user.super_admin' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'user.' ) ) );
		Ui::stat( __( 'Sensitive option changes', 'fckmaleware' ), (string) $count( array( 'option.changed' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'option.' ) ) );
		Ui::stat( __( 'Re-infections', 'fckmaleware' ), (string) $count( array( 'threat.reinfection' ) ), $count( array( 'threat.reinfection' ) ) ? 'bad' : 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'threat.' ) ) );
		echo '</div>';

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Event-driven checks', 'fckmaleware' ) );
		Ui::settings_form( 'realtime' );
		Ui::toggle( 'realtime_uploads', $settings['realtime_uploads'], __( 'Screen uploads', 'fckmaleware' ), __( 'Every upload through WordPress is checked before it is saved. Uploads matching a malicious signature with 80% or more confidence are refused; others are recorded as findings.', 'fckmaleware' ) );
		Ui::toggle( 'realtime_installs', $settings['realtime_installs'], __( 'Check installs and updates', 'fckmaleware' ), __( 'Plugins and themes are queued for a check right after they are installed or updated, and on activation.', 'fckmaleware' ) );
		Ui::toggle( 'monitor_users', $settings['monitor_users'], __( 'Watch administrator accounts', 'fckmaleware' ), __( 'Alerts when an administrator is created, a user is promoted or super-admin is granted.', 'fckmaleware' ) );
		Ui::toggle( 'monitor_options', $settings['monitor_options'], __( 'Watch security-relevant options', 'fckmaleware' ), __( 'Site and home URL, admin email, open registration, default role, role capabilities, active plugins and theme.', 'fckmaleware' ) );
		Ui::toggle( 'auto_quarantine', $settings['auto_quarantine'], __( 'Automatic quarantine (off by default)', 'fckmaleware' ), __( 'Only malicious signature matches with 90% or more confidence that are exact known-malware hashes, images, or files in uploads, plus heuristic detections of 95% or more in uploads. Never core files. Each action is logged and can be restored.', 'fckmaleware' ) );
		submit_button( __( 'Save', 'fckmaleware' ) );
		echo '</form>';
		Ui::card_end();

		Ui::card_start( __( 'Pending event-triggered checks', 'fckmaleware' ) );
		$queue = (array) Store::get( Monitor::QUEUE_OPTION, array() );
		if ( ! $queue ) {
			echo '<p>' . esc_html__( 'Nothing is waiting. Queued checks run within a minute through WP-Cron.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<ul class="fckmw-list">';
			foreach ( $queue as $item ) {
				/* translators: 1: directory, 2: reason */
				echo '<li><code>' . esc_html( (string) ( $item['dir'] ?? '' ) ) . '</code> — ' . esc_html( (string) ( $item['reason'] ?? '' ) ) . '</li>';
			}
			echo '</ul>';
			$next = wp_next_scheduled( Monitor::CRON_QUEUE );
			/* translators: %s: time */
			echo '<p class="description">' . esc_html( $next ? sprintf( __( 'Next run %s.', 'fckmaleware' ), Ui::ago( (int) $next ) ) : __( 'Not scheduled: WP-Cron may be disabled on this site.', 'fckmaleware' ) ) . '</p>';
		}
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			echo '<p>' . Ui::badge( __( 'Note', 'fckmaleware' ), 'warn' ) . ' ' . esc_html__( 'DISABLE_WP_CRON is set: make sure a system cron calls wp-cron.php, otherwise queued checks and scheduled scans do not run.', 'fckmaleware' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		Ui::card_end();
		echo '</div>';

		Ui::card_start( __( 'Recent real-time events', 'fckmaleware' ) );
		$rows = array();
		foreach ( array( 'upload.', 'event.', 'user.', 'option.', 'threat.', 'quarantine.auto' ) as $type ) {
			$rows = array_merge( $rows, ActivityLog::query( array( 'type' => $type, 'since' => $since ), 1, 10 )['rows'] );
		}
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				return (int) $b['id'] <=> (int) $a['id'];
			}
		);
		if ( ! $rows ) {
			echo '<p>' . esc_html__( 'No real-time events in the last 30 days.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<table class="widefat striped fckmw-table"><tbody>';
			foreach ( array_slice( $rows, 0, 20 ) as $row ) {
				echo '<tr><td class="fckmw-nowrap">' . esc_html( Ui::ago( (int) $row['created_at'] ) ) . '</td><td><code>' . esc_html( (string) $row['type'] ) . '</code></td><td>' . esc_html( (string) $row['message'] ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Ui::card_end();
		Ui::footer();
	}
}
