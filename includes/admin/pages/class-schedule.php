<?php
/**
 * Scan Schedule: when automatic work runs, what is queued in WP-Cron and the
 * history of finished scans.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Monitor;
use Fckmaleware\Notifier;
use Fckmaleware\Plugin;
use Fckmaleware\Settings;
use Fckmaleware\SignatureUpdater;

final class Schedule extends Page {

	public function render( string $title ): void {
		$settings = Settings::all();

		Ui::header( $title, __( 'Automatic work runs through WP-Cron, which needs site traffic or a system cron calling wp-cron.php. Scans run in small steps so they never hit PHP time limits.', 'fckmaleware' ) );

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Automatic scans', 'fckmaleware' ) );
		Ui::settings_form( 'schedule' );
		Ui::select(
			'schedule',
			$settings['schedule'],
			array(
				'off'        => __( 'Off', 'fckmaleware' ),
				'hourly'     => __( 'Hourly', 'fckmaleware' ),
				'twicedaily' => __( 'Twice daily', 'fckmaleware' ),
				'daily'      => __( 'Daily', 'fckmaleware' ),
				'weekly'     => __( 'Weekly', 'fckmaleware' ),
			),
			__( 'File scan frequency', 'fckmaleware' )
		);
		Ui::select( 'scheduled_mode', $settings['scheduled_mode'], array( 'quick' => __( 'Quick', 'fckmaleware' ), 'standard' => __( 'Standard', 'fckmaleware' ), 'deep' => __( 'Deep', 'fckmaleware' ) ), __( 'Scheduled scan mode', 'fckmaleware' ), __( 'Standard is recommended: thanks to the cache it only reads changed files.', 'fckmaleware' ) );
		Ui::toggle( 'scheduled_db_scan', $settings['scheduled_db_scan'], __( 'Also scan the database and run the persistence check after each scheduled file scan', 'fckmaleware' ) );
		Ui::input( 'throttle_ms', (string) $settings['throttle_ms'], __( 'Pause between files (ms)', 'fckmaleware' ), 'number', __( 'Use 5-50 on busy shared hosting to reduce load; 0 for the fastest scans.', 'fckmaleware' ), array( 'min' => 0, 'max' => 500, 'class' => 'small-text' ) );
		Ui::input( 'max_file_size_mb', (string) $settings['max_file_size_mb'], __( 'Skip files larger than (MB)', 'fckmaleware' ), 'number', __( 'Larger files are listed as skipped in the scan result, never silently ignored.', 'fckmaleware' ), array( 'min' => 1, 'max' => 64, 'class' => 'small-text' ) );
		submit_button( __( 'Save schedule', 'fckmaleware' ) );
		echo '</form>';
		Ui::card_end();

		Ui::card_start( __( 'Upcoming', 'fckmaleware' ) );
		$hooks = array(
			Plugin::CRON_SCAN          => __( 'Scheduled file scan', 'fckmaleware' ),
			Plugin::CRON_CONTINUE      => __( 'Continue an interrupted file scan', 'fckmaleware' ),
			Plugin::CRON_DB            => __( 'Continue a database scan', 'fckmaleware' ),
			SignatureUpdater::CRON     => __( 'Signature update check', 'fckmaleware' ),
			Plugin::CRON_DAILY         => __( 'Daily maintenance (persistence check, quarantine expiry, log pruning)', 'fckmaleware' ),
			Monitor::CRON_QUEUE        => __( 'Event-triggered checks', 'fckmaleware' ),
			Notifier::CRON             => __( 'Notification delivery', 'fckmaleware' ),
		);
		echo '<table class="widefat striped fckmw-table"><tbody>';
		foreach ( $hooks as $hook => $label ) {
			$next = wp_next_scheduled( $hook );
			echo '<tr><td>' . esc_html( $label ) . '</td><td class="fckmw-nowrap">' . esc_html( $next ? Ui::ago( (int) $next ) : __( 'not scheduled', 'fckmaleware' ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			echo '<p>' . Ui::badge( __( 'Note', 'fckmaleware' ), 'warn' ) . ' ' . esc_html__( 'DISABLE_WP_CRON is set. Check that a system cron runs wp-cron.php (or "wp cron event run --due-now") every few minutes.', 'fckmaleware' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '<p class="description">' . esc_html__( 'Overdue items run on the next page load or system cron call. From the command line: wp fckmaleware scan --mode=standard', 'fckmaleware' ) . '</p>';
		Ui::card_end();
		echo '</div>';

		Ui::card_start( __( 'Scan history', 'fckmaleware' ) );
		$rows = ActivityLog::query( array( 'type' => 'scan.' ), 1, 25 )['rows'];
		$rows = array_merge( $rows, ActivityLog::query( array( 'type' => 'dbscan.' ), 1, 10 )['rows'] );
		usort(
			$rows,
			static function ( array $a, array $b ): int {
				return (int) $b['id'] <=> (int) $a['id'];
			}
		);
		if ( ! $rows ) {
			echo '<p>' . esc_html__( 'No scans recorded yet.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<table class="widefat striped fckmw-table"><tbody>';
			foreach ( array_slice( $rows, 0, 25 ) as $row ) {
				echo '<tr><td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $row['created_at'] ) ) . '</td><td><code>' . esc_html( (string) $row['type'] ) . '</code></td><td>' . esc_html( (string) $row['message'] ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Ui::card_end();
		Ui::footer();
	}
}
