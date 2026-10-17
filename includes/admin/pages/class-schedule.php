<?php
/**
 * Scan Schedule: every recurring task with its frequency, next and last run
 * and outcome, the scheduling settings, and how WP-Cron executes them.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Monitor;
use Fckmaleware\Notifier;
use Fckmaleware\Plugin;
use Fckmaleware\ScanHistory;
use Fckmaleware\Settings;
use Fckmaleware\SignatureUpdater;

final class Schedule extends Page {

	public function render( string $title ): void {
		$settings = Settings::all();
		$runs     = Plugin::task_runs();
		$freq     = array(
			'off'        => __( 'Off', 'fckmaleware' ),
			'hourly'     => __( 'Hourly', 'fckmaleware' ),
			'twicedaily' => __( 'Twice daily', 'fckmaleware' ),
			'daily'      => __( 'Daily', 'fckmaleware' ),
			'weekly'     => __( 'Weekly', 'fckmaleware' ),
		);
		$cron_off = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;

		Ui::header( $title, __( 'Automatic work runs through WP-Cron. It runs when the site receives visits, or on time when a system cron calls wp-cron.php. A task never starts while a scan of the same kind is running.', 'fckmaleware' ) );

		if ( $cron_off ) {
			Ui::callout( __( 'DISABLE_WP_CRON is set, so nothing below runs unless a system cron calls wp-cron.php (or "wp cron event run --due-now") every few minutes.', 'fckmaleware' ), 'warning', __( 'WP-Cron is disabled', 'fckmaleware' ) );
		}

		$tasks = array(
			'scan'        => array( __( 'File scan', 'fckmaleware' ), 'off' === $settings['schedule'] ? $freq['off'] : $freq[ $settings['schedule'] ] . ' · ' . ScanHistory::label( (string) $settings['scheduled_mode'] ), wp_next_scheduled( Plugin::CRON_SCAN ) ),
			'database'    => array( __( 'Database scan & persistence check', 'fckmaleware' ), $settings['scheduled_db_scan'] && 'off' !== $settings['schedule'] ? __( 'After each scheduled file scan', 'fckmaleware' ) : $freq['off'], 0 ),
			'integrity'   => array( __( 'WordPress core integrity', 'fckmaleware' ), $freq[ $settings['integrity_schedule'] ], wp_next_scheduled( Plugin::CRON_CORE ) ),
			'uploads'     => array( __( 'Uploads check (new files)', 'fckmaleware' ), $freq[ $settings['uploads_watch'] ], wp_next_scheduled( Plugin::CRON_UPLOADS ) ),
			'signatures'  => array( __( 'Signature updates', 'fckmaleware' ), $settings['signature_updates'] ? $freq['twicedaily'] : $freq['off'], $settings['signature_updates'] ? wp_next_scheduled( SignatureUpdater::CRON ) : 0 ),
			'maintenance' => array( __( 'Cleanup (logs, expired quarantine, persistence check)', 'fckmaleware' ), $freq['daily'], wp_next_scheduled( Plugin::CRON_DAILY ) ),
		);
		$statuses = array( 'ok' => array( __( 'OK', 'fckmaleware' ), 'good' ), 'skipped' => array( __( 'Skipped', 'fckmaleware' ), 'warn' ), 'error' => array( __( 'Failed', 'fckmaleware' ), 'bad' ) );

		Ui::card_start( __( 'Scheduled tasks', 'fckmaleware' ) );
		/* translators: %s: time zone */
		echo '<p class="fckmw-card-desc">' . esc_html( sprintf( __( 'Times are shown in the site time zone (%s).', 'fckmaleware' ), wp_timezone_string() ) ) . '</p>';
		echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><th scope="col">' . esc_html__( 'Task', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Frequency', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Next run', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Last run', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Status', 'fckmaleware' ) . '</th></tr></thead><tbody>';
		foreach ( $tasks as $key => $task ) {
			$run  = $runs[ $key ] ?? null;
			$next = (int) $task[2];
			echo '<tr><td><strong>' . esc_html( $task[0] ) . '</strong></td><td>' . esc_html( $task[1] ) . '</td>';
			echo '<td class="fckmw-nowrap">' . ( $next ? esc_html( Ui::datetime( $next ) ) . '<span class="fckmw-sub">' . esc_html( $next < time() ? __( 'overdue: runs on the next visit or cron call', 'fckmaleware' ) : Ui::ago( $next ) ) . '</span>' : '—' ) . '</td>';
			echo '<td class="fckmw-nowrap">' . ( $run ? Ui::when( (int) $run['time'] ) : esc_html__( 'never', 'fckmaleware' ) ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- when() escapes.
			echo '<td>' . ( $run ? Ui::status( $statuses[ $run['status'] ][0] ?? $run['status'], $statuses[ $run['status'] ][1] ?? 'neutral' ) . ( '' !== $run['message'] ? '<span class="fckmw-sub">' . esc_html( $run['message'] ) . '</span>' : '' ) : Ui::status( __( 'Not run yet', 'fckmaleware' ), 'off' ) ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '</tbody></table></div>';
		Ui::card_end();

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Schedule settings', 'fckmaleware' ) );
		Ui::settings_form( 'schedule' );
		Ui::select( 'schedule', $settings['schedule'], $freq, __( 'File scan frequency', 'fckmaleware' ) );
		Ui::select( 'scheduled_mode', $settings['scheduled_mode'], array( 'quick' => __( 'Quick', 'fckmaleware' ), 'standard' => __( 'Full', 'fckmaleware' ), 'deep' => __( 'Deep', 'fckmaleware' ) ), __( 'Scheduled scan type', 'fckmaleware' ), __( 'Full is recommended: thanks to the cache it only re-reads changed files.', 'fckmaleware' ) );
		$hours = array();
		for ( $h = 0; $h < 24; $h++ ) {
			$hours[ (string) $h ] = sprintf( '%02d:00', $h );
		}
		Ui::select( 'schedule_hour', (string) $settings['schedule_hour'], $hours, __( 'Daily and weekly work starts at', 'fckmaleware' ), __( 'Site time zone. The integrity check runs two hours later and cleanup one hour later, so they do not overlap.', 'fckmaleware' ) );
		Ui::select( 'integrity_schedule', $settings['integrity_schedule'], array_intersect_key( $freq, array_flip( array( 'off', 'daily', 'weekly' ) ) ), __( 'Core integrity check', 'fckmaleware' ) );
		Ui::select( 'uploads_watch', $settings['uploads_watch'], array_intersect_key( $freq, array_flip( array( 'off', 'hourly', 'twicedaily', 'daily' ) ) ), __( 'Uploads check', 'fckmaleware' ), __( 'Inspects files added to uploads since the previous run, including files written by FTP or other plugins.', 'fckmaleware' ) );
		Ui::toggle( 'scheduled_db_scan', $settings['scheduled_db_scan'], __( 'Scan the database and run the persistence check after each scheduled file scan', 'fckmaleware' ) );
		Ui::submit( __( 'Save schedule', 'fckmaleware' ) );
		echo '</form>';
		Ui::card_end();

		Ui::card_start( __( 'Queued work', 'fckmaleware' ) );
		$hooks = array(
			Plugin::CRON_CONTINUE  => __( 'Continue an interrupted file scan', 'fckmaleware' ),
			Plugin::CRON_DB        => __( 'Continue a database scan', 'fckmaleware' ),
			Monitor::CRON_QUEUE    => __( 'Event-triggered checks (installs, updates, uploads check)', 'fckmaleware' ),
			Notifier::CRON         => __( 'Notification delivery', 'fckmaleware' ),
		);
		echo '<ul class="fckmw-statuslist">';
		foreach ( $hooks as $hook => $label ) {
			$next = wp_next_scheduled( $hook );
			echo '<li><span class="fckmw-statuslist-name">' . esc_html( $label ) . '</span>' . ( $next ? Ui::status( Ui::ago( (int) $next ), 'good' ) : Ui::status( __( 'idle', 'fckmaleware' ), 'off' ) ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '</ul>';
		echo '<p class="description">' . esc_html__( 'Overdue items run on the next page load or system cron call. From the command line: wp fckmaleware scan --mode=standard', 'fckmaleware' ) . '</p>';
		Ui::card_end();
		echo '</div>';

		Ui::footer();
	}
}
