<?php
/**
 * Real-Time Protection: prevention, detection, quarantine, blocking and
 * notifications, each kept separate, plus what is (and is not) covered.
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
		$s       = Settings::all();
		$since   = time() - 30 * DAY_IN_SECONDS;
		$summary = ActivityLog::summary( $since );
		$count   = static function ( array $types ) use ( $summary ): int {
			$total = 0;
			foreach ( $types as $type ) {
				$total += $summary[ $type ] ?? 0;
			}
			return $total;
		};

		Ui::header( $title, __( 'Protection reacts to events WordPress itself reports: uploads, plugin and theme installs and updates, user and option changes. WordPress has no file-system hooks, so files written by FTP, SSH or other software are found by the periodic uploads check and scheduled scans, not instantly.', 'fckmaleware' ) );

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Uploads blocked', 'fckmaleware' ), (string) $count( array( 'upload.blocked', 'upload.refused' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'upload.' ) ) );
		Ui::stat( __( 'Install/update checks', 'fckmaleware' ), (string) $count( array( 'event.scanned' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'event.' ) ) );
		Ui::stat( __( 'Administrator changes', 'fckmaleware' ), (string) $count( array( 'user.admin_created', 'user.promoted', 'user.super_admin' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'user.' ) ) );
		Ui::stat( __( 'Sensitive option changes', 'fckmaleware' ), (string) $count( array( 'option.changed' ) ), 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'option.' ) ) );
		$reinfections = $count( array( 'threat.reinfection' ) );
		Ui::stat( __( 'Re-infections', 'fckmaleware' ), (string) $reinfections, $reinfections ? 'warn' : 'neutral', __( 'last 30 days', 'fckmaleware' ), Ui::url( 'activity', array( 'type' => 'threat.' ) ) );
		echo '</div>';

		Ui::settings_form( 'realtime' );
		echo '<div class="fckmw-grid fckmw-grid-2">';

		Ui::card_start( __( '1. Prevention', 'fckmaleware' ), '', __( 'Stops a malicious upload before WordPress stores it.', 'fckmaleware' ) );
		Ui::toggle( 'realtime_uploads', $s['realtime_uploads'], __( 'Screen uploads', 'fckmaleware' ), __( 'Media library, REST API and sideloaded files are inspected with the signature and heuristic engines before they are saved.', 'fckmaleware' ) );
		Ui::select(
			'upload_block_mode',
			$s['upload_block_mode'],
			array(
				'malicious' => __( 'Block malicious uploads (recommended)', 'fckmaleware' ),
				'strict'    => __( 'Strict: also block suspicious uploads', 'fckmaleware' ),
				'monitor'   => __( 'Monitor only: never block, record findings', 'fckmaleware' ),
			),
			__( 'Upload policy', 'fckmaleware' ),
			__( 'Strict mode can refuse unusual legitimate files; use it on sites where only a few trusted people upload.', 'fckmaleware' )
		);
		Ui::input( 'upload_block_confidence', (string) $s['upload_block_confidence'], __( 'Block at confidence (%)', 'fckmaleware' ), 'number', __( 'Malicious detections at or above this confidence are refused. 80 blocks only clear-cut matches.', 'fckmaleware' ), array( 'min' => 50, 'max' => 100, 'class' => 'small-text' ) );
		Ui::toggle( 'block_dangerous_extensions', $s['block_dangerous_extensions'], __( 'Refuse executable file types', 'fckmaleware' ), __( '.php, .phtml, .phar, .cgi, .pl, .py, .asp, .jsp, .sh and similar, including double extensions such as photo.php.jpg, plus .htaccess and .user.ini. Applies to administrators too.', 'fckmaleware' ) );
		Ui::toggle( 'block_mime_mismatch', $s['block_mime_mismatch'], __( 'Refuse images that contain PHP code', 'fckmaleware' ), __( 'A file named like an image whose content holds a PHP open tag is a classic web-shell disguise.', 'fckmaleware' ) );
		Ui::select( 'upload_fail_mode', $s['upload_fail_mode'], array( 'allow' => __( 'Accept the upload and log a warning', 'fckmaleware' ), 'reject' => __( 'Refuse the upload', 'fckmaleware' ) ), __( 'If inspection fails', 'fckmaleware' ), __( 'For example a corrupt signature database. Refusing is safer but can block legitimate uploads until the problem is fixed. Files above the scan size limit are always accepted and logged as not inspected.', 'fckmaleware' ) );
		Ui::card_end();

		Ui::card_start( __( '2. Detection', 'fckmaleware' ), '', __( 'Checks changes soon after WordPress makes them, in the background.', 'fckmaleware' ) );
		Ui::toggle( 'realtime_installs', $s['realtime_installs'], __( 'Check plugins and themes after install, update and activation', 'fckmaleware' ), __( 'Queued and checked by WP-Cron within about a minute; core updates queue wp-admin and wp-includes.', 'fckmaleware' ) );
		Ui::toggle( 'monitor_users', $s['monitor_users'], __( 'Watch administrator accounts', 'fckmaleware' ), __( 'New administrators, promotions and super-admin grants.', 'fckmaleware' ) );
		Ui::toggle( 'monitor_options', $s['monitor_options'], __( 'Watch security-relevant options', 'fckmaleware' ), __( 'Site and home URL, admin e-mail, open registration, default role, role capabilities, active plugins and theme.', 'fckmaleware' ) );
		$freq = array( 'off' => __( 'Off', 'fckmaleware' ), 'hourly' => __( 'Hourly', 'fckmaleware' ), 'twicedaily' => __( 'Twice daily', 'fckmaleware' ), 'daily' => __( 'Daily', 'fckmaleware' ) );
		Ui::select( 'uploads_watch', $s['uploads_watch'], $freq, __( 'Periodic uploads check', 'fckmaleware' ), __( 'Finds files added to uploads outside WordPress (FTP, file managers, other plugins). This is detection, not prevention: such a file exists until the next run.', 'fckmaleware' ) );
		Ui::card_end();

		Ui::card_start( __( '3. Quarantine', 'fckmaleware' ), '', __( 'What happens to a malicious file that was already written.', 'fckmaleware' ) );
		Ui::toggle( 'auto_remove_verified', $s['auto_remove_verified'], __( 'Remove verified malware automatically, immediately', 'fckmaleware' ), __( 'The moment a scan, the uploads check, an install check or the server scanner finds verified malware (a malicious match of 90% or more from a signature, an exact known-malware hash or Imunify), the file is taken off the site. Never core files, configuration files, or legitimate files with injected code (those are listed for cleaning).', 'fckmaleware' ) );
		Ui::input( 'auto_remove_keep_days', (string) $s['auto_remove_keep_days'], __( 'Keep a recovery copy for (days)', 'fckmaleware' ), 'number', __( 'The removed file is stored compressed and non-executable, then permanently deleted after this many days. 0 deletes it permanently at once, with no way to restore it.', 'fckmaleware' ), array( 'min' => 0, 'max' => 90, 'class' => 'small-text' ) );
		Ui::toggle( 'auto_quarantine', $s['auto_quarantine'], __( 'Also quarantine very-high-confidence heuristic detections in uploads (off by default)', 'fckmaleware' ), __( 'Only malicious signature matches of 90% or more that are exact known-malware hashes, images or files in uploads, and heuristic detections of 95% or more in uploads. Never core files, configuration files, or plugin and theme code. Each action is logged and restorable.', 'fckmaleware' ) );
		Ui::input( 'bulk_min_confidence', (string) $s['bulk_min_confidence'], __( '"Quarantine all eligible" minimum confidence (%)', 'fckmaleware' ), 'number', __( 'Bulk quarantine of filtered or all findings skips anything below this, suspicious-only findings, and heuristic matches in active plugins or themes.', 'fckmaleware' ), array( 'min' => 50, 'max' => 100, 'class' => 'small-text' ) );
		Ui::card_end();

		Ui::card_start( __( '4. Blocking', 'fckmaleware' ), '', __( 'Temporary upload blocks after repeated malicious uploads. Only uploads are blocked, never logins or page views, so nobody is locked out of the site.', 'fckmaleware' ) );
		Ui::input( 'upload_rate_limit', (string) $s['upload_rate_limit'], __( 'Block after this many refused uploads in an hour', 'fckmaleware' ), 'number', __( '0 turns blocking off. Logged-in users are tracked by account; visitors by connection address (REMOTE_ADDR, which can be shared by many people behind one proxy).', 'fckmaleware' ), array( 'min' => 0, 'max' => 20, 'class' => 'small-text' ) );
		Ui::input( 'upload_block_minutes', (string) $s['upload_block_minutes'], __( 'Block duration (minutes)', 'fckmaleware' ), 'number', '', array( 'min' => 5, 'max' => 1440, 'class' => 'small-text' ) );
		Ui::card_end();

		Ui::card_start( __( '5. Notifications', 'fckmaleware' ), '', __( 'Blocked uploads, new administrators and critical option changes are alerts.', 'fckmaleware' ) );
		Ui::toggle( 'email_alerts', $s['email_alerts'], __( 'E-mail alerts', 'fckmaleware' ) );
		Ui::toggle( 'dashboard_notices', $s['dashboard_notices'], __( 'Dashboard notice for open high or critical findings and critical events', 'fckmaleware' ) );
		echo '<p class="description"><a href="' . esc_url( Ui::url( 'settings' ) . '#notifications' ) . '">' . esc_html__( 'Recipients, severity threshold and cooldown', 'fckmaleware' ) . '</a> · <a href="' . esc_url( Ui::url( 'connections' ) ) . '">' . esc_html__( 'Webhooks', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( __( 'Coverage', 'fckmaleware' ) );
		$rows = array(
			array( __( 'Media library, REST API, sideloaded files', 'fckmaleware' ), $s['realtime_uploads'] ? Ui::status( __( 'Prevented at upload', 'fckmaleware' ), 'good' ) : Ui::status( __( 'Off', 'fckmaleware' ), 'warn' ) ),
			array( __( 'Plugin and theme installs and updates', 'fckmaleware' ), $s['realtime_installs'] ? Ui::status( __( 'Checked within minutes', 'fckmaleware' ), 'good' ) : Ui::status( __( 'Off', 'fckmaleware' ), 'warn' ) ),
			array( __( 'Files written by other plugins into uploads', 'fckmaleware' ), 'off' !== $s['uploads_watch'] ? Ui::status( __( 'Periodic uploads check', 'fckmaleware' ), 'neutral' ) : Ui::status( __( 'Scheduled scans only', 'fckmaleware' ), 'warn' ) ),
			array( __( 'FTP, SSH, control-panel file managers', 'fckmaleware' ), Ui::status( __( 'Scheduled scans and uploads check', 'fckmaleware' ), 'neutral' ) ),
			array( __( 'Other sites or accounts on the same server', 'fckmaleware' ), Ui::status( __( 'Needs a server scanner', 'fckmaleware' ), 'off' ) ),
		);
		echo '<ul class="fckmw-statuslist">';
		foreach ( $rows as $row ) {
			echo '<li><span class="fckmw-statuslist-name">' . esc_html( $row[0] ) . '</span>' . $row[1] . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput -- status() escapes.
		}
		echo '</ul>';
		Ui::card_end();
		echo '</div>';
		Ui::submit( __( 'Save protection settings', 'fckmaleware' ) );
		echo '</form>';

		echo '<div class="fckmw-grid" style="margin-top:18px">';
		Ui::card_start( __( 'Temporary upload blocks', 'fckmaleware' ) );
		$blocks = Monitor::blocks();
		if ( ! $blocks ) {
			Ui::empty_state( __( 'No active blocks', 'fckmaleware' ), '', '', 'yes-alt' );
		} else {
			echo '<ul class="fckmw-statuslist">';
			foreach ( $blocks as $actor => $block ) {
				/* translators: %s: time */
				echo '<li><span class="fckmw-statuslist-name">' . esc_html( Monitor::actor_label( (string) $actor ) ) . '</span><span class="description">' . esc_html( sprintf( __( 'until %s', 'fckmaleware' ), Ui::datetime( (int) $block['until'] ) ) ) . '</span></li>';
			}
			echo '</ul>';
			Ui::action_button( 'upload_blocks', __( 'Lift all blocks', 'fckmaleware' ), array( 'return' => 'realtime' ) );
		}
		Ui::card_end();

		Ui::card_start( __( 'Pending background checks', 'fckmaleware' ) );
		$queue = (array) Store::get( Monitor::QUEUE_OPTION, array() );
		if ( ! $queue ) {
			Ui::empty_state( __( 'Nothing is waiting', 'fckmaleware' ), __( 'Queued checks run within a minute through WP-Cron.', 'fckmaleware' ), '', 'yes-alt' );
		} else {
			echo '<ul class="fckmw-statuslist">';
			foreach ( $queue as $item ) {
				echo '<li><code>' . esc_html( (string) ( $item['dir'] ?? '' ) ) . '</code><span class="description">' . esc_html( (string) ( $item['reason'] ?? '' ) ) . '</span></li>';
			}
			echo '</ul>';
			$next = wp_next_scheduled( Monitor::CRON_QUEUE );
			/* translators: %s: time */
			echo '<p class="description">' . esc_html( $next ? sprintf( __( 'Next run %s.', 'fckmaleware' ), Ui::ago( (int) $next ) ) : __( 'Not scheduled: WP-Cron may be disabled on this site.', 'fckmaleware' ) ) . '</p>';
		}
		Ui::card_end();
		echo '</div>';

		Ui::card_start( __( 'Recent protection events', 'fckmaleware' ) );
		$rows = ActivityLog::query( array( 'types' => array( 'upload.', 'event.', 'user.', 'option.', 'threat.', 'quarantine.auto' ), 'since' => $since ), 1, 20 )['rows'];
		if ( ! $rows ) {
			Ui::empty_state( __( 'No protection events in the last 30 days', 'fckmaleware' ), '', '', 'shield' );
		} else {
			echo '<ul class="fckmw-events">';
			foreach ( $rows as $row ) {
				list( $icon, $tone ) = Overview::event_style( (string) $row['type'], (string) $row['severity'] );
				printf( '<li><span class="fckmw-event-icon fckmw-tone-%1$s"><span class="dashicons dashicons-%2$s" aria-hidden="true"></span></span><span class="fckmw-event-text">%3$s</span><span class="fckmw-event-time">%4$s</span></li>', esc_attr( $tone ), esc_attr( $icon ), esc_html( (string) $row['message'] ), Ui::when( (int) $row['created_at'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput
			}
			echo '</ul>';
		}
		Ui::card_end();
		Ui::footer();
	}
}
