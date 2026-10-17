<?php
/**
 * Security Overview: posture at a glance, all numbers from live data.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Ai\Reviewer;
use Fckmaleware\FileCache;
use Fckmaleware\Health;
use Fckmaleware\Plugin;
use Fckmaleware\Settings;
use Fckmaleware\Store;

final class Overview extends Page {

	public function render( string $title ): void {
		$health   = Health::compute( $this->plugin );
		$counts   = $this->plugin->findings()->open_counts();
		$statuses = $this->plugin->findings()->status_counts();
		$last     = (array) Store::get( 'fckmw_last_scan', array() );
		$scan     = $this->plugin->scanner()->state();
		$sigs     = $this->plugin->signatures();
		$updates  = $this->plugin->signature_updater()->state();
		$quar     = $this->plugin->quarantine()->stats();
		$settings = Settings::all();

		Ui::header( $title, __( 'Current security posture of this WordPress installation.', 'fckmaleware' ) );

		echo '<div class="fckmw-grid fckmw-grid-hero">';
		Ui::card_start( __( 'Security health', 'fckmaleware' ), 'fckmw-health fckmw-tone-' . $health['grade'] );
		printf( '<div class="fckmw-score" role="img" aria-label="%1$s"><span>%2$d</span><small>/100</small></div>', esc_attr( sprintf( /* translators: %d: score */ __( 'Health score %d out of 100', 'fckmaleware' ), $health['score'] ) ), (int) $health['score'] );
		if ( $health['deductions'] ) {
			echo '<ul class="fckmw-deductions">';
			foreach ( $health['deductions'] as $deduction ) {
				printf( '<li><strong>−%d</strong> %s</li>', (int) $deduction['points'], esc_html( $deduction['reason'] ) );
			}
			echo '</ul>';
		} else {
			echo '<p>' . esc_html__( 'No deductions: no open threats, recent scan, protection enabled.', 'fckmaleware' ) . '</p>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Scan', 'fckmaleware' ) );
		if ( 'running' === $scan['status'] ) {
			/* translators: 1: mode, 2: position, 3: total */
			echo '<p>' . esc_html( sprintf( __( '%1$s scan running: %2$d of %3$d files checked.', 'fckmaleware' ), ucfirst( (string) $scan['mode'] ), $scan['position'], $scan['total'] ) ) . '</p>';
			echo '<div class="fckmw-progress"><div class="fckmw-bar" style="width:' . esc_attr( (string) ( $scan['total'] ? round( 100 * $scan['position'] / $scan['total'] ) : 0 ) ) . '%"></div></div>';
		} elseif ( $last ) {
			/* translators: 1: mode, 2: time ago */
			echo '<p>' . esc_html( sprintf( __( 'Last complete scan: %1$s, %2$s.', 'fckmaleware' ), ucfirst( (string) $last['mode'] ), Ui::ago( (int) $last['finished'] ) ) ) . '</p>';
			/* translators: 1: files, 2: skipped, 3: detections */
			echo '<p class="description">' . esc_html( sprintf( __( '%1$d files checked (%2$d unchanged skipped), %3$d detections.', 'fckmaleware' ), $last['total'], $last['skipped'], $last['found'] ) ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'No scan has completed yet.', 'fckmaleware' ) . '</p>';
		}
		$next = wp_next_scheduled( Plugin::CRON_SCAN );
		/* translators: %s: time */
		echo '<p class="description">' . esc_html( 'off' === $settings['schedule'] ? __( 'Scheduled scans are off.', 'fckmaleware' ) : sprintf( __( 'Next scheduled scan: %s.', 'fckmaleware' ), Ui::ago( (int) $next ) ) ) . '</p>';
		echo '<p><a class="button button-primary" href="' . esc_url( Ui::url( 'scanner' ) ) . '">' . esc_html__( 'Open scanner', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();
		echo '</div>';

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Active threats', 'fckmaleware' ), (string) $counts['malicious'], $counts['malicious'] ? 'bad' : 'good', sprintf( /* translators: %d: count */ __( '+%d suspicious', 'fckmaleware' ), $counts['suspicious'] ), Ui::url( 'findings' ) );
		Ui::stat( __( 'Critical / high', 'fckmaleware' ), $counts['critical'] . ' / ' . $counts['high'], $counts['critical'] + $counts['high'] ? 'bad' : 'good', '', Ui::url( 'findings' ) );
		Ui::stat( __( 'Quarantined files', 'fckmaleware' ), (string) $quar['quarantined'], 'neutral', sprintf( /* translators: %d: count */ __( '%d backups', 'fckmaleware' ), $quar['backups'] ), Ui::url( 'quarantine' ) );
		$cache = FileCache::stats();
		Ui::stat( __( 'Files tracked', 'fckmaleware' ), number_format_i18n( $cache['files'] ), 'neutral', sprintf( /* translators: %d: count */ __( '%d clean', 'fckmaleware' ), $cache['clean'] ) );
		Ui::stat( __( 'Signatures', 'fckmaleware' ), number_format_i18n( $sigs->count() ), 'neutral', sprintf( /* translators: 1: version, 2: hashes */ __( 'v%1$s · %2$d hashes', 'fckmaleware' ), $sigs->version(), $sigs->hash_count() ), Ui::url( 'signatures' ) );
		Ui::stat( __( 'Intelligence update', 'fckmaleware' ), Ui::ago( (int) $updates['last_success'] ), $updates['failures'] >= 3 ? 'warn' : 'neutral', $updates['last_error'] ? __( 'last check failed', 'fckmaleware' ) : '', Ui::url( 'intel' ) );
		echo '</div>';

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'WordPress integrity', 'fckmaleware' ) );
		global $wpdb;
		$table     = \Fckmaleware\Findings::table();
		$integrity = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status = 'open' AND source = 'integrity'" ); // phpcs:ignore WordPress.DB
		echo $integrity
			? '<p>' . Ui::badge( __( 'Changes detected', 'fckmaleware' ), 'warn' ) . ' ' . esc_html( sprintf( /* translators: %d: count */ _n( '%d file differs from its official checksum or baseline.', '%d files differ from their official checksums or baselines.', $integrity, 'fckmaleware' ), $integrity ) ) . '</p>' // phpcs:ignore WordPress.Security.EscapeOutput
			: '<p>' . Ui::badge( __( 'Verified', 'fckmaleware' ), 'good' ) . ' ' . esc_html__( 'Core, wordpress.org plugins and baselined components match.', 'fckmaleware' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		$baseline = \Fckmaleware\Detection\Baseline::stats();
		/* translators: 1: files, 2: components */
		echo '<p class="description">' . esc_html( sprintf( __( 'Local baselines: %1$d files in %2$d components.', 'fckmaleware' ), $baseline['files'], $baseline['components'] ) ) . '</p>';
		Ui::card_end();

		Ui::card_start( __( 'Protection configuration', 'fckmaleware' ) );
		$items = array(
			__( 'Scheduled scans', 'fckmaleware' )        => 'off' !== $settings['schedule'],
			__( 'Upload screening', 'fckmaleware' )       => $settings['realtime_uploads'],
			__( 'Install/update checks', 'fckmaleware' )  => $settings['realtime_installs'],
			__( 'User & option monitoring', 'fckmaleware' ) => $settings['monitor_users'] && $settings['monitor_options'],
			__( 'Heuristic engine', 'fckmaleware' )       => $settings['heuristics'],
			__( 'Signature updates', 'fckmaleware' )      => $settings['signature_updates'],
			__( 'Automatic quarantine', 'fckmaleware' )   => $settings['auto_quarantine'],
			__( 'Email alerts', 'fckmaleware' )           => $settings['email_alerts'],
		);
		echo '<ul class="fckmw-checklist">';
		foreach ( $items as $label => $on ) {
			printf( '<li class="%s">%s</li>', $on ? 'is-on' : 'is-off', esc_html( $label ) );
		}
		echo '</ul>';
		Ui::card_end();

		Ui::card_start( __( 'AI classification summary', 'fckmaleware' ) );
		$ai = Reviewer::summary();
		/* translators: 1: heuristic findings */
		echo '<p>' . esc_html( sprintf( __( 'Local heuristic engine: %d open findings.', 'fckmaleware' ), (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status = 'open' AND source = 'heuristic'" ) ) ) . '</p>'; // phpcs:ignore WordPress.DB
		if ( $ai['reviewed'] ) {
			/* translators: 1: reviewed, 2: agree, 3: malicious, 4: suspicious, 5: benign */
			echo '<p>' . esc_html( sprintf( __( 'External AI reviews: %1$d (agreed with local verdict: %2$d). Malicious %3$d, suspicious %4$d, benign %5$d.', 'fckmaleware' ), $ai['reviewed'], $ai['agree'], $ai['malicious'], $ai['suspicious'], $ai['benign'] ) ) . '</p>';
		} else {
			echo '<p class="description">' . esc_html__( 'No external AI reviews (optional; off by default).', 'fckmaleware' ) . '</p>';
		}
		Ui::card_end();
		echo '</div>';

		Ui::card_start( __( 'Recent security events', 'fckmaleware' ) );
		$events = ActivityLog::query( array(), 1, 10 )['rows'];
		if ( ! $events ) {
			echo '<p>' . esc_html__( 'No events recorded yet.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<table class="widefat striped fckmw-table"><tbody>';
			foreach ( $events as $event ) {
				printf(
					'<tr><td class="fckmw-nowrap">%1$s</td><td>%2$s</td><td>%3$s</td></tr>',
					esc_html( Ui::ago( (int) $event['created_at'] ) ),
					Ui::badge( $event['severity'], array( 'critical' => 'critical', 'warning' => 'warn', 'notice' => 'neutral', 'info' => 'neutral' )[ $event['severity'] ] ?? 'neutral' ), // phpcs:ignore WordPress.Security.EscapeOutput
					esc_html( $event['message'] )
				);
			}
			echo '</tbody></table>';
		}
		echo '<p><a href="' . esc_url( Ui::url( 'activity' ) ) . '">' . esc_html__( 'All activity', 'fckmaleware' ) . '</a> · ';
		/* translators: 1: open, 2: quarantined, 3: ignored, 4: resolved */
		echo esc_html( sprintf( __( 'Findings: %1$d open, %2$d quarantined, %3$d ignored, %4$d resolved.', 'fckmaleware' ), $statuses['open'], $statuses['quarantined'], $statuses['ignored'], $statuses['resolved'] ) ) . '</p>';
		Ui::card_end();

		Ui::footer();
	}
}
