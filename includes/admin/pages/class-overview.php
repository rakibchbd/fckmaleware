<?php
/**
 * Security Overview: posture at a glance. Every number comes from the site's
 * own records (findings, quarantine index, scan history, activity log,
 * settings); nothing is estimated or invented. Unknown states are shown as such.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Health;
use Fckmaleware\Paths;
use Fckmaleware\Plugin;
use Fckmaleware\ScanHistory;
use Fckmaleware\Settings;
use Fckmaleware\Store;

final class Overview extends Page {

	public function render( string $title ): void {
		$health   = Health::compute( $this->plugin );
		$counts   = $this->plugin->findings()->open_counts();
		$statuses = $this->plugin->findings()->status_counts();
		$settings = Settings::all();
		$quar     = $this->plugin->quarantine()->stats();
		$scan     = $this->plugin->scanner()->state();
		$last     = ScanHistory::latest( null, true );
		$legacy   = (array) Store::get( 'fckmw_last_scan', array() );
		$sigs     = $this->plugin->signatures();
		$updates  = $this->plugin->signature_updater()->state();

		Ui::header( $title, __( 'Your website\'s security at a glance.', 'fckmaleware' ) );

		echo '<div class="fckmw-layout"><div class="fckmw-main">';

		// Score, metrics and the scan/signature strip.
		Ui::card_start( '', 'fckmw-overview-hero' );
		echo '<div class="fckmw-metrics">';
		$this->score( $health );
		$open_tone = $counts['confirmed'] ? 'bad' : 'good';
		self::metric( __( 'Confirmed malware', 'fckmaleware' ), (string) $counts['confirmed'], $open_tone, $counts['confirmed'] ? __( 'Requires attention', 'fckmaleware' ) : __( 'None open', 'fckmaleware' ), 'warning', Ui::url( 'findings', array( 'verdict' => 'malicious', 'confidence' => 'high' ) ) );
		self::metric( __( 'Suspicious files', 'fckmaleware' ), (string) $counts['suspicious'], $counts['suspicious'] ? 'warn' : 'good', $counts['suspicious'] ? __( 'Under review', 'fckmaleware' ) : __( 'None open', 'fckmaleware' ), 'search', Ui::url( 'findings', array( 'verdict' => 'suspicious' ) ) );
		self::metric( __( 'Quarantined files', 'fckmaleware' ), (string) $quar['quarantined'], 'info', __( 'Isolated, restorable', 'fckmaleware' ), 'lock', Ui::url( 'quarantine' ) );
		self::metric( __( 'False positives', 'fckmaleware' ), (string) $statuses['ignored'], 'neutral', __( 'Accepted as safe', 'fckmaleware' ), 'yes', Ui::url( 'findings', array( 'status' => 'ignored' ) ) );
		echo '</div>';

		echo '<div class="fckmw-strip">';
		if ( 'running' === $scan['status'] ) {
			/* translators: 1: position, 2: total */
			self::strip_item( 'update', __( 'Scan in progress', 'fckmaleware' ), ScanHistory::label( (string) $scan['mode'] ), sprintf( __( '%1$d of %2$d files', 'fckmaleware' ), $scan['position'], $scan['total'] ) );
		} elseif ( $last || $legacy ) {
			$finished = $last ? (int) $last['finished'] : (int) $legacy['finished'];
			self::strip_item( 'calendar-alt', __( 'Last successful scan', 'fckmaleware' ), self::short_date( $finished ), sprintf( '%s · %s', ScanHistory::label( $last ? (string) $last['mode'] : (string) $legacy['mode'] ), Ui::ago( $finished ) ) );
		} else {
			self::strip_item( 'calendar-alt', __( 'Last successful scan', 'fckmaleware' ), __( 'No scan yet', 'fckmaleware' ), __( 'Run a full scan to start', 'fckmaleware' ) );
		}
		$next = wp_next_scheduled( Plugin::CRON_SCAN );
		self::strip_item( 'clock', __( 'Next scheduled scan', 'fckmaleware' ), $next ? self::short_date( (int) $next ) : ( 'off' === $settings['schedule'] ? __( 'Off', 'fckmaleware' ) : __( 'Not scheduled', 'fckmaleware' ) ), $next ? sprintf( '%s · %s', ScanHistory::label( (string) $settings['scheduled_mode'] ), Ui::ago( (int) $next ) ) : __( 'Set a schedule under Scan & Threats', 'fckmaleware' ) );
		$fresh = $updates['last_error'] ? __( 'Last update check failed', 'fckmaleware' ) : ( $updates['last_success'] ? sprintf( /* translators: %s: time */ __( 'Checked %s', 'fckmaleware' ), Ui::ago( (int) $updates['last_success'] ) ) : __( 'Bundled with the plugin', 'fckmaleware' ) );
		/* translators: %s: version */
		self::strip_item( 'database', __( 'Signature database', 'fckmaleware' ), sprintf( __( 'v%s', 'fckmaleware' ), $sigs->version() ), $fresh );
		echo '<div class="fckmw-strip-actions">';
		echo '<a class="button button-primary" href="' . esc_url( Ui::url( 'scanner' ) ) . '"><span class="dashicons dashicons-search" aria-hidden="true"></span>' . esc_html__( 'Start scan', 'fckmaleware' ) . '</a>';
		echo '<a class="button" href="' . esc_url( Ui::url( 'findings' ) ) . '"><span class="dashicons dashicons-list-view" aria-hidden="true"></span>' . esc_html__( 'View findings', 'fckmaleware' ) . '</a>';
		if ( $counts['total'] ) {
			echo '<button type="button" class="button" data-fckmw-bulk-eligible data-href="' . esc_url( Ui::url( 'findings' ) ) . '" data-preview="' . esc_attr( self::eligible_preview_text() ) . '"><span class="dashicons dashicons-lock" aria-hidden="true"></span>' . esc_html__( 'Quarantine all', 'fckmaleware' ) . '</button>';
		}
		echo '</div></div>';
		Ui::card_end();

		Findings::job_panel();

		$this->shortcuts();

		echo '<div class="fckmw-grid fckmw-grid-2">';
		$this->scan_activity();
		$this->threats( $counts, $settings, $health );
		echo '</div>';

		echo '</div><aside class="fckmw-aside">';
		$this->system_status( $counts, $settings, $scan, $sigs, $updates );
		$this->quick_actions();
		$this->events();
		echo '</aside></div>';

		Ui::footer();
	}

	/** Shared confirmation text for "Quarantine all eligible" (placeholders filled by the preview). */
	public static function eligible_preview_text(): string {
		/* translators: 1: eligible, 2: total, 3: skipped */
		return __( '%1$d of %2$d open findings are eligible and will be moved to quarantine in safe batches. %3$d will be skipped (core and configuration files, suspicious-only, low-confidence or injected-but-legitimate files stay for review). Each file is re-checked before it is moved, a verified copy is kept, and the whole action can be rolled back from the Quarantine screen.', 'fckmaleware' );
	}

	private function score( array $health ): void {
		$labels = array( 'good' => __( 'Good', 'fckmaleware' ), 'warn' => __( 'Fair', 'fckmaleware' ), 'bad' => __( 'At risk', 'fckmaleware' ) );
		$score  = (int) $health['score'];
		echo '<div class="fckmw-metric fckmw-score fckmw-tone-' . esc_attr( $health['grade'] ) . '">';
		printf(
			'<div class="fckmw-ring" role="img" aria-label="%1$s"><svg viewBox="0 0 36 36" aria-hidden="true"><circle class="fckmw-ring-track" cx="18" cy="18" r="15.9155" fill="none" stroke-width="3.2"></circle><circle class="fckmw-ring-value" cx="18" cy="18" r="15.9155" fill="none" stroke-width="3.2" stroke-dasharray="%2$d 100"></circle></svg><span class="fckmw-ring-label">%2$d</span></div>',
			esc_attr( sprintf( /* translators: %d: score */ __( 'Security score %d out of 100', 'fckmaleware' ), $score ) ),
			$score // phpcs:ignore WordPress.Security.EscapeOutput -- integer.
		);
		echo '<div class="fckmw-score-text"><strong>' . esc_html__( 'Security score', 'fckmaleware' ) . '</strong><span class="fckmw-score-grade">' . esc_html( $labels[ $health['grade'] ] ?? '' ) . '</span>';
		echo '<details><summary>' . esc_html__( 'How it is calculated', 'fckmaleware' ) . '</summary>';
		if ( $health['deductions'] ) {
			echo '<ul class="fckmw-deductions">';
			foreach ( $health['deductions'] as $deduction ) {
				printf( '<li><strong>−%d</strong> %s</li>', (int) $deduction['points'], esc_html( $deduction['reason'] ) );
			}
			echo '</ul>';
		} else {
			echo '<p class="description">' . esc_html__( '100 points: no open threats, a recent scan, protection on and hardening checks passing.', 'fckmaleware' ) . '</p>';
		}
		echo '</details></div></div>';
	}

	private static function metric( string $label, string $value, string $tone, string $sub, string $icon, string $link ): void {
		printf(
			'<a class="fckmw-metric fckmw-tone-%1$s" href="%2$s"><span class="fckmw-metric-icon"><span class="dashicons dashicons-%3$s" aria-hidden="true"></span></span><span class="fckmw-metric-value">%4$s</span><span class="fckmw-metric-label">%5$s</span><span class="fckmw-metric-sub">%6$s</span></a>',
			esc_attr( $tone ),
			esc_url( $link ),
			esc_attr( $icon ),
			esc_html( $value ),
			esc_html( $label ),
			esc_html( $sub )
		);
	}

	private static function short_date( int $timestamp ): string {
		return wp_date( 'M j, ' . get_option( 'time_format' ), $timestamp );
	}

	private static function strip_item( string $icon, string $label, string $value, string $sub ): void {
		printf(
			'<div class="fckmw-strip-item"><span class="dashicons dashicons-%1$s" aria-hidden="true"></span><div><span class="fckmw-strip-label">%2$s</span><span class="fckmw-strip-value">%3$s</span><span class="fckmw-strip-sub">%4$s</span></div></div>',
			esc_attr( $icon ),
			esc_html( $label ),
			esc_html( $value ),
			esc_html( $sub )
		);
	}

	private function shortcuts(): void {
		$cards = array(
			array( 'scanner', 'search', __( 'Scan & Threats', 'fckmaleware' ), __( 'Run scans, review findings and manage the quarantine.', 'fckmaleware' ), __( 'Go to scanner', 'fckmaleware' ) ),
			array( 'realtime', 'shield', __( 'Protection', 'fckmaleware' ), __( 'Upload screening, automatic prevention, hardening and signatures.', 'fckmaleware' ), __( 'Configure protection', 'fckmaleware' ) ),
			array( 'integrations', 'admin-links', __( 'Integrations', 'fckmaleware' ), __( 'Connect Imunify360 or ImunifyAV, check cPGuard, webhooks.', 'fckmaleware' ), __( 'Manage integrations', 'fckmaleware' ) ),
			array( 'settings', 'admin-generic', __( 'Settings & Logs', 'fckmaleware' ), __( 'Plugin settings, activity log, reports and diagnostics.', 'fckmaleware' ), __( 'Open settings', 'fckmaleware' ) ),
		);
		echo '<div class="fckmw-shortcuts">';
		foreach ( $cards as $card ) {
			printf(
				'<a class="fckmw-shortcut" href="%1$s"><span class="fckmw-shortcut-icon"><span class="dashicons dashicons-%2$s" aria-hidden="true"></span></span><span class="fckmw-shortcut-title">%3$s</span><span>%4$s</span><span class="fckmw-shortcut-link">%5$s</span></a>',
				esc_url( Ui::url( $card[0] ) ),
				esc_attr( $card[1] ),
				esc_html( $card[2] ),
				esc_html( $card[3] ),
				esc_html( $card[4] )
			);
		}
		echo '</div>';
	}

	private function scan_activity(): void {
		echo '<section class="fckmw-card"><div class="fckmw-card-head"><h2 class="fckmw-card-title">' . esc_html__( 'Recent scan activity', 'fckmaleware' ) . '</h2><a class="fckmw-more" href="' . esc_url( Ui::url( 'scanner' ) . '#history' ) . '">' . esc_html__( 'View all scans', 'fckmaleware' ) . '</a></div>';
		$history = array_slice( ScanHistory::all(), 0, 6 );
		if ( ! $history ) {
			Ui::empty_state( __( 'No scans yet', 'fckmaleware' ), __( 'Completed, cancelled and failed scans appear here.', 'fckmaleware' ), Ui::button_link( Ui::url( 'scanner' ), __( 'Start a scan', 'fckmaleware' ), 'button button-primary' ), 'search' );
		} else {
			Scanner::history_table( $history, true );
		}
		echo '</section>';
	}

	private function threats( array $counts, array $settings, array $health ): void {
		$data   = $this->plugin->findings()->breakdown_since( time() - 7 * DAY_IN_SECONDS );
		$total  = array_sum( $data );
		$series = array(
			'malware'        => array( __( 'Malware', 'fckmaleware' ), '#ef4444' ),
			'suspicious'     => array( __( 'Suspicious', 'fckmaleware' ), '#f59e0b' ),
			'heuristic'      => array( __( 'Heuristic', 'fckmaleware' ), '#3b82f6' ),
			'false_positive' => array( __( 'False positive', 'fckmaleware' ), '#94a3b8' ),
			'other'          => array( __( 'Integrity & other', 'fckmaleware' ), '#8b5cf6' ),
		);
		echo '<section class="fckmw-card"><div class="fckmw-card-head"><h2 class="fckmw-card-title">' . esc_html__( 'Top threats (last 7 days)', 'fckmaleware' ) . '</h2><a class="fckmw-more" href="' . esc_url( Ui::url( 'findings', array( 'since_days' => 7 ) ) ) . '">' . esc_html__( 'View all findings', 'fckmaleware' ) . '</a></div>';
		if ( ! $total ) {
			Ui::empty_state( __( 'No new detections in the last 7 days', 'fckmaleware' ), __( 'New findings from scans and protection events are summarised here.', 'fckmaleware' ) );
		} else {
			echo '<div class="fckmw-donut-wrap"><div class="fckmw-donut"><svg viewBox="0 0 36 36" role="img" aria-label="' . esc_attr__( 'Findings by type', 'fckmaleware' ) . '">';
			$offset = 0.0;
			foreach ( $series as $key => $meta ) {
				if ( ! $data[ $key ] ) {
					continue;
				}
				$pct = 100 * $data[ $key ] / $total;
				printf( '<circle cx="18" cy="18" r="15.9155" fill="none" stroke="%1$s" stroke-width="4.2" stroke-dasharray="%2$s %3$s" stroke-dashoffset="%4$s"></circle>', esc_attr( $meta[1] ), esc_attr( number_format( $pct, 3, '.', '' ) ), esc_attr( number_format( 100 - $pct, 3, '.', '' ) ), esc_attr( number_format( -$offset, 3, '.', '' ) ) );
				$offset += $pct;
			}
			echo '</svg><div class="fckmw-donut-center"><strong>' . esc_html( number_format_i18n( $total ) ) . '</strong><span>' . esc_html__( 'findings', 'fckmaleware' ) . '</span></div></div><ul class="fckmw-legend">';
			foreach ( $series as $key => $meta ) {
				printf( '<li><span class="fckmw-legend-swatch" style="background:%1$s"></span><span>%2$s</span><span class="fckmw-num">%3$s</span><span class="fckmw-legend-pct">%4$s%%</span></li>', esc_attr( $meta[1] ), esc_html( $meta[0] ), esc_html( number_format_i18n( $data[ $key ] ) ), esc_html( number_format_i18n( 100 * $data[ $key ] / $total, 1 ) ) );
			}
			echo '</ul></div>';
		}
		$recommendations = $this->recommendations( $counts, $settings, $health );
		if ( $recommendations ) {
			echo '<div class="fckmw-recommend"><p class="fckmw-recommend-title"><span class="dashicons dashicons-lightbulb" aria-hidden="true"></span>' . esc_html__( 'Recommended actions', 'fckmaleware' ) . '</p><ol>';
			foreach ( array_slice( $recommendations, 0, 4 ) as $item ) {
				echo '<li><a href="' . esc_url( $item[1] ) . '">' . esc_html( $item[0] ) . '</a></li>';
			}
			echo '</ol></div>';
		}
		echo '</section>';
	}

	/**
	 * Recommendations ordered by risk, each from a real condition.
	 *
	 * @return array<int, array{0: string, 1: string}>
	 */
	private function recommendations( array $counts, array $settings, array $health ): array {
		$out  = array();
		$last = (array) Store::get( 'fckmw_last_scan', array() );
		if ( $counts['confirmed'] ) {
			/* translators: %d: count */
			$out[] = array( sprintf( _n( 'Quarantine %d confirmed malware finding.', 'Quarantine %d confirmed malware findings.', $counts['confirmed'], 'fckmaleware' ), $counts['confirmed'] ), Ui::url( 'findings', array( 'verdict' => 'malicious', 'confidence' => 'high' ) ) );
		}
		if ( $counts['critical'] + $counts['high'] > $counts['confirmed'] ) {
			/* translators: %d: count */
			$out[] = array( sprintf( __( 'Review %d open critical and high-severity findings.', 'fckmaleware' ), $counts['critical'] + $counts['high'] ), Ui::url( 'findings', array( 'severity' => $counts['critical'] ? 'critical' : 'high' ) ) );
		}
		if ( empty( $last['finished'] ) ) {
			$out[] = array( __( 'Run a full scan to establish a baseline.', 'fckmaleware' ), Ui::url( 'scanner' ) );
		} elseif ( time() - (int) $last['finished'] > 7 * DAY_IN_SECONDS ) {
			$out[] = array( __( 'The last full scan is more than a week old: run one now.', 'fckmaleware' ), Ui::url( 'scanner' ) );
		}
		if ( ! $settings['realtime_uploads'] ) {
			$out[] = array( __( 'Turn on upload screening to refuse malicious uploads.', 'fckmaleware' ), Ui::url( 'realtime' ) );
		}
		if ( 'off' === $settings['schedule'] ) {
			$out[] = array( __( 'Schedule automatic scans.', 'fckmaleware' ), Ui::url( 'schedule' ) );
		}
		$updates = $this->plugin->signature_updater()->state();
		if ( ! $settings['signature_updates'] ) {
			$out[] = array( __( 'Turn on signature updates so new rules reach this site.', 'fckmaleware' ), Ui::url( 'signatures' ) );
		} elseif ( $updates['failures'] >= 3 ) {
			$out[] = array( __( 'Signature updates are failing: check the connection.', 'fckmaleware' ), Ui::url( 'signatures' ) );
		}
		if ( $counts['suspicious'] ) {
			/* translators: %d: count */
			$out[] = array( sprintf( __( 'Review %d suspicious findings and accept or quarantine them.', 'fckmaleware' ), $counts['suspicious'] ), Ui::url( 'findings', array( 'verdict' => 'suspicious' ) ) );
		}
		$hardening = (array) Store::get( 'fckmw_hardening_summary', array() );
		if ( ! empty( $hardening['fail'] ) || ! empty( $hardening['warn'] ) ) {
			$out[] = array( __( 'Apply the recommended hardening rules.', 'fckmaleware' ), Ui::url( 'hardening' ) );
		}
		if ( Paths::data_dir_in_web_root() ) {
			$out[] = array( __( 'Move the quarantine outside the web root (FCKMW_DATA_DIR).', 'fckmaleware' ), Ui::url( 'diagnostics' ) );
		}
		return $out;
	}

	private function system_status( array $counts, array $settings, array $scan, $sigs, array $updates ): void {
		$integration = $this->plugin->integrations()->summary();
		$cron_off    = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
		$last_any    = ScanHistory::latest( null, false );
		$scanner     = 'running' === $scan['status']
			? array( __( 'Scanning', 'fckmaleware' ), 'good' )
			: ( $last_any && 'failed' === $last_any['status'] ? array( __( 'Last scan failed', 'fckmaleware' ), 'warn' ) : array( __( 'Ready', 'fckmaleware' ), 'good' ) );
		$signatures  = 0 === $sigs->count()
			? array( __( 'Unavailable', 'fckmaleware' ), 'bad' )
			: ( $updates['failures'] >= 3 ? array( __( 'Update failing', 'fckmaleware' ), 'warn' ) : ( $settings['signature_updates'] ? array( __( 'Up to date', 'fckmaleware' ), 'good' ) : array( __( 'Updates off', 'fckmaleware' ), 'warn' ) ) );
		$rows        = array(
			array( 'search', __( 'Scanner', 'fckmaleware' ), $scanner ),
			array( 'database', __( 'Signatures', 'fckmaleware' ), $signatures ),
			array( 'shield', __( 'Auto quarantine', 'fckmaleware' ), $settings['auto_quarantine'] ? array( __( 'Enabled', 'fckmaleware' ), 'good' ) : array( __( 'Off (manual review)', 'fckmaleware' ), 'off' ) ),
			array( 'upload', __( 'Upload protection', 'fckmaleware' ), $settings['realtime_uploads'] ? ( 'monitor' === $settings['upload_block_mode'] ? array( __( 'Monitor only', 'fckmaleware' ), 'warn' ) : array( __( 'Enabled', 'fckmaleware' ), 'good' ) ) : array( __( 'Off', 'fckmaleware' ), 'warn' ) ),
			array( 'clock', __( 'Scheduled tasks', 'fckmaleware' ), $cron_off ? array( __( 'Needs system cron', 'fckmaleware' ), 'warn' ) : ( 'off' === $settings['schedule'] ? array( __( 'Scans off', 'fckmaleware' ), 'warn' ) : array( __( 'WP-Cron', 'fckmaleware' ), 'good' ) ) ),
			array( 'cloud', __( 'Server integration', 'fckmaleware' ), array( $integration['label'], $integration['tone'] ) ),
		);
		$problems = count(
			array_filter(
				$rows,
				static function ( array $row ): bool {
					return in_array( $row[2][1], array( 'warn', 'bad' ), true );
				}
			)
		);
		$tone = $counts['confirmed'] || 0 === $sigs->count() ? 'bad' : ( $problems || $counts['total'] ? 'warn' : 'good' );
		Ui::card_start();
		echo '<div class="fckmw-system-head fckmw-tone-' . esc_attr( $tone ) . '"><span class="fckmw-system-icon"><span class="dashicons dashicons-' . ( 'good' === $tone ? 'yes' : 'warning' ) . '" aria-hidden="true"></span></span><div>';
		if ( 'good' === $tone ) {
			echo '<strong>' . esc_html__( 'All systems operational', 'fckmaleware' ) . '</strong><span class="description">' . esc_html__( 'No open findings.', 'fckmaleware' ) . '</span>';
		} else {
			/* translators: %d: count */
			echo '<strong>' . esc_html( $counts['total'] ? sprintf( _n( '%d unresolved finding', '%d unresolved findings', $counts['total'], 'fckmaleware' ), $counts['total'] ) : __( 'Some protection is limited', 'fckmaleware' ) ) . '</strong>';
			/* translators: %d: count */
			echo '<span class="description">' . esc_html( $problems ? sprintf( _n( '%d component needs attention.', '%d components need attention.', $problems, 'fckmaleware' ), $problems ) : __( 'All components are working.', 'fckmaleware' ) ) . '</span>';
		}
		echo '</div></div><ul class="fckmw-statuslist">';
		foreach ( $rows as $row ) {
			echo '<li><span class="fckmw-statuslist-name"><span class="dashicons dashicons-' . esc_attr( $row[0] ) . '" aria-hidden="true"></span>' . esc_html( $row[1] ) . '</span>' . Ui::status( $row[2][0], $row[2][1] ) . '</li>'; // phpcs:ignore WordPress.Security.EscapeOutput -- status() escapes.
		}
		echo '</ul>';
		Ui::card_end();
	}

	private function quick_actions(): void {
		$scanner = Ui::url( 'scanner' );
		Ui::card_start( __( 'Quick actions', 'fckmaleware' ) );
		echo '<div class="fckmw-quick">';
		$buttons = array(
			array( 'quick', 'search', __( 'Start quick scan', 'fckmaleware' ), 'button button-primary' ),
			array( 'core', 'wordpress', __( 'Scan WordPress core', 'fckmaleware' ), 'button' ),
			array( 'plugins', 'admin-plugins', __( 'Scan themes & plugins', 'fckmaleware' ), 'button' ),
			array( 'uploads', 'format-image', __( 'Scan uploads directory', 'fckmaleware' ), 'button' ),
			array( 'database', 'database', __( 'Scan database', 'fckmaleware' ), 'button' ),
		);
		foreach ( $buttons as $button ) {
			printf(
				'<button type="button" class="%1$s" data-fckmw-scan="%2$s" data-href="%3$s"><span class="dashicons dashicons-%4$s" aria-hidden="true"></span>%5$s</button>',
				esc_attr( $button[3] ),
				esc_attr( $button[0] ),
				esc_url( $scanner ),
				esc_attr( $button[1] ),
				esc_html( $button[2] )
			);
		}
		echo '</div>';
		Ui::card_end();
	}

	private function events(): void {
		echo '<section class="fckmw-card"><div class="fckmw-card-head"><h2 class="fckmw-card-title">' . esc_html__( 'Recent events', 'fckmaleware' ) . '</h2><a class="fckmw-more" href="' . esc_url( Ui::url( 'activity' ) ) . '">' . esc_html__( 'View all', 'fckmaleware' ) . '</a></div>';
		$events = ActivityLog::query( array(), 1, 6 )['rows'];
		if ( ! $events ) {
			Ui::empty_state( __( 'No events recorded yet', 'fckmaleware' ), '', '', 'info' );
		} else {
			echo '<ul class="fckmw-events">';
			foreach ( $events as $event ) {
				list( $icon, $tone ) = self::event_style( (string) $event['type'], (string) $event['severity'] );
				printf(
					'<li><span class="fckmw-event-icon fckmw-tone-%1$s"><span class="dashicons dashicons-%2$s" aria-hidden="true"></span></span><span class="fckmw-event-text" title="%3$s">%3$s</span><span class="fckmw-event-time">%4$s</span></li>',
					esc_attr( $tone ),
					esc_attr( $icon ),
					esc_attr( (string) $event['message'] ),
					Ui::when( (int) $event['created_at'] ) // phpcs:ignore WordPress.Security.EscapeOutput -- when() escapes.
				);
			}
			echo '</ul>';
		}
		echo '</section>';
	}

	/** @return array{0: string, 1: string} Dashicon and tone for an activity entry. */
	public static function event_style( string $type, string $severity ): array {
		$prefix = strtok( $type, '.' );
		$icons  = array(
			'scan'       => 'search',
			'dbscan'     => 'database',
			'quarantine' => 'lock',
			'bulk'       => 'lock',
			'repair'     => 'hammer',
			'signatures' => 'database',
			'upload'     => 'upload',
			'hardening'  => 'shield',
			'settings'   => 'admin-generic',
			'user'       => 'admin-users',
			'threat'     => 'warning',
			'plugin'     => 'admin-plugins',
			'theme'      => 'admin-appearance',
			'imunify'    => 'cloud',
			'integration' => 'admin-links',
			'notify'     => 'email',
		);
		$tones = array( 'critical' => 'bad', 'warning' => 'warn', 'notice' => 'info', 'info' => 'info' );
		$tone  = $tones[ $severity ] ?? 'info';
		if ( in_array( $type, array( 'scan.complete', 'dbscan.complete', 'signatures.updated', 'bulk.completed', 'quarantine.isolate' ), true ) && 'info' === $tone ) {
			$tone = 'good';
		}
		return array( $icons[ $prefix ] ?? 'info-outline', $tone );
	}
}
