<?php
/**
 * Reports: what happened over a period, computed from the findings table,
 * the scan history and the activity log, with CSV exports per category and
 * a printable view. Exports neutralise spreadsheet formulas and contain
 * site-relative paths only.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Findings;
use Fckmaleware\Health;
use Fckmaleware\ScanHistory;

final class Reports extends Page {

	private const PERIODS = array( 7, 30, 90 );

	public function render( string $title ): void {
		global $wpdb;
		$days   = (int) self::query( 'days', 30 );
		$days   = in_array( $days, self::PERIODS, true ) ? $days : 30;
		$since  = time() - $days * DAY_IN_SECONDS;
		$cutoff = gmdate( 'Y-m-d H:i:s', $since );
		$table  = Findings::table();
		$events = ActivityLog::summary( $since );
		$health = Health::compute( $this->plugin );

		Ui::header( $title, __( 'All figures are counted from this site\'s own records.', 'fckmaleware' ), '<button type="button" class="button fckmw-print"><span class="dashicons dashicons-printer" aria-hidden="true"></span>' . esc_html__( 'Print / save as PDF', 'fckmaleware' ) . '</button>' );

		echo '<nav class="fckmw-segments" aria-label="' . esc_attr__( 'Period', 'fckmaleware' ) . '">';
		foreach ( self::PERIODS as $period ) {
			/* translators: %d: days */
			echo '<a href="' . esc_url( Ui::url( 'reports', array( 'days' => $period ) ) ) . '"' . ( $period === $days ? ' class="is-current" aria-current="page"' : '' ) . '>' . esc_html( sprintf( __( 'Last %d days', 'fckmaleware' ), $period ) ) . '</a>';
		}
		echo '</nav>';

		// phpcs:disable WordPress.DB
		$new_by_severity = $wpdb->get_results( $wpdb->prepare( "SELECT severity, COUNT(*) AS n FROM {$table} WHERE detected_at >= %s GROUP BY severity", $cutoff ), ARRAY_A );
		$new_by_source   = $wpdb->get_results( $wpdb->prepare( "SELECT source, COUNT(*) AS n FROM {$table} WHERE detected_at >= %s GROUP BY source ORDER BY n DESC", $cutoff ), ARRAY_A );
		$top_rules       = $wpdb->get_results( $wpdb->prepare( "SELECT signature_id, signature_name, COUNT(*) AS n FROM {$table} WHERE detected_at >= %s GROUP BY signature_id, signature_name ORDER BY n DESC LIMIT 10", $cutoff ), ARRAY_A );
		$new_total       = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE detected_at >= %s", $cutoff ) );
		// phpcs:enable

		$sum = static function ( array $types ) use ( $events ): int {
			$total = 0;
			foreach ( $events as $type => $count ) {
				foreach ( $types as $prefix ) {
					if ( $type === $prefix || ( '.' === substr( $prefix, -1 ) && 0 === strpos( $type, $prefix ) ) ) {
						$total += $count;
					}
				}
			}
			return $total;
		};
		$failed = 0;
		foreach ( $events as $type => $count ) {
			if ( preg_match( '/\.(failed|error|corrupt)$/', $type ) ) {
				$failed += $count;
			}
		}
		$scans = array_filter(
			ScanHistory::all(),
			static function ( array $row ) use ( $since ): bool {
				return (int) $row['finished'] >= $since;
			}
		);

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Current health score', 'fckmaleware' ), (string) $health['score'], $health['grade'] );
		Ui::stat( __( 'Scans run', 'fckmaleware' ), (string) count( $scans ), 'neutral', '', Ui::url( 'scanner' ) . '#history' );
		Ui::stat( __( 'New findings', 'fckmaleware' ), (string) $new_total, 'neutral', '', Ui::url( 'findings', array( 'since_days' => $days ) ) );
		Ui::stat( __( 'Files quarantined', 'fckmaleware' ), (string) $sum( array( 'quarantine.isolate', 'quarantine.auto' ) ) );
		Ui::stat( __( 'Files restored', 'fckmaleware' ), (string) $sum( array( 'quarantine.restore' ) ) );
		Ui::stat( __( 'Uploads blocked', 'fckmaleware' ), (string) $sum( array( 'upload.blocked', 'upload.refused' ) ) );
		Ui::stat( __( 'Signature updates', 'fckmaleware' ), (string) $sum( array( 'signatures.updated' ) ) );
		Ui::stat( __( 'Failed operations', 'fckmaleware' ), (string) $failed, $failed ? 'warn' : 'neutral', '', Ui::url( 'activity', array( 'type' => 'failed', 'days' => $days ) ) );
		echo '</div>';

		echo '<div class="fckmw-grid fckmw-grid-3">';
		Ui::card_start( __( 'New findings by severity', 'fckmaleware' ) );
		self::bars( $new_by_severity, 'severity' );
		Ui::card_end();
		Ui::card_start( __( 'New findings by detection source', 'fckmaleware' ) );
		self::bars( $new_by_source, 'source' );
		Ui::card_end();
		Ui::card_start( __( 'Most frequent rules', 'fckmaleware' ) );
		if ( ! $top_rules ) {
			echo '<p class="description">' . esc_html__( 'No findings in this period.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<table class="fckmw-table"><tbody>';
			foreach ( $top_rules as $rule ) {
				echo '<tr><td><code>' . esc_html( $rule['signature_id'] ) . '</code> ' . esc_html( $rule['signature_name'] ) . '</td><td class="fckmw-num">' . (int) $rule['n'] . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Ui::card_end();
		echo '</div>';

		$categories = array(
			array( __( 'Scan summaries', 'fckmaleware' ), array( 'scan.', 'dbscan.' ), 'scan.' ),
			array( __( 'Detection history', 'fckmaleware' ), array( 'threat.' ), 'threat.' ),
			array( __( 'Quarantine and restoration', 'fckmaleware' ), array( 'quarantine.', 'bulk.', 'restore_point.' ), 'quarantine.' ),
			array( __( 'Protection events', 'fckmaleware' ), array( 'upload.', 'event.', 'user.', 'option.', 'file.' ), 'upload.' ),
			array( __( 'Integration health', 'fckmaleware' ), array( 'integration.', 'imunify.' ), 'integration.' ),
			array( __( 'Signature updates', 'fckmaleware' ), array( 'signatures.' ), 'signatures.' ),
			array( __( 'Hardening changes', 'fckmaleware' ), array( 'hardening.' ), 'hardening.' ),
			array( __( 'Configuration changes', 'fckmaleware' ), array( 'settings.' ), 'settings.' ),
		);
		Ui::card_start( __( 'Activity by category', 'fckmaleware' ), '', __( 'Each export contains the events of that category in the selected period.', 'fckmaleware' ) );
		echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><th scope="col">' . esc_html__( 'Category', 'fckmaleware' ) . '</th><th scope="col" class="fckmw-num">' . esc_html__( 'Events', 'fckmaleware' ) . '</th><th scope="col"></th></tr></thead><tbody>';
		foreach ( $categories as $category ) {
			echo '<tr><td><a href="' . esc_url( Ui::url( 'activity', array( 'type' => $category[2], 'days' => $days ) ) ) . '">' . esc_html( $category[0] ) . '</a></td><td class="fckmw-num">' . esc_html( number_format_i18n( $sum( $category[1] ) ) ) . '</td><td class="fckmw-num">';
			Ui::form( 'export_activity', array( 'type' => $category[2], 'days' => $days ), 'fckmw-inline' );
			echo '<button class="button">' . esc_html__( 'CSV', 'fckmaleware' ) . '</button></form></td></tr>';
		}
		echo '<tr><td><a href="' . esc_url( Ui::url( 'activity', array( 'type' => 'failed', 'days' => $days ) ) ) . '">' . esc_html__( 'Failed operations', 'fckmaleware' ) . '</a></td><td class="fckmw-num">' . esc_html( number_format_i18n( $failed ) ) . '</td><td class="fckmw-num">';
		Ui::form( 'export_activity', array( 'type' => 'failed', 'days' => $days ), 'fckmw-inline' );
		echo '<button class="button">' . esc_html__( 'CSV', 'fckmaleware' ) . '</button></form></td></tr>';
		echo '</tbody></table></div>';
		Ui::card_end();

		Ui::card_start( __( 'Findings exports', 'fckmaleware' ) );
		echo '<div class="fckmw-actions">';
		foreach ( array( 'open' => __( 'Open findings (CSV)', 'fckmaleware' ), 'quarantined' => __( 'Quarantined findings (CSV)', 'fckmaleware' ), 'ignored' => __( 'Accepted findings (CSV)', 'fckmaleware' ), 'resolved' => __( 'Resolved findings (CSV)', 'fckmaleware' ) ) as $status => $label ) {
			Ui::form( 'export_findings', array( 'status' => $status ), 'fckmw-inline' );
			echo '<button class="button"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html( $label ) . '</button></form>';
		}
		Ui::form( 'export_activity', array(), 'fckmw-inline' );
		echo '<button class="button"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Full activity log (CSV)', 'fckmaleware' ) . '</button></form>';
		echo '</div>';
		Ui::card_end();
		Ui::footer();
	}

	/** Horizontal bar list; widths are proportional to the counts shown next to them. */
	private static function bars( array $rows, string $key ): void {
		if ( ! $rows ) {
			echo '<p class="description">' . esc_html__( 'No findings in this period.', 'fckmaleware' ) . '</p>';
			return;
		}
		$max = max( array_map( 'intval', array_column( $rows, 'n' ) ) );
		echo '<ul class="fckmw-bars">';
		foreach ( $rows as $row ) {
			$width = $max ? round( 100 * (int) $row['n'] / $max ) : 0;
			printf( '<li><span class="fckmw-bars-label">%1$s</span><span class="fckmw-bars-track"><span class="fckmw-bars-fill" style="width:%2$d%%"></span></span><span class="fckmw-num">%3$d</span></li>', esc_html( ucfirst( (string) $row[ $key ] ) ), (int) $width, (int) $row['n'] );
		}
		echo '</ul>';
	}
}
