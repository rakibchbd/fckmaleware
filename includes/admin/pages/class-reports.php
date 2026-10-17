<?php
/**
 * Reports: what happened over a period, computed from the findings table and
 * the activity log, with CSV/JSON exports and a printable view.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Findings;
use Fckmaleware\Health;

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

		Ui::header( $title, __( 'All figures are counted from this site\'s own records.', 'fckmaleware' ) );

		echo '<div class="fckmw-toolbar"><ul class="subsubsub">';
		$links = array();
		foreach ( self::PERIODS as $period ) {
			/* translators: %d: days */
			$links[] = '<li><a href="' . esc_url( Ui::url( 'reports', array( 'days' => $period ) ) ) . '"' . ( $period === $days ? ' class="current" aria-current="page"' : '' ) . '>' . esc_html( sprintf( __( 'Last %d days', 'fckmaleware' ), $period ) ) . '</a>';
		}
		echo implode( ' | </li>', $links ) . '</li></ul>'; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<button type="button" class="button fckmw-print">' . esc_html__( 'Print / save as PDF', 'fckmaleware' ) . '</button></div>';

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

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Current health score', 'fckmaleware' ), (string) $health['score'], $health['grade'] );
		Ui::stat( __( 'New findings', 'fckmaleware' ), (string) $new_total );
		Ui::stat( __( 'Scans completed', 'fckmaleware' ), (string) $sum( array( 'scan.complete', 'dbscan.complete' ) ) );
		Ui::stat( __( 'Files quarantined', 'fckmaleware' ), (string) $sum( array( 'quarantine.isolate', 'quarantine.auto' ) ) );
		Ui::stat( __( 'Files repaired', 'fckmaleware' ), (string) $sum( array( 'repair.official' ) ) );
		Ui::stat( __( 'Uploads blocked', 'fckmaleware' ), (string) $sum( array( 'upload.blocked' ) ) );
		Ui::stat( __( 'Re-infections', 'fckmaleware' ), (string) $sum( array( 'threat.reinfection' ) ), $sum( array( 'threat.reinfection' ) ) ? 'bad' : 'neutral' );
		Ui::stat( __( 'Signature updates', 'fckmaleware' ), (string) $sum( array( 'signatures.updated' ) ) );
		echo '</div>';

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'New findings by severity', 'fckmaleware' ) );
		self::bars( $new_by_severity, 'severity' );
		Ui::card_end();
		Ui::card_start( __( 'New findings by detection layer', 'fckmaleware' ) );
		self::bars( $new_by_source, 'source' );
		Ui::card_end();
		Ui::card_start( __( 'Most frequent rules', 'fckmaleware' ) );
		if ( ! $top_rules ) {
			echo '<p>' . esc_html__( 'No findings in this period.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<table class="widefat striped fckmw-table"><tbody>';
			foreach ( $top_rules as $rule ) {
				echo '<tr><td><code>' . esc_html( $rule['signature_id'] ) . '</code> ' . esc_html( $rule['signature_name'] ) . '</td><td class="fckmw-num">' . (int) $rule['n'] . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Ui::card_end();
		echo '</div>';

		Ui::card_start( __( 'Exports', 'fckmaleware' ) );
		echo '<div class="fckmw-actions">';
		foreach ( array( 'open' => __( 'Open findings (CSV)', 'fckmaleware' ), 'resolved' => __( 'Resolved findings (CSV)', 'fckmaleware' ), 'quarantined' => __( 'Quarantined findings (CSV)', 'fckmaleware' ) ) as $status => $label ) {
			Ui::form( 'export_findings', array( 'status' => $status ), 'fckmw-inline' );
			echo '<button class="button">' . esc_html( $label ) . '</button></form>';
		}
		Ui::form( 'export_activity', array(), 'fckmw-inline' );
		echo '<button class="button">' . esc_html__( 'Activity log (CSV)', 'fckmaleware' ) . '</button></form>';
		echo '</div>';
		Ui::card_end();
		Ui::footer();
	}

	/** Horizontal bar list; widths are proportional to the counts shown next to them. */
	private static function bars( array $rows, string $key ): void {
		if ( ! $rows ) {
			echo '<p>' . esc_html__( 'No findings in this period.', 'fckmaleware' ) . '</p>';
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
