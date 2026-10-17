<?php
/**
 * Security health score: 100 minus explained deductions, computed only from
 * real state (open findings, scan freshness, protection settings, hardening
 * results, signature update health). Every deduction is listed so the number
 * can be verified.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Health {

	/**
	 * @return array{score: int, grade: string, deductions: array<int, array{points: int, reason: string}>}
	 */
	public static function compute( Plugin $plugin ): array {
		$deductions = array();
		$add        = static function ( int $points, string $reason ) use ( &$deductions ): void {
			if ( $points > 0 ) {
				$deductions[] = array( 'points' => $points, 'reason' => $reason );
			}
		};

		$counts = $plugin->findings()->open_counts();
		$add( min( 50, 25 * $counts['critical'] ), sprintf( /* translators: %d: count */ _n( '%d open critical finding', '%d open critical findings', $counts['critical'], 'fckmaleware' ), $counts['critical'] ) );
		$add( min( 30, 10 * $counts['high'] ), sprintf( /* translators: %d: count */ _n( '%d open high-severity finding', '%d open high-severity findings', $counts['high'], 'fckmaleware' ), $counts['high'] ) );
		$add( min( 15, 3 * $counts['medium'] ), sprintf( /* translators: %d: count */ _n( '%d open medium-severity finding', '%d open medium-severity findings', $counts['medium'], 'fckmaleware' ), $counts['medium'] ) );

		$last = Store::get( 'fckmw_last_scan', array() );
		$age  = is_array( $last ) && ! empty( $last['finished'] ) ? time() - (int) $last['finished'] : null;
		if ( null === $age ) {
			$add( 20, __( 'No complete scan has run yet', 'fckmaleware' ) );
		} elseif ( $age > 14 * DAY_IN_SECONDS ) {
			$add( 15, __( 'Last complete scan is older than 14 days', 'fckmaleware' ) );
		} elseif ( $age > 7 * DAY_IN_SECONDS ) {
			$add( 5, __( 'Last complete scan is older than 7 days', 'fckmaleware' ) );
		}

		$settings = Settings::all();
		if ( 'off' === $settings['schedule'] ) {
			$add( 10, __( 'Scheduled scans are off', 'fckmaleware' ) );
		}
		if ( ! $settings['realtime_uploads'] || ! $settings['realtime_installs'] ) {
			$add( 5, __( 'Event-driven protection is partly disabled', 'fckmaleware' ) );
		}

		$updates = $plugin->signature_updater()->state();
		if ( $settings['signature_updates'] && $updates['failures'] >= 3 ) {
			$add( 5, __( 'Signature updates are failing', 'fckmaleware' ) );
		}

		$hardening = Store::get( 'fckmw_hardening_summary', array() );
		if ( is_array( $hardening ) && isset( $hardening['fail'] ) ) {
			$add( min( 15, 5 * (int) $hardening['fail'] + (int) $hardening['warn'] ), sprintf( /* translators: 1: failed, 2: warnings */ __( 'Hardening: %1$d failed checks, %2$d warnings', 'fckmaleware' ), $hardening['fail'], $hardening['warn'] ) );
		}

		$score = max( 0, 100 - array_sum( array_column( $deductions, 'points' ) ) );
		$grade = $score >= 90 ? 'good' : ( $score >= 70 ? 'warn' : 'bad' );
		return array( 'score' => $score, 'grade' => $grade, 'deductions' => $deductions );
	}
}
