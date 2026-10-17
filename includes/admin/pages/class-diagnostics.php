<?php
/**
 * Diagnostics: environment, resources, filesystem, cron, scanner and
 * integration status, recent plugin errors and a copyable report.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Diagnostics as Checks;

final class Diagnostics extends Page {

	public function render( string $title ): void {
		$sections = Checks::collect( $this->plugin );
		$tones    = array( 'good' => __( 'OK', 'fckmaleware' ), 'warn' => __( 'Check', 'fckmaleware' ), 'bad' => __( 'Problem', 'fckmaleware' ) );

		Ui::header( $title, __( 'Compatibility and health of this installation. Credentials, keys, absolute paths and environment variables are never shown or included in the report.', 'fckmaleware' ), '<button type="button" class="button" data-fckmw-copy="fckmw-report" data-copied="' . esc_attr__( 'Copied', 'fckmaleware' ) . '"><span class="dashicons dashicons-clipboard" aria-hidden="true"></span>' . esc_html__( 'Copy report', 'fckmaleware' ) . '</button>' );

		echo '<div class="fckmw-grid fckmw-grid-2">';
		foreach ( $sections as $section => $rows ) {
			Ui::card_start( $section );
			echo '<ul class="fckmw-statuslist">';
			foreach ( $rows as $row ) {
				echo '<li><span class="fckmw-statuslist-name">' . esc_html( $row[0] ) . '</span><span>' . ( isset( $tones[ $row[2] ] ) ? Ui::status( $row[1], $row[2] ) : esc_html( $row[1] ) ) . '</span></li>'; // phpcs:ignore WordPress.Security.EscapeOutput -- status() escapes.
			}
			echo '</ul>';
			Ui::card_end();
		}
		echo '</div>';

		Ui::card_start( __( 'Recent plugin errors', 'fckmaleware' ) );
		$errors = ActivityLog::query( array( 'failed' => true ), 1, 10 )['rows'];
		if ( ! $errors ) {
			Ui::empty_state( __( 'No failed operations recorded', 'fckmaleware' ) );
		} else {
			echo '<ul class="fckmw-events">';
			foreach ( $errors as $row ) {
				printf( '<li><span class="fckmw-event-icon fckmw-tone-warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span></span><span class="fckmw-event-text"><code>%1$s</code> %2$s</span><span class="fckmw-event-time">%3$s</span></li>', esc_html( (string) $row['type'] ), esc_html( (string) $row['message'] ), Ui::when( (int) $row['created_at'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput
			}
			echo '</ul><p><a class="fckmw-more" href="' . esc_url( Ui::url( 'activity', array( 'type' => 'failed' ) ) ) . '">' . esc_html__( 'All failed operations', 'fckmaleware' ) . '</a></p>';
		}
		Ui::card_end();

		Ui::disclosure_start( __( 'Text report for support', 'fckmaleware' ) );
		echo '<pre class="fckmw-code" id="fckmw-report">' . esc_html( Checks::report( $this->plugin ) ) . '</pre>';
		Ui::disclosure_end();
		Ui::footer();
	}
}
