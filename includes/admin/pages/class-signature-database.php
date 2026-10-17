<?php
/**
 * Signature Database: the active rule set, signed updates and rollback.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Settings;
use Fckmaleware\SignatureUpdater;

final class SignatureDatabase extends Page {

	private const PER_PAGE = 50;

	public function render( string $title ): void {
		$sigs    = $this->plugin->signatures();
		$updater = $this->plugin->signature_updater();
		$state   = $updater->state();

		Ui::header( $title, __( 'Signatures are the plugin\'s own rules, written and tested against clean WordPress code before release. Updates are downloaded only when signed with an FCK Malware key built into the plugin.', 'fckmaleware' ) );

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Active version', 'fckmaleware' ), $sigs->version(), 'neutral', $state['installed'] ? __( 'downloaded update', 'fckmaleware' ) : __( 'bundled with the plugin', 'fckmaleware' ) );
		Ui::stat( __( 'Pattern signatures', 'fckmaleware' ), number_format_i18n( $sigs->count() ) );
		Ui::stat( __( 'Known-malware hashes', 'fckmaleware' ), number_format_i18n( $sigs->hash_count() ) );
		Ui::stat( __( 'Rejected rules', 'fckmaleware' ), (string) count( $sigs->invalid() ), $sigs->invalid() ? 'warn' : 'good', __( 'failed validation', 'fckmaleware' ) );
		echo '</div>';

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Updates', 'fckmaleware' ) );
		echo '<dl class="fckmw-dl">';
		echo '<dt>' . esc_html__( 'Automatic updates', 'fckmaleware' ) . '</dt><dd>' . esc_html( Settings::get( 'signature_updates' ) ? __( 'On (twice daily)', 'fckmaleware' ) : __( 'Off', 'fckmaleware' ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Feed', 'fckmaleware' ) . '</dt><dd><code>' . esc_html( SignatureUpdater::feed_url() ) . '</code></dd>';
		echo '<dt>' . esc_html__( 'Trusted keys', 'fckmaleware' ) . '</dt><dd><code>' . esc_html( implode( ', ', array_keys( SignatureUpdater::keys() ) ) ) . '</code></dd>';
		echo '<dt>' . esc_html__( 'Last check', 'fckmaleware' ) . '</dt><dd>' . esc_html( Ui::ago( (int) $state['last_check'] ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Last success', 'fckmaleware' ) . '</dt><dd>' . esc_html( Ui::ago( (int) $state['last_success'] ) ) . '</dd>';
		if ( $state['last_error'] ) {
			/* translators: 1: error, 2: failures */
			echo '<dt>' . esc_html__( 'Last error', 'fckmaleware' ) . '</dt><dd>' . Ui::badge( __( 'Failed', 'fckmaleware' ), 'warn' ) . ' ' . esc_html( sprintf( __( '%1$s (%2$d in a row)', 'fckmaleware' ), $state['last_error'], $state['failures'] ) ) . '</dd>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '</dl><div class="fckmw-actions">';
		Ui::action_button( 'signatures', __( 'Check for updates now', 'fckmaleware' ), array( 'op' => 'update', 'return' => 'signatures' ), 'button button-primary' );
		if ( $state['installed'] ) {
			Ui::action_button( 'signatures', __( 'Roll back to previous version', 'fckmaleware' ), array( 'op' => 'rollback', 'return' => 'signatures' ), 'button', __( 'Remove the newest downloaded signature database and use the previous one?', 'fckmaleware' ) );
		}
		echo '</div>';
		if ( $state['installed'] ) {
			echo '<h4>' . esc_html__( 'Installed versions', 'fckmaleware' ) . '</h4><ul class="fckmw-list">';
			foreach ( array_reverse( $state['installed'] ) as $entry ) {
				/* translators: 1: version, 2: count, 3: date, 4: key */
				echo '<li>' . esc_html( sprintf( __( '%1$s: %2$d signatures, installed %3$s, signed by %4$s', 'fckmaleware' ), $entry['version'], $entry['count'], Ui::datetime( (int) $entry['installed'] ), $entry['key'] ) ) . '</li>';
			}
			echo '</ul>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Problems', 'fckmaleware' ) );
		$problems = false;
		foreach ( $sigs->invalid() as $id => $why ) {
			$problems = true;
			echo '<p>' . Ui::badge( __( 'Rejected', 'fckmaleware' ), 'warn' ) . ' <code>' . esc_html( (string) $id ) . '</code> ' . esc_html( (string) $why ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		$last = (array) \Fckmaleware\Store::get( 'fckmw_last_scan', array() );
		foreach ( (array) ( $last['pattern_errors'] ?? array() ) as $id => $count ) {
			$problems = true;
			/* translators: %d: count */
			echo '<p>' . Ui::badge( __( 'Runtime error', 'fckmaleware' ), 'warn' ) . ' <code>' . esc_html( (string) $id ) . '</code> ' . esc_html( sprintf( _n( 'In the last complete scan the pattern engine gave up on this rule for %d file (backtracking limit), so that file was not checked by it.', 'In the last complete scan the pattern engine gave up on this rule for %d files (backtracking limit), so those files were not checked by it.', (int) $count, 'fckmaleware' ), (int) $count ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		if ( ! $problems ) {
			echo '<p>' . esc_html__( 'Every rule passed validation (syntax, size and a backtracking stress test), and no rule hit the pattern engine\'s limits in the last complete scan.', 'fckmaleware' ) . '</p>';
		}
		Ui::card_end();
		echo '</div>';

		$all    = array_merge( array_values( $sigs->all() ), array_values( $sigs->hash_signatures() ) );
		$search = strtolower( sanitize_text_field( (string) self::query( 's' ) ) );
		if ( '' !== $search ) {
			$all = array_values(
				array_filter(
					$all,
					static function ( array $sig ) use ( $search ): bool {
						return false !== strpos( strtolower( $sig['id'] . ' ' . $sig['name'] . ' ' . $sig['family'] . ' ' . $sig['category'] ), $search );
					}
				)
			);
		}
		$paged = max( 1, absint( self::query( 'paged', 1 ) ) );

		Ui::card_start( __( 'Rules', 'fckmaleware' ) );
		echo '<form method="get" class="fckmw-filters"><input type="hidden" name="page" value="' . esc_attr( Ui::SLUG . '-signatures' ) . '"><label class="screen-reader-text" for="fckmw-sig-search">' . esc_html__( 'Search signatures', 'fckmaleware' ) . '</label><input type="search" id="fckmw-sig-search" name="s" value="' . esc_attr( $search ) . '"> <button class="button">' . esc_html__( 'Search', 'fckmaleware' ) . '</button></form>';
		echo '<table class="widefat striped fckmw-table"><thead><tr><th>' . esc_html__( 'ID', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Name', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Family', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Severity', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Confidence', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Applies to', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Source', 'fckmaleware' ) . '</th></tr></thead><tbody>';
		foreach ( array_slice( $all, ( $paged - 1 ) * self::PER_PAGE, self::PER_PAGE ) as $sig ) {
			echo '<tr><td><code>' . esc_html( $sig['id'] ) . '</code></td><td>' . esc_html( $sig['name'] ) . ( $sig['description'] ? '<br><span class="description">' . esc_html( $sig['description'] ) . '</span>' : '' ) . '</td><td>' . esc_html( $sig['family'] ) . '</td><td>' . Ui::severity( $sig['severity'] ) . '</td><td class="fckmw-num">' . (int) $sig['confidence'] . '</td><td>' . esc_html( implode( ', ', $sig['targets'] ) . ' · ' . $sig['technique'] ) . '</td><td>' . esc_html( $sig['source'] . ( $sig['license'] ? ' (' . $sig['license'] . ')' : '' ) ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '</tbody></table>';
		Ui::pagination( count( $all ), self::PER_PAGE, $paged );
		Ui::card_end();
		Ui::footer();
	}
}
