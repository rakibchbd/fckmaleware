<?php
/**
 * Threat Intelligence: where the active rules come from, how new ones reach
 * this site, and how this site can contribute (always opt-in, reviewed by the
 * person sending it).
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Feedback;
use Fckmaleware\Settings;

final class ThreatIntel extends Page {

	public function render( string $title ): void {
		$sigs = $this->plugin->signatures();

		Ui::header( $title, __( 'New rules are collected from openly licensed sources and community reports, tested against a corpus of clean WordPress code, reviewed by a person, then signed and published. Nothing collected automatically reaches this site without that review.', 'fckmaleware' ) );

		Ui::card_start( __( 'Pipeline', 'fckmaleware' ) );
		$steps = array(
			__( 'Collect', 'fckmaleware' )   => __( 'Open feeds (abuse.ch URLhaus and MalwareBazaar, CC0), YARA rules from Neo23x0 signature-base (DRL 1.1) converted where possible, and community reports.', 'fckmaleware' ),
			__( 'Validate', 'fckmaleware' )  => __( 'Syntax, size and backtracking stress tests; unsupported rules are dropped with a reason.', 'fckmaleware' ),
			__( 'Test', 'fckmaleware' )      => __( 'Each candidate runs against tens of thousands of clean core, plugin and theme files; any match rejects it.', 'fckmaleware' ),
			__( 'Approve', 'fckmaleware' )   => __( 'A maintainer reviews each candidate and records who approved it.', 'fckmaleware' ),
			__( 'Sign', 'fckmaleware' )      => __( 'The database is signed with an Ed25519 key; this site trusts only the public keys built into the plugin.', 'fckmaleware' ),
			__( 'Update', 'fckmaleware' )    => __( 'This site checks the feed twice daily, verifies signature, hash, expiry and version, and keeps the previous versions for rollback.', 'fckmaleware' ),
		);
		echo '<ol class="fckmw-pipeline">';
		foreach ( $steps as $step => $text ) {
			echo '<li><strong>' . esc_html( $step ) . '</strong><span>' . esc_html( $text ) . '</span></li>';
		}
		echo '</ol>';
		echo '<p class="description">' . esc_html__( 'Not integrated: WPScan and Patchstack vulnerability data (commercial licences) and Imunify360\'s own signatures (proprietary). Imunify360 results can be imported from the agent on this server instead, see Integrations.', 'fckmaleware' ) . '</p>';
		Ui::card_end();

		$updates = $this->plugin->signature_updater()->state();
		$imunify = $this->plugin->integrations()->summary();
		Ui::card_start( __( 'Intelligence sources on this site', 'fckmaleware' ), '', __( 'Only sources that are actually implemented are listed. Each indicator in the database keeps its source and licence.', 'fckmaleware' ) );
		echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><th scope="col">' . esc_html__( 'Source', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Status', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Last synchronisation', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Verification', 'fckmaleware' ) . '</th></tr></thead><tbody>';
		echo '<tr><td><strong>' . esc_html__( 'FCK Malware signed feed', 'fckmaleware' ) . '</strong><span class="fckmw-sub">' . esc_html( \Fckmaleware\SignatureUpdater::feed_url() ) . '</span></td><td>' . ( Settings::get( 'signature_updates' ) ? ( $updates['last_error'] ? Ui::status( __( 'Last check failed', 'fckmaleware' ), 'warn' ) : Ui::status( __( 'Active', 'fckmaleware' ), 'good' ) ) : Ui::status( __( 'Off', 'fckmaleware' ), 'off' ) ) . '</td><td>' . Ui::when( (int) $updates['last_success'] ) . '</td><td>' . esc_html__( 'Ed25519 signature, SHA-256, expiry and anti-replay', 'fckmaleware' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
		/* translators: %s: version */
		echo '<tr><td><strong>' . esc_html__( 'Bundled database', 'fckmaleware' ) . '</strong><span class="fckmw-sub">' . esc_html( sprintf( __( 'Shipped with FCK Malware %s', 'fckmaleware' ), FCKMW_VERSION ) ) . '</span></td><td>' . Ui::status( __( 'Always available', 'fckmaleware' ), 'good' ) . '</td><td>—</td><td>' . esc_html__( 'Covered by the plugin\'s integrity manifest', 'fckmaleware' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<tr><td><strong>' . esc_html__( 'Server scanner results', 'fckmaleware' ) . '</strong><span class="fckmw-sub">' . esc_html__( 'Imunify360 / ImunifyAV malicious-file list', 'fckmaleware' ) . '</span></td><td>' . Ui::status( $imunify['label'], $imunify['tone'] ) . '</td><td>' . Ui::when( (int) \Fckmaleware\Store::get( 'fckmw_imunify_last_sync', 0 ) ) . '</td><td>' . esc_html__( 'Read from the local agent; file paths limited to this site', 'fckmaleware' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '</tbody></table></div>';
		Ui::card_end();

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Sources in the active database', 'fckmaleware' ) );
		$sources = array();
		foreach ( array_merge( $sigs->all(), array_values( $sigs->hash_signatures() ) ) as $sig ) {
			$key             = ( $sig['source'] ?: __( 'FCK Malware', 'fckmaleware' ) ) . ( $sig['license'] ? ' (' . $sig['license'] . ')' : '' );
			$sources[ $key ] = ( $sources[ $key ] ?? 0 ) + 1;
		}
		arsort( $sources );
		echo '<table class="fckmw-table"><tbody>';
		foreach ( $sources as $source => $count ) {
			echo '<tr><td>' . esc_html( $source ) . '</td><td class="fckmw-num">' . (int) $count . '</td></tr>';
		}
		echo '</tbody></table>';
		/* translators: %s: version */
		echo '<p class="description">' . esc_html( sprintf( __( 'Database %s.', 'fckmaleware' ), $sigs->version() ) ) . ' <a href="' . esc_url( Ui::url( 'signatures' ) ) . '">' . esc_html__( 'Browse rules', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( __( 'Contribute from this site', 'fckmaleware' ) );
		echo '<p>' . esc_html__( 'Nothing is sent from this site automatically. You can help in two ways:', 'fckmaleware' ) . '</p><ul class="fckmw-list">';
		echo '<li>' . esc_html__( 'On any finding, "Report false positive" or "Confirm malware" opens a pre-filled GitHub issue in your browser. It contains the rule, the component and its version, the path inside that component and the file\'s SHA-256 hash; you see and edit everything before submitting, and no code is included unless you add it.', 'fckmaleware' ) . '</li>';
		echo '<li>' . esc_html__( 'Download anonymous detection statistics (per rule ID, how many findings are open, accepted, quarantined or resolved, plus the plugin, signature and WordPress versions; no paths, code, URLs or user data) and attach them to an issue if you want to.', 'fckmaleware' ) . '</li></ul>';
		/* translators: %s: id */
		echo '<p class="description">' . esc_html( sprintf( __( 'Anonymous site identifier used in exports: %s (random, not derived from your site).', 'fckmaleware' ), Feedback::anonymous_id() ) ) . '</p>';
		Ui::form( 'feedback_export', array(), 'fckmw-inline' );
		echo '<button class="button">' . esc_html__( 'Download statistics (JSON)', 'fckmaleware' ) . '</button></form> ';
		echo '<a class="button" href="' . esc_url( 'https://github.com/' . Feedback::REPOSITORY . '/issues' ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Open issues on GitHub', 'fckmaleware' ) . '</a>';
		Ui::card_end();
		echo '</div>';

		if ( ! Settings::get( 'signature_updates' ) ) {
			Ui::callout( __( 'Signature updates are off, so new rules do not reach this site. Turn them on in Settings.', 'fckmaleware' ), 'warning' );
		}
		Ui::footer();
	}
}
