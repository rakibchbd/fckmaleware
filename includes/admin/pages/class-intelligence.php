<?php
/**
 * AI Intelligence: the local heuristic engine (always on, no network) and
 * the optional external advisory reviewer.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Ai\Reviewer;
use Fckmaleware\Detection\Heuristics;
use Fckmaleware\Settings;
use Fckmaleware\Store;

final class Intelligence extends Page {

	public function render( string $title ): void {
		global $wpdb;
		$settings = Settings::all();
		$table    = \Fckmaleware\Findings::table();
		$summary  = Reviewer::summary();
		$stats    = Reviewer::stats();
		$reason   = Reviewer::unavailable();

		Ui::header( $title, __( 'Detection decisions are made by deterministic local engines that work without any external service. An external AI model can be asked for a second opinion on single findings; it is advisory, sees only a redacted excerpt and can never change, delete or execute anything. Nothing it suggests is run automatically.', 'fckmaleware' ) );

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Local heuristic engine', 'fckmaleware' ) );
		/* translators: 1: on/off, 2: threshold */
		echo '<p>' . Ui::badge( $settings['heuristics'] ? __( 'On', 'fckmaleware' ) : __( 'Off', 'fckmaleware' ), $settings['heuristics'] ? 'good' : 'warn' ) . ' ' . esc_html( sprintf( __( 'Reporting threshold %d. A file is reported only when its score reaches the threshold, its strongest indicator weighs at least 40, and it has two or more indicators or one of 80+. Scores of 85+ are labelled malicious, lower ones suspicious.', 'fckmaleware' ), $settings['heuristic_threshold'] ) ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<p>' . esc_html__( 'Runs on PHP files that no signature matched. It parses the code into tokens (it never runs it), follows request input through variables within each function, and scores what the code does. Weak indicators alone cannot raise a finding.', 'fckmaleware' ) . '</p>';
		$open = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status = 'open' AND source = 'heuristic'" ); // phpcs:ignore WordPress.DB
		$all  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE source = 'heuristic'" ); // phpcs:ignore WordPress.DB
		/* translators: 1: open, 2: total */
		echo '<p class="description">' . esc_html( sprintf( __( '%1$d open heuristic findings, %2$d in total.', 'fckmaleware' ), $open, $all ) ) . '</p>';
		echo '<details><summary>' . esc_html( sprintf( /* translators: %d: count */ __( 'The %d indicators and their weights', 'fckmaleware' ), count( Heuristics::INDICATORS ) ) ) . '</summary><table class="widefat striped fckmw-table"><tbody>';
		foreach ( Heuristics::INDICATORS as $indicator ) {
			echo '<tr><td class="fckmw-num">' . (int) $indicator[0] . '</td><td>' . esc_html( $indicator[1] ) . '</td></tr>';
		}
		echo '</tbody></table></details>';
		Ui::card_end();

		Ui::card_start( __( 'External AI review', 'fckmaleware' ) );
		$providers = array( 'none' => __( 'Off', 'fckmaleware' ), 'anthropic' => 'Anthropic Claude', 'openai_compatible' => __( 'OpenAI-compatible endpoint (e.g. a local model)', 'fckmaleware' ) );
		echo '<p>' . Ui::badge( null === $reason ? __( 'Ready', 'fckmaleware' ) : __( 'Not available', 'fckmaleware' ), null === $reason ? 'good' : 'neutral' ) . ' ' . esc_html( $providers[ $settings['ai_provider'] ] ?? '' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		if ( null !== $reason ) {
			echo '<p class="description">' . esc_html( $reason ) . '</p>';
		}
		echo '<p>' . esc_html__( 'What is sent: detection metadata (rule, layer, local verdict, line, evidence, file path) and a code excerpt of at most the configured number of characters. Before sending, the site path, domain and table prefix are replaced with placeholders, and database credentials, password/secret/token assignments, private keys, common API key formats, credentials in URLs and e-mail addresses are redacted. For wp-config.php only three lines around the match are used. Nothing is sent automatically: each review is started by an administrator.', 'fckmaleware' ) . '</p>';
		$test = Store::get( 'fckmw_ai_test', array() );
		if ( is_array( $test ) && isset( $test['ok'] ) ) {
			/* translators: %s: time */
			echo '<p>' . Ui::status( $test['ok'] ? __( 'Last test passed', 'fckmaleware' ) : __( 'Last test failed', 'fckmaleware' ), $test['ok'] ? 'good' : 'bad' ) . ' <span class="description">' . esc_html( $test['message'] . ' · ' . Ui::ago( (int) $test['time'] ) ) . '</span></p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '<div class="fckmw-actions"><a class="button" href="' . esc_url( Ui::url( 'settings' ) . '#ai' ) . '">' . esc_html__( 'Configure', 'fckmaleware' ) . '</a>';
		if ( 'none' !== $settings['ai_provider'] && $settings['ai_consent'] ) {
			Ui::action_button( 'ai_test', __( 'Test connection', 'fckmaleware' ), array( 'return' => 'ai' ), 'button', __( 'Send a fixed sample ("<?php echo \'hello world\';") to the provider? No data from this site is included. It counts as one review towards the daily limit.', 'fckmaleware' ) );
		}
		echo '</div>';
		Ui::card_end();

		Ui::card_start( __( 'AI review results', 'fckmaleware' ) );
		if ( ! $summary['reviewed'] ) {
			echo '<p>' . esc_html__( 'No findings have been reviewed by an external model.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<div class="fckmw-stats fckmw-stats-compact">';
			Ui::stat( __( 'Reviewed', 'fckmaleware' ), (string) $summary['reviewed'] );
			Ui::stat( __( 'Agreed with local verdict', 'fckmaleware' ), (string) $summary['agree'] );
			Ui::stat( __( 'Malicious', 'fckmaleware' ), (string) $summary['malicious'] );
			Ui::stat( __( 'Suspicious', 'fckmaleware' ), (string) $summary['suspicious'] );
			Ui::stat( __( 'Benign', 'fckmaleware' ), (string) $summary['benign'] );
			Ui::stat( __( 'Unknown', 'fckmaleware' ), (string) $summary['unknown'] );
			echo '</div>';
			echo '<p class="description">' . esc_html__( 'A "benign" answer does not dismiss a finding. Review it yourself and use "Accept as safe" if you agree.', 'fckmaleware' ) . '</p>';
		}
		/* translators: 1: month, 2: requests, 3: failures, 4: tokens, 5: cost, 6: today, 7: limit */
		echo '<p class="description">' . esc_html( sprintf( __( 'Usage in %1$s: %2$d requests (%3$d failed), %4$s tokens, estimated $%5$s. Today: %6$d of %7$d allowed.', 'fckmaleware' ), $stats['month'], $stats['requests'], $stats['failures'], number_format_i18n( (int) $stats['tokens'] ), number_format( (float) $stats['cost_usd'], 4 ), $stats['today'], $settings['ai_daily_limit'] ) ) . '</p>';
		Ui::card_end();
		echo '</div>';

		Ui::footer();
	}
}
