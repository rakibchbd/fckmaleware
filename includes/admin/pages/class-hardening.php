<?php
/**
 * Security Hardening: optional rules and report-only checks grouped by
 * area, each with its current and recommended state, risk level,
 * compatibility notes and apply / test / revert actions.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Hardening as Rules;

final class Hardening extends Page {

	public function render( string $title ): void {
		$hardening = $this->plugin->hardening();
		$status    = $hardening->status();
		$score     = $hardening->score();
		$catalog   = Rules::catalog();
		$server    = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		$levels    = array( 'high' => array( __( 'High risk', 'fckmaleware' ), 'bad' ), 'medium' => array( __( 'Medium risk', 'fckmaleware' ), 'warn' ), 'low' => array( __( 'Low risk', 'fckmaleware' ), 'neutral' ) );

		ob_start();
		Ui::action_button( 'hardening_check', __( 'Re-run checks', 'fckmaleware' ), array( 'return' => 'hardening' ) );
		$actions = (string) ob_get_clean();

		Ui::header( $title, __( 'Every rule is off until you turn it on, and turning it off undoes it. Checks only report; they never change the site. Server configuration outside this site is never modified.', 'fckmaleware' ), $actions );

		/* translators: 1: passing, 2: total */
		Ui::callout( sprintf( __( '%1$d of %2$d applicable items pass.', 'fckmaleware' ), $score['pass'], $score['total'] ), $score['pass'] === $score['total'] ? 'success' : 'info' );

		foreach ( Rules::categories() as $category => $heading ) {
			$ids = array_keys(
				array_filter(
					$catalog,
					static function ( array $rule ) use ( $category ): bool {
						return $rule['category'] === $category;
					}
				)
			);
			if ( ! $ids ) {
				continue;
			}
			echo '<h2 class="fckmw-section-title">' . esc_html( $heading ) . '</h2><div class="fckmw-rules">';
			foreach ( $ids as $id ) {
				$rule = $catalog[ $id ];
				$item = $status[ $id ] ?? array( 'state' => 'unknown', 'detail' => '' );
				$on   = $rule['toggle'] && Rules::is_enabled( $id );
				Ui::card_start( '', 'fckmw-rule' );
				echo '<div class="fckmw-rule-head"><h3>' . esc_html( $rule['title'] ) . '</h3>' . Ui::state( $item['state'] ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<div class="fckmw-rule-meta">' . Ui::badge( $levels[ $rule['level'] ][0], $levels[ $rule['level'] ][1] ) . Ui::badge( $rule['toggle'] ? __( 'Rule', 'fckmaleware' ) : __( 'Check (report only)', 'fckmaleware' ), 'info' ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<p>' . esc_html( $rule['description'] ) . '</p>';
				echo '<dl class="fckmw-rule-state"><dt>' . esc_html__( 'Current', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['toggle'] ? ( $on ? __( 'On', 'fckmaleware' ) : __( 'Off', 'fckmaleware' ) ) . ( '' !== $item['detail'] ? ' · ' . $item['detail'] : '' ) : $item['detail'] ) . '</dd>';
				echo '<dt>' . esc_html__( 'Recommended', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['toggle'] ? __( 'On, unless the compatibility note applies to this site', 'fckmaleware' ) : __( 'Pass', 'fckmaleware' ) ) . '</dd></dl>';
				echo '<details><summary>' . esc_html__( 'Why it matters, compatibility and undo', 'fckmaleware' ) . '</summary><dl class="fckmw-dl">';
				echo '<dt>' . esc_html__( 'Why it matters', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['risk'] ) . '</dd>';
				echo '<dt>' . esc_html__( 'Compatibility', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['compatibility'] ) . '</dd>';
				echo '<dt>' . esc_html__( 'Undo', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['rollback'] ) . '</dd>';
				echo '</dl></details>';
				if ( 'uploads_php' === $id && false !== strpos( $server, 'nginx' ) ) {
					Ui::callout( __( 'This server reports nginx, which ignores .htaccess: turning the rule on writes the file but does not protect the site. Ask your host to add the nginx rule above.', 'fckmaleware' ), 'warning' );
				}
				if ( $rule['toggle'] ) {
					echo '<div class="fckmw-actions">';
					Ui::action_button(
						'hardening',
						$on ? __( 'Revert', 'fckmaleware' ) : __( 'Apply', 'fckmaleware' ),
						array( 'rule' => $id, 'on' => $on ? '0' : '1', 'return' => 'hardening' ),
						$on ? 'button' : 'button button-primary',
						$on ? '' : sprintf( /* translators: %s: compatibility note */ __( 'Compatibility: %s Apply this rule?', 'fckmaleware' ), $rule['compatibility'] )
					);
					if ( 'uploads_php' === $id ) {
						Ui::action_button( 'hardening', __( 'Test', 'fckmaleware' ), array( 'rule' => $id, 'op' => 'test', 'return' => 'hardening' ), 'button', __( 'A harmless test file that only prints a marker is written to uploads, requested over HTTP and deleted immediately. Run the test?', 'fckmaleware' ) );
					}
					echo '</div>';
					if ( 'uploads_php' === $id ) {
						echo '<p class="description">' . esc_html__( 'uploads/.htaccess is backed up to the private data folder before every change.', 'fckmaleware' ) . '</p>';
					}
				}
				Ui::card_end();
			}
			echo '</div>';
		}
		Ui::footer();
	}
}
