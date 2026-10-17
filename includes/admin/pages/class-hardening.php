<?php
/**
 * Security Hardening: optional rules (each with risk, compatibility and
 * rollback notes) and report-only checks.
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

		Ui::header( $title, __( 'Every rule is off until you turn it on, and turning it off undoes it. Checks only report; they never change the site.', 'fckmaleware' ) );

		echo '<div class="fckmw-toolbar">';
		/* translators: 1: passing, 2: total */
		echo '<p><strong>' . esc_html( sprintf( __( '%1$d of %2$d applicable items pass.', 'fckmaleware' ), $score['pass'], $score['total'] ) ) . '</strong></p>';
		Ui::action_button( 'hardening_check', __( 'Re-run checks', 'fckmaleware' ), array( 'return' => 'hardening' ) );
		echo '</div>';

		foreach ( array( true => __( 'Rules', 'fckmaleware' ), false => __( 'Checks', 'fckmaleware' ) ) as $toggle => $heading ) {
			echo '<h2>' . esc_html( $heading ) . '</h2><div class="fckmw-rules">';
			foreach ( $catalog as $id => $rule ) {
				if ( (bool) $rule['toggle'] !== (bool) $toggle ) {
					continue;
				}
				$item = $status[ $id ] ?? array( 'state' => 'unknown', 'detail' => '' );
				Ui::card_start( '', 'fckmw-rule' );
				echo '<div class="fckmw-rule-head"><h3>' . esc_html( $rule['title'] ) . '</h3>' . Ui::state( $item['state'] ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<p class="fckmw-rule-detail">' . esc_html( $item['detail'] ) . '</p>';
				echo '<p>' . esc_html( $rule['description'] ) . '</p>';
				echo '<details><summary>' . esc_html__( 'Risk, compatibility and rollback', 'fckmaleware' ) . '</summary><dl class="fckmw-dl">';
				echo '<dt>' . esc_html__( 'Why it matters', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['risk'] ) . '</dd>';
				echo '<dt>' . esc_html__( 'Compatibility', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['compatibility'] ) . '</dd>';
				echo '<dt>' . esc_html__( 'Undo', 'fckmaleware' ) . '</dt><dd>' . esc_html( $rule['rollback'] ) . '</dd>';
				echo '</dl></details>';
				if ( $rule['toggle'] ) {
					$on = Rules::is_enabled( $id );
					Ui::action_button(
						'hardening',
						$on ? __( 'Turn off', 'fckmaleware' ) : __( 'Turn on', 'fckmaleware' ),
						array( 'rule' => $id, 'on' => $on ? '0' : '1', 'return' => 'hardening' ),
						$on ? 'button' : 'button button-primary',
						$on ? '' : sprintf( /* translators: %s: compatibility note */ __( 'Compatibility: %s Turn this rule on?', 'fckmaleware' ), $rule['compatibility'] )
					);
				}
				Ui::card_end();
			}
			echo '</div>';
		}
		Ui::footer();
	}
}
