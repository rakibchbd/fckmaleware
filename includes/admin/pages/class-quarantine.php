<?php
/**
 * Quarantine: isolated files and pre-repair backups, restore points.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Settings;

final class Quarantine extends Page {

	public function render( string $title ): void {
		$quarantine = $this->plugin->quarantine();
		$items      = $quarantine->all();
		$stats      = $quarantine->stats();
		$retention  = (int) Settings::get( 'quarantine_retention' );

		Ui::header( $title, __( 'Quarantined files are stored compressed in a randomly named folder under uploads (deny rules, no executable extension) and verified before the original is removed. Restoring puts the exact bytes, permissions and timestamp back.', 'fckmaleware' ) );

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Quarantined files', 'fckmaleware' ), (string) $stats['quarantined'] );
		Ui::stat( __( 'Repair backups', 'fckmaleware' ), (string) $stats['backups'] );
		Ui::stat( __( 'Storage used', 'fckmaleware' ), size_format( $stats['bytes'] ) ?: '0 B', 'neutral', __( 'original size', 'fckmaleware' ) );
		Ui::stat( __( 'Retention', 'fckmaleware' ), $retention ? sprintf( /* translators: %d: days */ _n( '%d day', '%d days', $retention, 'fckmaleware' ), $retention ) : __( 'Kept until deleted', 'fckmaleware' ), 'neutral', '', Ui::url( 'settings' ) );
		echo '</div>';

		Ui::card_start( __( 'Stored files', 'fckmaleware' ) );
		if ( ! $items ) {
			echo '<p>' . esc_html__( 'Nothing is in quarantine.', 'fckmaleware' ) . '</p>';
		} else {
			uasort(
				$items,
				static function ( array $a, array $b ): int {
					return (int) $b['time'] <=> (int) $a['time'];
				}
			);
			echo '<table class="widefat striped fckmw-table"><thead><tr><th>' . esc_html__( 'Original location', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Type', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Reason', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Size', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Stored', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Actions', 'fckmaleware' ) . '</th></tr></thead><tbody>';
			foreach ( $items as $key => $item ) {
				$context = (array) ( $item['context'] ?? array() );
				$reason  = ! empty( $context['signature'] ) ? (string) $context['signature'] : ( 'repair' === ( $context['reason'] ?? '' ) ? __( 'Backup before repair', 'fckmaleware' ) : (string) ( $context['reason'] ?? '' ) );
				$user    = get_userdata( (int) ( $item['user'] ?? 0 ) );
				echo '<tr>';
				echo '<td class="fckmw-file"><code>' . esc_html( (string) $item['file'] ) . '</code><br><span class="description fckmw-mono">' . esc_html( 'sha256 ' . substr( (string) $item['hash'], 0, 16 ) . '…' ) . '</span></td>';
				echo '<td>' . Ui::badge( 'backup' === ( $item['kind'] ?? 'quarantine' ) ? __( 'Backup', 'fckmaleware' ) : __( 'Quarantined', 'fckmaleware' ), 'backup' === ( $item['kind'] ?? 'quarantine' ) ? 'neutral' : 'warn' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<td>' . esc_html( $reason ) . ( ! empty( $context['finding'] ) ? ' <span class="description">#' . (int) $context['finding'] . '</span>' : '' ) . '</td>';
				echo '<td>' . esc_html( size_format( (int) $item['size'] ) ?: '0 B' ) . '</td>';
				echo '<td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $item['time'] ) ) . ( $user ? '<br><span class="description">' . esc_html( $user->user_login ) . '</span>' : '' ) . '</td>';
				echo '<td class="fckmw-actions">';
				Ui::action_button( 'quarantine_item', __( 'Restore', 'fckmaleware' ), array( 'key' => $key, 'op' => 'restore', 'return' => 'quarantine' ), 'button', __( 'Put this file back in its original location? If it is malicious, the site will be infected again.', 'fckmaleware' ) );
				Ui::action_button( 'quarantine_item', __( 'Delete permanently', 'fckmaleware' ), array( 'key' => $key, 'op' => 'delete', 'return' => 'quarantine' ), 'button button-link-delete', __( 'Permanently delete the stored copy? This cannot be undone.', 'fckmaleware' ) );
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Restore points', 'fckmaleware' ) );
		echo '<p class="description">' . esc_html__( 'Every quarantine or repair, and every bulk action, records a restore point. Rolling back restores all files of that point that are still stored.', 'fckmaleware' ) . '</p>';
		$points = array_reverse( $this->plugin->remediation()->points(), true );
		if ( ! $points ) {
			echo '<p>' . esc_html__( 'No restore points yet.', 'fckmaleware' ) . '</p>';
		} else {
			echo '<table class="widefat striped fckmw-table"><thead><tr><th>' . esc_html__( 'Point', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Created', 'fckmaleware' ) . '</th><th>' . esc_html__( 'Files', 'fckmaleware' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( array_slice( $points, 0, 25, true ) as $id => $point ) {
				$restorable = 0;
				foreach ( (array) $point['items'] as $entry ) {
					$restorable += isset( $items[ $entry['key'] ] ) ? 1 : 0;
				}
				echo '<tr><td>' . esc_html( (string) $point['label'] ) . '</td><td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $point['time'] ) ) . '</td>';
				/* translators: 1: restorable, 2: total */
				echo '<td>' . esc_html( sprintf( __( '%1$d of %2$d still restorable', 'fckmaleware' ), $restorable, count( (array) $point['items'] ) ) ) . '</td><td>';
				if ( $restorable ) {
					Ui::action_button( 'rollback', __( 'Roll back', 'fckmaleware' ), array( 'point' => $id, 'return' => 'quarantine' ), 'button', __( 'Restore every file of this restore point?', 'fckmaleware' ) );
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		Ui::card_end();
		Ui::footer();
	}
}
