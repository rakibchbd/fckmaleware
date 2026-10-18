<?php
/**
 * Quarantine: isolated files and pre-repair backups, bulk restore and
 * permanent deletion, retention, storage location and restore points.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Paths;
use Fckmaleware\Settings;

final class Quarantine extends Page {

	private const PER_PAGE = 40;

	public function render( string $title ): void {
		$quarantine = $this->plugin->quarantine();
		$stats      = $quarantine->stats();
		$retention  = (int) Settings::get( 'quarantine_retention' );
		$kind       = sanitize_key( (string) self::query( 'kind' ) );
		$kind       = in_array( $kind, array( 'quarantine', 'backup' ), true ) ? $kind : '';
		$search     = sanitize_text_field( (string) self::query( 's' ) );
		$items      = $quarantine->search( $kind, $search );
		$paged      = max( 1, absint( self::query( 'paged', 1 ) ) );

		$actions = $this->plugin->findings()->status_counts()['open']
			? '<a class="button" href="' . esc_url( Ui::url( 'findings' ) ) . '">' . esc_html__( 'Review open findings', 'fckmaleware' ) . '</a>'
			: '';
		Ui::header( $title, __( 'Quarantined files are stored compressed (never executable), verified before the original is removed, and kept with their original path, hash, permissions and timestamp. Restoring never overwrites a file that exists at the original location.', 'fckmaleware' ), $actions );

		echo '<div class="fckmw-stats">';
		Ui::stat( __( 'Quarantined files', 'fckmaleware' ), (string) $stats['quarantined'], 'neutral' );
		Ui::stat( __( 'Repair backups', 'fckmaleware' ), (string) $stats['backups'] );
		Ui::stat( __( 'Storage used', 'fckmaleware' ), size_format( $stats['bytes'] ) ?: '0 B', 'neutral', __( 'original size', 'fckmaleware' ) );
		Ui::stat( __( 'Retention', 'fckmaleware' ), $retention ? sprintf( /* translators: %d: days */ _n( '%d day', '%d days', $retention, 'fckmaleware' ), $retention ) : __( 'Until deleted', 'fckmaleware' ), 'neutral', __( 'change in Settings', 'fckmaleware' ), Ui::url( 'settings' ) . '#quarantine' );
		echo '</div>';

		if ( Paths::data_dir_in_web_root() ) {
			Ui::callout( __( 'The quarantine folder is inside the web root, protected by a random name, deny rules and non-executable compressed storage. For stronger isolation, define FCKMW_DATA_DIR in wp-config.php with a folder outside the web root; stored files are moved there and verified automatically.', 'fckmaleware' ), 'info', __( 'Storage location', 'fckmaleware' ) );
		} else {
			Ui::callout( __( 'Quarantined files are stored outside the web root, so the web server cannot serve them.', 'fckmaleware' ), 'success', __( 'Storage location', 'fckmaleware' ) );
		}

		Ui::card_start( __( 'Stored files', 'fckmaleware' ) );
		echo '<form method="get" class="fckmw-filters" role="search">';
		Ui::location_fields( 'quarantine' );
		echo '<label class="screen-reader-text" for="fckmw-qkind">' . esc_html__( 'Type', 'fckmaleware' ) . '</label><select id="fckmw-qkind" name="kind"><option value="">' . esc_html__( 'All types', 'fckmaleware' ) . '</option><option value="quarantine"' . selected( $kind, 'quarantine', false ) . '>' . esc_html__( 'Quarantined', 'fckmaleware' ) . '</option><option value="backup"' . selected( $kind, 'backup', false ) . '>' . esc_html__( 'Repair backups', 'fckmaleware' ) . '</option></select> ';
		echo '<label class="screen-reader-text" for="fckmw-qsearch">' . esc_html__( 'Search by path', 'fckmaleware' ) . '</label><input type="search" id="fckmw-qsearch" name="s" value="' . esc_attr( $search ) . '" placeholder="' . esc_attr__( 'Original path', 'fckmaleware' ) . '"> <button class="button">' . esc_html__( 'Filter', 'fckmaleware' ) . '</button></form>';

		if ( ! $items ) {
			Ui::empty_state( '' === $kind && '' === $search ? __( 'Nothing is in quarantine', 'fckmaleware' ) : __( 'No stored files match', 'fckmaleware' ), __( 'Files you quarantine from Threat Findings appear here and can be restored or deleted.', 'fckmaleware' ), '', 'lock' );
		} else {
			Ui::form( 'quarantine_bulk', array( 'return' => 'quarantine' ), 'fckmw-bulkbar', 'fckmw-qbulk' );
			echo '<label class="screen-reader-text" for="fckmw-qop">' . esc_html__( 'Bulk action', 'fckmaleware' ) . '</label><select name="op" id="fckmw-qop"><option value="restore">' . esc_html__( 'Restore selected', 'fckmaleware' ) . '</option><option value="delete">' . esc_html__( 'Delete selected permanently', 'fckmaleware' ) . '</option></select> ';
			echo '<button class="button" data-confirm="' . esc_attr__( 'Apply this action to every selected file? Restoring puts malicious files back where they were and skips any location where a file now exists. Deleting cannot be undone.', 'fckmaleware' ) . '" data-confirm-label="' . esc_attr__( 'Apply to selected', 'fckmaleware' ) . '">' . esc_html__( 'Apply', 'fckmaleware' ) . '</button></form>';

			echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><td class="check-column"><input type="checkbox" data-check-all="keys[]" aria-label="' . esc_attr__( 'Select all on this page', 'fckmaleware' ) . '"></td><th scope="col">' . esc_html__( 'Original location', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Type', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Reason', 'fckmaleware' ) . '</th><th scope="col" class="fckmw-num">' . esc_html__( 'Size', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Stored', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Actions', 'fckmaleware' ) . '</th></tr></thead><tbody>';
			foreach ( array_slice( $items, ( $paged - 1 ) * self::PER_PAGE, self::PER_PAGE, true ) as $key => $item ) {
				$context = (array) ( $item['context'] ?? array() );
				$backup  = 'backup' === ( $item['kind'] ?? 'quarantine' );
				$reason  = ! empty( $context['signature'] ) ? (string) $context['signature'] : ( 'repair' === ( $context['reason'] ?? '' ) ? __( 'Backup before repair', 'fckmaleware' ) : (string) ( $context['reason'] ?? '' ) );
				$user    = get_userdata( (int) ( $item['user'] ?? 0 ) );
				$exists  = file_exists( Paths::root() . $item['file'] );
				echo '<tr><th scope="row" class="check-column"><input type="checkbox" form="fckmw-qbulk" name="keys[]" value="' . esc_attr( (string) $key ) . '" aria-label="' . esc_attr( sprintf( /* translators: %s: file */ __( 'Select %s', 'fckmaleware' ), (string) $item['file'] ) ) . '"></th>';
				echo '<td class="fckmw-file"><code>' . esc_html( (string) $item['file'] ) . '</code><span class="fckmw-sub fckmw-mono" title="' . esc_attr( (string) $item['hash'] ) . '">' . esc_html( 'SHA-256 ' . substr( (string) $item['hash'], 0, 16 ) . '…' ) . '</span>' . ( $exists && ! $backup ? '<span class="fckmw-sub">' . esc_html__( 'A file exists at this location again; restore is blocked until it is removed.', 'fckmaleware' ) . '</span>' : '' ) . '</td>';
				echo '<td>' . Ui::badge( $backup ? __( 'Backup', 'fckmaleware' ) : __( 'Quarantined', 'fckmaleware' ), $backup ? 'neutral' : 'warn' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
				echo '<td>' . esc_html( $reason ) . ( ! empty( $context['finding'] ) ? ' <span class="description">#' . (int) $context['finding'] . '</span>' : '' ) . '</td>';
				echo '<td class="fckmw-num">' . esc_html( size_format( (int) $item['size'] ) ?: '0 B' ) . '</td>';
				$expires = (int) ( $context['expires'] ?? 0 );
				echo '<td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $item['time'] ) ) . ( $expires ? '<span class="fckmw-sub">' . esc_html( sprintf( /* translators: %s: date */ __( 'auto-removed · deleted %s', 'fckmaleware' ), wp_date( 'M j', $expires ) ) ) . '</span>' : '' ) . ( $user ? '<span class="fckmw-sub">' . esc_html( $user->user_login ) . '</span>' : '<span class="fckmw-sub">' . esc_html__( 'automatic', 'fckmaleware' ) . '</span>' ) . '</td>';
				echo '<td><div class="fckmw-actions" style="margin:0">';
				Ui::action_button( 'quarantine_item', __( 'Restore', 'fckmaleware' ), array( 'key' => $key, 'op' => 'restore', 'return' => 'quarantine' ), 'button', $backup ? __( 'Put this backup back? It replaces the current (repaired) file.', 'fckmaleware' ) : __( 'Put this file back in its original location? Its integrity is verified first, and nothing is overwritten. If it is malicious, the site will be infected again.', 'fckmaleware' ) );
				Ui::action_button( 'quarantine_item', __( 'Delete', 'fckmaleware' ), array( 'key' => $key, 'op' => 'delete', 'return' => 'quarantine' ), 'button button-link-delete', __( 'Permanently delete the stored copy? This cannot be undone.', 'fckmaleware' ) );
				echo '</div></td></tr>';
			}
			echo '</tbody></table></div>';
			Ui::pagination( count( $items ), self::PER_PAGE, $paged );
		}
		Ui::card_end();

		Ui::card_start( __( 'Restore points', 'fckmaleware' ), '', __( 'Every quarantine, repair and bulk action records a restore point. Rolling back restores every file of that point that is still stored.', 'fckmaleware' ) );
		$all    = $quarantine->all();
		$points = array_reverse( $this->plugin->remediation()->points(), true );
		if ( ! $points ) {
			Ui::empty_state( __( 'No restore points yet', 'fckmaleware' ), '', '', 'backup' );
		} else {
			echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><th scope="col">' . esc_html__( 'Point', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Created', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Files', 'fckmaleware' ) . '</th><th scope="col"></th></tr></thead><tbody>';
			foreach ( array_slice( $points, 0, 25, true ) as $id => $point ) {
				$restorable = 0;
				foreach ( (array) $point['items'] as $entry ) {
					$restorable += isset( $all[ $entry['key'] ] ) ? 1 : 0;
				}
				echo '<tr><td>' . esc_html( (string) $point['label'] ) . '</td><td class="fckmw-nowrap">' . esc_html( Ui::datetime( (int) $point['time'] ) ) . '</td>';
				/* translators: 1: restorable, 2: total */
				echo '<td>' . esc_html( sprintf( __( '%1$d of %2$d still restorable', 'fckmaleware' ), $restorable, count( (array) $point['items'] ) ) ) . '</td><td>';
				if ( $restorable ) {
					Ui::action_button( 'rollback', __( 'Roll back', 'fckmaleware' ), array( 'point' => $id, 'return' => 'quarantine' ), 'button', __( 'Restore every file of this restore point? Files whose original location is occupied are skipped.', 'fckmaleware' ) );
				}
				echo '</td></tr>';
			}
			echo '</tbody></table></div>';
		}
		Ui::card_end();
		Ui::footer();
	}
}
