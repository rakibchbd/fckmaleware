<?php
/**
 * Malware Scanner: start file and database scans, watch progress, run the
 * persistence check.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\FileCache;
use Fckmaleware\Store;

final class Scanner extends Page {

	public function render( string $title ): void {
		$scan = $this->plugin->scanner()->state();
		$db   = $this->plugin->db_scanner()->state();
		$last = (array) Store::get( 'fckmw_last_scan', array() );

		Ui::header( $title, __( 'Scans read files only; nothing is executed or changed. Detections become findings you decide on.', 'fckmaleware' ) );

		Ui::card_start( __( 'File scan', 'fckmaleware' ), 'fckmw-scan-card' );
		$modes = array(
			'quick'    => __( 'Quick: PHP, .htaccess and .ini files only, skipping files unchanged since they were found clean.', 'fckmaleware' ),
			'standard' => __( 'Standard: every file, skipping files unchanged since they were last found clean.', 'fckmaleware' ),
			'deep'     => __( 'Deep: every file re-read without the cache, images included. Slowest; use after a compromise.', 'fckmaleware' ),
			'core'     => __( 'Core: WordPress core files against the official checksums.', 'fckmaleware' ),
			'recent'   => __( 'Recent: files modified in the last N days.', 'fckmaleware' ),
			'custom'   => __( 'Custom: one directory inside the installation.', 'fckmaleware' ),
		);
		$running = 'running' === ( $scan['status'] ?? '' );
		echo '<form id="fckmw-scan-form" class="fckmw-scan-form"' . ( $running ? ' hidden' : '' ) . '><fieldset><legend class="screen-reader-text">' . esc_html__( 'Scan mode', 'fckmaleware' ) . '</legend>';
		foreach ( $modes as $mode => $help ) {
			printf(
				'<label class="fckmw-mode"><input type="radio" name="mode" value="%1$s"%2$s> <strong>%3$s</strong><span>%4$s</span></label>',
				esc_attr( $mode ),
				checked( 'standard', $mode, false ),
				esc_html( ucfirst( $mode ) ),
				esc_html( $help )
			);
		}
		echo '</fieldset>';
		echo '<p class="fckmw-mode-option" data-mode="recent" hidden><label>' . esc_html__( 'Days', 'fckmaleware' ) . ' <input type="number" name="days" value="7" min="1" max="365" class="small-text"></label></p>';
		echo '<p class="fckmw-mode-option" data-mode="custom" hidden><label>' . esc_html__( 'Directory (relative to the WordPress root)', 'fckmaleware' ) . ' <input type="text" name="scope" class="regular-text" placeholder="wp-content/plugins/example"></label></p>';
		echo '<p><button type="submit" class="button button-primary button-hero">' . esc_html__( 'Start scan', 'fckmaleware' ) . '</button></p></form>';

		echo '<div id="fckmw-scan-progress" class="fckmw-live"' . ( $running ? '' : ' hidden' ) . ' aria-live="polite">';
		echo '<div class="fckmw-progress"><div class="fckmw-bar"></div></div><p class="fckmw-live-text">';
		if ( $running ) {
			/* translators: 1: mode, 2: position, 3: total */
			echo esc_html( sprintf( __( '%1$s scan in progress: %2$d of %3$d files.', 'fckmaleware' ), ucfirst( (string) $scan['mode'] ), $scan['position'], $scan['total'] ) );
		}
		echo '</p><p><button type="button" class="button" id="fckmw-scan-cancel">' . esc_html__( 'Cancel scan', 'fckmaleware' ) . '</button></p></div>';
		echo '<p class="description">' . esc_html__( 'Keep this page open while the scan runs; each step takes a few seconds. If you leave, an interrupted scan continues in the background through WP-Cron.', 'fckmaleware' ) . '</p>';
		Ui::card_end();

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Last complete file scan', 'fckmaleware' ) );
		if ( $last ) {
			echo '<dl class="fckmw-dl">';
			self::row( __( 'Mode', 'fckmaleware' ), ucfirst( (string) $last['mode'] ) . ' (' . (string) ( $last['trigger'] ?? '' ) . ')' );
			self::row( __( 'Finished', 'fckmaleware' ), Ui::datetime( (int) $last['finished'] ) );
			self::row( __( 'Duration', 'fckmaleware' ), human_time_diff( (int) $last['started'], (int) $last['finished'] ) );
			self::row( __( 'Files checked', 'fckmaleware' ), number_format_i18n( (int) $last['total'] ) );
			self::row( __( 'Unchanged, skipped', 'fckmaleware' ), number_format_i18n( (int) $last['skipped'] ) );
			self::row( __( 'Detections', 'fckmaleware' ), (int) $last['found'] . ' (' . (int) $last['new'] . ' ' . __( 'new', 'fckmaleware' ) . ')' );
			self::row( __( 'Resolved since previous scan', 'fckmaleware' ), (string) (int) ( $last['resolved'] ?? 0 ) );
			self::row( __( 'Signature database', 'fckmaleware' ), (string) ( $last['sig_version'] ?? '' ) );
			echo '</dl>';
			if ( ! empty( $last['too_large'] ) ) {
				echo '<details><summary>' . esc_html( sprintf( /* translators: 1: count, 2: MB */ _n( '%1$d file was larger than %2$d MB and was not checked', '%1$d files were larger than %2$d MB and were not checked', (int) $last['too_large'], 'fckmaleware' ), (int) $last['too_large'], (int) \Fckmaleware\Settings::get( 'max_file_size_mb' ) ) ) . '</summary><ul class="fckmw-mono">';
				foreach ( (array) ( $last['too_large_files'] ?? array() ) as $large ) {
					echo '<li>' . esc_html( (string) $large ) . '</li>';
				}
				echo '</ul><p class="description">' . esc_html__( 'Raise the limit in Scan Schedule, or scan them from the command line, if they should be checked.', 'fckmaleware' ) . '</p></details>';
			}
			$errors = (array) ( $last['errors'] ?? array() );
			if ( $errors ) {
				echo '<details><summary>' . esc_html( sprintf( /* translators: %d: count */ _n( '%d file could not be read', '%d files could not be read', count( $errors ), 'fckmaleware' ), count( $errors ) ) ) . '</summary><ul class="fckmw-mono">';
				foreach ( array_slice( $errors, 0, 50 ) as $error ) {
					echo '<li>' . esc_html( is_array( $error ) ? implode( ': ', $error ) : (string) $error ) . '</li>';
				}
				echo '</ul></details>';
			}
		} else {
			echo '<p>' . esc_html__( 'No scan has completed yet.', 'fckmaleware' ) . '</p>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Database scan', 'fckmaleware' ) );
		echo '<p>' . esc_html__( 'Searches posts, options and comments on every site for injected scripts, hidden links and PHP. Findings link to the right editor; the scanner never edits serialized data.', 'fckmaleware' ) . '</p>';
		$last_db = (array) Store::get( 'fckmw_last_db_scan', array() );
		if ( $last_db ) {
			/* translators: 1: time, 2: rows, 3: detections */
			echo '<p class="description">' . esc_html( sprintf( __( 'Last run %1$s: %2$d candidate rows inspected, %3$d detections.', 'fckmaleware' ), Ui::ago( (int) $last_db['finished'] ), $last_db['rows'], $last_db['found'] ) ) . '</p>';
		}
		$db_running = 'running' === ( $db['status'] ?? '' );
		echo '<div id="fckmw-db-progress" class="fckmw-live"' . ( $db_running ? '' : ' hidden' ) . ' aria-live="polite"><div class="fckmw-progress"><div class="fckmw-bar fckmw-bar-indeterminate"></div></div><p class="fckmw-live-text"></p></div>';
		echo '<p><button type="button" class="button" id="fckmw-db-start"' . ( $db_running ? ' hidden' : '' ) . '>' . esc_html__( 'Scan database', 'fckmaleware' ) . '</button></p>';
		Ui::card_end();

		Ui::card_start( __( 'Persistence check', 'fckmaleware' ) );
		echo '<p>' . esc_html__( 'Looks for the ways attackers keep access: hidden or new administrators, changed roles and capabilities, a changed site URL, auto_prepend_file, malicious scheduled events and eval\'d hook callbacks.', 'fckmaleware' ) . '</p>';
		$persist = (array) Store::get( 'fckmw_last_persistence_check', array() );
		if ( $persist ) {
			/* translators: 1: time, 2: findings */
			echo '<p class="description">' . esc_html( sprintf( __( 'Last run %1$s: %2$d findings.', 'fckmaleware' ), Ui::ago( (int) $persist['time'] ), $persist['found'] ) ) . '</p>';
		}
		Ui::action_button( 'persistence', __( 'Run persistence check', 'fckmaleware' ), array( 'return' => 'scanner' ) );
		Ui::card_end();

		Ui::card_start( __( 'Incremental cache', 'fckmaleware' ) );
		$cache = FileCache::stats();
		/* translators: 1: files, 2: clean */
		echo '<p>' . esc_html( sprintf( __( '%1$s files remembered, %2$s of them clean. Standard and quick scans skip clean files whose size, time and hash are unchanged and whose signature database has not changed.', 'fckmaleware' ), number_format_i18n( $cache['files'] ), number_format_i18n( $cache['clean'] ) ) ) . '</p>';
		Ui::action_button( 'cache_clear', __( 'Clear cache', 'fckmaleware' ), array( 'return' => 'scanner' ), 'button', __( 'The next scan will read every file again. Continue?', 'fckmaleware' ) );
		Ui::card_end();
		echo '</div>';

		Ui::footer();
	}

	private static function row( string $label, string $value ): void {
		echo '<dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( $value ) . '</dd>';
	}
}
