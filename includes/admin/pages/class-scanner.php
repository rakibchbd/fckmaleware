<?php
/**
 * Malware Scanner: start file and database scans, watch progress, run the
 * persistence check, and review the scan history.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\FileCache;
use Fckmaleware\ScanHistory;
use Fckmaleware\Settings;
use Fckmaleware\Store;

final class Scanner extends Page {

	public function render( string $title ): void {
		$scan = $this->plugin->scanner()->state();
		$db   = $this->plugin->db_scanner()->state();
		$last = (array) Store::get( 'fckmw_last_scan', array() );

		Ui::header( $title, __( 'Scans read files only; nothing is executed or changed. Detections become findings you decide on. Large sites are scanned in small, resumable steps.', 'fckmaleware' ) );

		Ui::card_start( __( 'File scan', 'fckmaleware' ), 'fckmw-scan-card' );
		$modes   = array(
			'quick'    => array( __( 'Quick', 'fckmaleware' ), __( 'PHP, .htaccess and .ini files, skipping files unchanged since they were found clean.', 'fckmaleware' ) ),
			'standard' => array( __( 'Full', 'fckmaleware' ), __( 'Every file, skipping unchanged clean files. Records integrity baselines.', 'fckmaleware' ) ),
			'deep'     => array( __( 'Deep', 'fckmaleware' ), __( 'Every file re-read without the cache, images included. Use after a compromise.', 'fckmaleware' ) ),
			'core'     => array( __( 'WordPress core', 'fckmaleware' ), __( 'Core files against the official checksums.', 'fckmaleware' ) ),
			'plugins'  => array( __( 'Plugins & themes', 'fckmaleware' ), __( 'Plugins, must-use plugins and themes, with official checksums where available.', 'fckmaleware' ) ),
			'uploads'  => array( __( 'Uploads', 'fckmaleware' ), __( 'The uploads directory, images included (PHP hidden in images).', 'fckmaleware' ) ),
			'recent'   => array( __( 'Recent changes', 'fckmaleware' ), __( 'Files modified in the last N days.', 'fckmaleware' ) ),
			'custom'   => array( __( 'Custom directory', 'fckmaleware' ), __( 'One directory inside the installation.', 'fckmaleware' ) ),
		);
		$running = 'running' === ( $scan['status'] ?? '' );
		echo '<form id="fckmw-scan-form" class="fckmw-scan-form"' . ( $running ? ' hidden' : '' ) . '><fieldset class="fckmw-modes"><legend class="screen-reader-text">' . esc_html__( 'Scan mode', 'fckmaleware' ) . '</legend>';
		foreach ( $modes as $mode => $label ) {
			printf(
				'<label class="fckmw-mode"><input type="radio" name="mode" value="%1$s"%2$s> <strong>%3$s</strong><span>%4$s</span></label>',
				esc_attr( $mode ),
				checked( 'standard', $mode, false ),
				esc_html( $label[0] ),
				esc_html( $label[1] )
			);
		}
		echo '</fieldset>';
		echo '<p class="fckmw-mode-option" data-mode="recent" hidden><label>' . esc_html__( 'Days', 'fckmaleware' ) . ' <input type="number" name="days" value="7" min="1" max="365" class="small-text"></label></p>';
		echo '<p class="fckmw-mode-option" data-mode="custom" hidden><label>' . esc_html__( 'Directory (relative to the WordPress root)', 'fckmaleware' ) . ' <input type="text" name="scope" class="regular-text" placeholder="wp-content/plugins/example"></label><span class="fckmw-sub">' . esc_html__( 'Must exist inside this installation; ".." and symbolic links that lead outside are refused.', 'fckmaleware' ) . '</span></p>';
		echo '<p><button type="submit" class="button button-primary button-hero"><span class="dashicons dashicons-search" aria-hidden="true"></span>' . esc_html__( 'Start scan', 'fckmaleware' ) . '</button></p></form>';

		echo '<div id="fckmw-scan-progress" class="fckmw-live"' . ( $running ? '' : ' hidden' ) . ' aria-live="polite">';
		echo '<p class="fckmw-live-text">';
		if ( $running ) {
			/* translators: 1: mode, 2: position, 3: total */
			echo esc_html( sprintf( __( '%1$s in progress: %2$d of %3$d files.', 'fckmaleware' ), ScanHistory::label( (string) $scan['mode'] ), $scan['position'], $scan['total'] ) );
		}
		echo '</p><div class="fckmw-progress"><div class="fckmw-bar"></div></div><dl class="fckmw-live-stats">';
		foreach ( array( 'files' => __( 'Files checked', 'fckmaleware' ), 'skipped' => __( 'Unchanged, skipped', 'fckmaleware' ), 'found' => __( 'Detections', 'fckmaleware' ), 'errors' => __( 'Errors', 'fckmaleware' ), 'elapsed' => __( 'Elapsed', 'fckmaleware' ) ) as $key => $label ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd data-stat="' . esc_attr( $key ) . '">—</dd></div>';
		}
		echo '</dl><p><button type="button" class="button" id="fckmw-scan-cancel">' . esc_html__( 'Cancel scan', 'fckmaleware' ) . '</button></p></div>';
		echo '<p class="description">' . esc_html__( 'Keep this page open while the scan runs. If you leave, an interrupted scan continues in the background through WP-Cron and resumes exactly where it stopped. Only one scan runs at a time.', 'fckmaleware' ) . '</p>';
		$exclusions = Settings::exclusions();
		if ( $exclusions ) {
			/* translators: %s: list of directories */
			Ui::callout( sprintf( __( 'Excluded from every scan: %s. Malware in these folders is not found.', 'fckmaleware' ), implode( ', ', $exclusions ) ), 'warning' );
		}
		Ui::card_end();

		echo '<div class="fckmw-grid">';
		Ui::card_start( __( 'Database scan', 'fckmaleware' ), '', __( 'Posts, options and comments on every site: injected scripts, hidden links and PHP. Findings link to the right editor; serialized data is never edited.', 'fckmaleware' ) );
		$last_db = (array) Store::get( 'fckmw_last_db_scan', array() );
		if ( $last_db ) {
			/* translators: 1: time, 2: rows, 3: detections */
			echo '<p class="description">' . esc_html( sprintf( __( 'Last run %1$s: %2$d candidate rows inspected, %3$d detections.', 'fckmaleware' ), Ui::ago( (int) $last_db['finished'] ), $last_db['rows'], $last_db['found'] ) ) . '</p>';
		}
		$db_running = 'running' === ( $db['status'] ?? '' );
		echo '<div id="fckmw-db-progress" class="fckmw-live"' . ( $db_running ? '' : ' hidden' ) . ' aria-live="polite"><div class="fckmw-progress"><div class="fckmw-bar fckmw-bar-indeterminate"></div></div><p class="fckmw-live-text"></p><p><button type="button" class="button" id="fckmw-db-cancel">' . esc_html__( 'Cancel', 'fckmaleware' ) . '</button></p></div>';
		echo '<p><button type="button" class="button button-primary" id="fckmw-db-start"' . ( $db_running ? ' hidden' : '' ) . '><span class="dashicons dashicons-database" aria-hidden="true"></span>' . esc_html__( 'Scan database', 'fckmaleware' ) . '</button></p>';
		Ui::card_end();

		Ui::card_start( __( 'Persistence check', 'fckmaleware' ), '', __( 'Ways attackers keep access: hidden or new administrators, changed roles and capabilities, a changed site URL, auto_prepend_file, malicious scheduled events and eval\'d hook callbacks.', 'fckmaleware' ) );
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
		echo '<p>' . esc_html( sprintf( __( '%1$s files remembered, %2$s of them clean. Quick and full scans skip clean files whose size, time and hash are unchanged and whose signature database has not changed.', 'fckmaleware' ), number_format_i18n( $cache['files'] ), number_format_i18n( $cache['clean'] ) ) ) . '</p>';
		Ui::action_button( 'cache_clear', __( 'Clear cache', 'fckmaleware' ), array( 'return' => 'scanner' ), 'button', __( 'The next scan will read every file again. Continue?', 'fckmaleware' ) );
		Ui::card_end();
		echo '</div>';

		if ( $last ) {
			Ui::card_start( __( 'Last complete file scan', 'fckmaleware' ) );
			Ui::kv(
				array(
					array( __( 'Type', 'fckmaleware' ), esc_html( ScanHistory::label( (string) $last['mode'] ) . ' (' . (string) ( $last['trigger'] ?? '' ) . ')' ) ),
					array( __( 'Finished', 'fckmaleware' ), esc_html( Ui::datetime( (int) $last['finished'] ) ) ),
					array( __( 'Duration', 'fckmaleware' ), esc_html( human_time_diff( (int) $last['started'], (int) $last['finished'] ) ) ),
					array( __( 'Files checked', 'fckmaleware' ), esc_html( number_format_i18n( (int) $last['total'] ) ) ),
					array( __( 'Unchanged, skipped', 'fckmaleware' ), esc_html( number_format_i18n( (int) $last['skipped'] ) ) ),
					array( __( 'Detections', 'fckmaleware' ), esc_html( (int) $last['found'] . ' (' . (int) $last['new'] . ' ' . __( 'new', 'fckmaleware' ) . ')' ) ),
					array( __( 'Resolved since previous scan', 'fckmaleware' ), esc_html( (string) (int) ( $last['resolved'] ?? 0 ) ) ),
					array( __( 'Signature database', 'fckmaleware' ), esc_html( (string) ( $last['sig_version'] ?? '' ) ) ),
				)
			);
			if ( ! empty( $last['too_large'] ) ) {
				echo '<details><summary>' . esc_html( sprintf( /* translators: 1: count, 2: MB */ _n( '%1$d file was larger than %2$d MB and was not checked', '%1$d files were larger than %2$d MB and were not checked', (int) $last['too_large'], 'fckmaleware' ), (int) $last['too_large'], (int) Settings::get( 'max_file_size_mb' ) ) ) . '</summary><ul class="fckmw-mono">';
				foreach ( (array) ( $last['too_large_files'] ?? array() ) as $large ) {
					echo '<li>' . esc_html( (string) $large ) . '</li>';
				}
				echo '</ul><p class="description">' . esc_html__( 'These files were not checked. Raise the limit under Settings → Performance, or scan them with WP-CLI.', 'fckmaleware' ) . '</p></details>';
			}
			$errors = (array) ( $last['errors'] ?? array() );
			if ( $errors ) {
				echo '<details><summary>' . esc_html( sprintf( /* translators: %d: count */ _n( '%d file could not be read', '%d files could not be read', count( $errors ), 'fckmaleware' ), count( $errors ) ) ) . '</summary><ul class="fckmw-mono">';
				foreach ( array_slice( $errors, 0, 50 ) as $error ) {
					echo '<li>' . esc_html( is_array( $error ) ? implode( ': ', $error ) : (string) $error ) . '</li>';
				}
				echo '</ul></details>';
			}
			Ui::card_end();
		}

		Ui::card_start( __( 'Scan history', 'fckmaleware' ), '', '', 'history' );
		$history = ScanHistory::all();
		if ( ! $history ) {
			Ui::empty_state( __( 'No scans recorded yet', 'fckmaleware' ), __( 'Every finished, cancelled or failed scan is listed here.', 'fckmaleware' ), '', 'search' );
		} else {
			self::history_table( array_slice( $history, 0, 50 ), false );
		}
		Ui::card_end();

		Ui::footer();
	}

	/** Scan history rows (shared with the overview). */
	public static function history_table( array $rows, bool $compact ): void {
		$tones = array( 'complete' => array( __( 'Completed', 'fckmaleware' ), 'good' ), 'cancelled' => array( __( 'Cancelled', 'fckmaleware' ), 'off' ), 'failed' => array( __( 'Failed', 'fckmaleware' ), 'bad' ) );
		echo '<div class="fckmw-table-wrap"><table class="fckmw-table"><thead><tr><th scope="col">' . esc_html__( 'Type', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Status', 'fckmaleware' ) . '</th><th scope="col" class="fckmw-num">' . esc_html__( 'Scanned', 'fckmaleware' ) . '</th><th scope="col" class="fckmw-num">' . esc_html__( 'Detections', 'fckmaleware' ) . '</th>';
		if ( ! $compact ) {
			echo '<th scope="col" class="fckmw-num">' . esc_html__( 'Skipped', 'fckmaleware' ) . '</th><th scope="col" class="fckmw-num">' . esc_html__( 'Errors', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Trigger', 'fckmaleware' ) . '</th>';
		}
		echo '<th scope="col">' . esc_html__( 'Duration', 'fckmaleware' ) . '</th><th scope="col">' . esc_html__( 'Started', 'fckmaleware' ) . '</th></tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$status = $tones[ $row['status'] ] ?? array( ucfirst( (string) $row['status'] ), 'neutral' );
			$label  = ScanHistory::label( (string) $row['mode'] ) . ( ! empty( $row['scope'] ) && ! $compact ? ': ' . $row['scope'] : '' );
			echo '<tr><td>' . esc_html( $label ) . '</td><td>' . Ui::status( $status[0], $status[1] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput -- status() escapes.
			echo '<td class="fckmw-num">' . esc_html( number_format_i18n( (int) $row['files'] ) ) . ( 'database' === $row['mode'] ? ' ' . esc_html__( 'rows', 'fckmaleware' ) : '' ) . '</td>';
			echo '<td class="fckmw-num">' . esc_html( number_format_i18n( (int) $row['found'] ) ) . ( ! $compact && (int) $row['new'] ? '<span class="fckmw-sub">' . esc_html( sprintf( /* translators: %d: count */ __( '%d new', 'fckmaleware' ), (int) $row['new'] ) ) . '</span>' : '' ) . '</td>';
			if ( ! $compact ) {
				echo '<td class="fckmw-num">' . esc_html( number_format_i18n( (int) $row['skipped'] ) ) . '</td><td class="fckmw-num">' . esc_html( (string) ( (int) $row['errors'] + (int) ( $row['large'] ?? 0 ) ) ) . '</td><td>' . esc_html( (string) $row['trigger'] ) . '</td>';
			}
			echo '<td class="fckmw-nowrap">' . esc_html( $row['started'] ? human_time_diff( (int) $row['started'], max( (int) $row['started'] + 1, (int) $row['finished'] ) ) : '—' ) . '</td>';
			echo '<td class="fckmw-nowrap">' . esc_html( wp_date( 'M j, H:i', (int) ( $row['started'] ?: $row['finished'] ) ) ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}
}
