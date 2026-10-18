<?php
/**
 * Threat Findings: searchable, filterable list with evidence, remediation
 * actions, bulk operations over thousands of rows and optional advisory AI
 * review.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Ai\Reviewer;
use Fckmaleware\DbScanner;
use Fckmaleware\Feedback;
use Fckmaleware\Findings as FindingStore;
use Fckmaleware\Paths;

final class Findings extends Page {

	private const PER_PAGE = 30;

	/** Current filters from the query string, whitelisted. */
	private static function filters(): array {
		$filters = array(
			'status'     => sanitize_key( (string) self::query( 'status', 'open' ) ),
			'source'     => sanitize_key( (string) self::query( 'source' ) ),
			'severity'   => sanitize_key( (string) self::query( 'severity' ) ),
			'verdict'    => sanitize_key( (string) self::query( 'verdict' ) ),
			'confidence' => sanitize_key( (string) self::query( 'confidence' ) ),
			'file_type'  => sanitize_key( (string) self::query( 'file_type' ) ),
			'since_days' => absint( self::query( 'since_days', 0 ) ),
			'search'     => sanitize_text_field( (string) self::query( 's' ) ),
		);
		if ( ! in_array( $filters['status'], FindingStore::STATUSES, true ) ) {
			$filters['status'] = 'open';
		}
		if ( ! in_array( $filters['verdict'], FindingStore::VERDICTS, true ) ) {
			$filters['verdict'] = '';
		}
		if ( ! isset( FindingStore::CONFIDENCE_BANDS[ $filters['confidence'] ] ) ) {
			$filters['confidence'] = '';
		}
		if ( ! isset( FindingStore::FILE_TYPES[ $filters['file_type'] ] ) ) {
			$filters['file_type'] = '';
		}
		return $filters;
	}

	public function render( string $title ): void {
		$filters  = self::filters();
		$paged    = max( 1, absint( self::query( 'paged', 1 ) ) );
		$result   = $this->plugin->findings()->query( $filters, $paged, self::PER_PAGE );
		$statuses = $this->plugin->findings()->status_counts();
		$ai_ready = null === Reviewer::unavailable();
		$open     = 'open' === $filters['status'];

		$actions = '';
		if ( $statuses['open'] ) {
			$actions = Overview::quarantine_menu( $this->plugin );
		}
		Ui::header( $title, __( 'Every detection with its evidence. Nothing changes until you choose an action; quarantine and repair keep a verified copy you can restore. Confirmed malware, likely malicious code, suspicious behaviour and unverified changes are labelled separately.', 'fckmaleware' ), $actions );

		self::job_panel();

		$labels = array(
			'open'        => __( 'Open', 'fckmaleware' ),
			'quarantined' => __( 'Quarantined', 'fckmaleware' ),
			'ignored'     => __( 'Accepted (false positive)', 'fckmaleware' ),
			'resolved'    => __( 'Resolved', 'fckmaleware' ),
		);
		echo '<nav class="fckmw-segments" aria-label="' . esc_attr__( 'Finding status', 'fckmaleware' ) . '">';
		foreach ( $labels as $status => $label ) {
			printf( '<a href="%1$s"%2$s>%3$s <span class="count">%4$s</span></a>', esc_url( Ui::url( 'findings', array( 'status' => $status ) ) ), $status === $filters['status'] ? ' class="is-current" aria-current="page"' : '', esc_html( $label ), esc_html( number_format_i18n( (int) $statuses[ $status ] ) ) );
		}
		echo '</nav>';

		echo '<form method="get" class="fckmw-filters" role="search">';
		Ui::location_fields( 'findings' );
		echo '<input type="hidden" name="status" value="' . esc_attr( $filters['status'] ) . '">';
		self::filter_select( 'verdict', $filters['verdict'], array( '' => __( 'All verdicts', 'fckmaleware' ), 'malicious' => __( 'Malicious', 'fckmaleware' ), 'suspicious' => __( 'Suspicious', 'fckmaleware' ) ) );
		self::filter_select( 'confidence', $filters['confidence'], array( '' => __( 'Any confidence', 'fckmaleware' ), 'high' => __( 'High (90–100%)', 'fckmaleware' ), 'medium' => __( 'Medium (70–89%)', 'fckmaleware' ), 'low' => __( 'Low (under 70%)', 'fckmaleware' ) ) );
		self::filter_select( 'severity', $filters['severity'], array( '' => __( 'All severities', 'fckmaleware' ), 'critical' => __( 'Critical', 'fckmaleware' ), 'high' => __( 'High', 'fckmaleware' ), 'medium' => __( 'Medium', 'fckmaleware' ), 'low' => __( 'Low', 'fckmaleware' ) ) );
		self::filter_select( 'source', $filters['source'], array( '' => __( 'All detection sources', 'fckmaleware' ), 'signature' => __( 'Signature', 'fckmaleware' ), 'heuristic' => __( 'Heuristic', 'fckmaleware' ), 'integrity' => __( 'Integrity', 'fckmaleware' ), 'location' => __( 'Location', 'fckmaleware' ), 'database' => __( 'Database', 'fckmaleware' ), 'behaviour' => __( 'Behaviour', 'fckmaleware' ), 'imunify' => __( 'Server scanner (Imunify)', 'fckmaleware' ) ) );
		self::filter_select( 'file_type', $filters['file_type'], array( '' => __( 'All file types', 'fckmaleware' ), 'php' => 'PHP', 'js' => 'JavaScript', 'config' => __( '.htaccess / .ini', 'fckmaleware' ), 'html' => __( 'HTML / SVG', 'fckmaleware' ), 'image' => __( 'Images', 'fckmaleware' ) ) );
		self::filter_select( 'since_days', (string) $filters['since_days'], array( '0' => __( 'Any date', 'fckmaleware' ), '1' => __( 'Last 24 hours', 'fckmaleware' ), '7' => __( 'Last 7 days', 'fckmaleware' ), '30' => __( 'Last 30 days', 'fckmaleware' ), '90' => __( 'Last 90 days', 'fckmaleware' ) ) );
		echo '<label class="screen-reader-text" for="fckmw-search">' . esc_html__( 'Search findings', 'fckmaleware' ) . '</label><input type="search" id="fckmw-search" name="s" value="' . esc_attr( $filters['search'] ) . '" placeholder="' . esc_attr__( 'File path or signature', 'fckmaleware' ) . '"> ';
		echo '<button class="button">' . esc_html__( 'Filter', 'fckmaleware' ) . '</button>';
		$active = array_filter( array( $filters['source'], $filters['severity'], $filters['verdict'], $filters['confidence'], $filters['file_type'], $filters['since_days'], $filters['search'] ) );
		if ( $active ) {
			echo ' <a class="button-link" href="' . esc_url( Ui::url( 'findings', array( 'status' => $filters['status'] ) ) ) . '">' . esc_html__( 'Clear filters', 'fckmaleware' ) . '</a>';
		}
		echo '</form>';

		if ( ! $result['rows'] ) {
			Ui::card_start();
			if ( $open && ! $active ) {
				Ui::empty_state( __( 'No open findings', 'fckmaleware' ), __( 'Nothing needs your attention. Run a scan to check again.', 'fckmaleware' ), Ui::button_link( Ui::url( 'scanner' ), __( 'Open scanner', 'fckmaleware' ), 'button button-primary' ) );
			} else {
				Ui::empty_state( __( 'No findings match', 'fckmaleware' ), __( 'Try fewer filters.', 'fckmaleware' ), '', 'filter' );
			}
			Ui::card_end();
			Ui::footer();
			return;
		}

		Ui::card_start( '', 'fckmw-card-table' );
		if ( $open ) {
			// The bulk form is empty; row checkboxes join it through the form
			// attribute so the per-row action forms are not nested inside it.
			$bulk_filters = array_filter( array_diff_key( $filters, array( 'status' => 1 ) ) );
			Ui::form( 'bulk', array( 'return' => 'findings' ), 'fckmw-bulkbar', 'fckmw-bulk-form' );
			echo '<label class="screen-reader-text" for="fckmw-bulk-op">' . esc_html__( 'Bulk action', 'fckmaleware' ) . '</label><select name="op" id="fckmw-bulk-op"><option value="">' . esc_html__( 'Bulk actions', 'fckmaleware' ) . '</option><option value="quarantine">' . esc_html__( 'Quarantine files', 'fckmaleware' ) . '</option><option value="accept">' . esc_html__( 'Accept as safe', 'fckmaleware' ) . '</option><option value="resolve">' . esc_html__( 'Mark resolved', 'fckmaleware' ) . '</option></select> ';
			echo '<button class="button">' . esc_html__( 'Apply', 'fckmaleware' ) . '</button> ';
			/* translators: %d: selected count */
			echo '<span class="fckmw-bulkbar-count" id="fckmw-bulk-count" data-template="' . esc_attr__( '%d selected', 'fckmaleware' ) . '" data-all="' . esc_attr( sprintf( /* translators: %s: count */ __( 'All %s matching findings selected', 'fckmaleware' ), number_format_i18n( (int) $result['total'] ) ) ) . '"></span>';
			echo '</form>';
			// Data for the script: the active filters and the confirmation wording.
			printf(
				'<div hidden id="fckmw-bulk-attrs" data-filters="%1$s" data-preview="%2$s"></div>',
				esc_attr( (string) wp_json_encode( (object) $bulk_filters ) ),
				/* translators: 1: findings that will be processed, 2: selected, 3: skipped */
				esc_attr__( '%1$d of %2$d selected findings will be processed in safe batches; %3$d will be skipped for the reasons below. Quarantined files are re-checked first, kept as verified copies and can be restored or rolled back as one restore point.', 'fckmaleware' )
			);
			if ( (int) $result['total'] > count( $result['rows'] ) ) {
				echo '<div class="fckmw-selectall" id="fckmw-selectall" hidden><span class="fckmw-selectall-page">' . esc_html( sprintf( /* translators: %d: count */ __( 'All %d findings on this page are selected.', 'fckmaleware' ), count( $result['rows'] ) ) ) . ' <button type="button" data-select-all>' . esc_html( sprintf( /* translators: %s: count */ __( 'Select all %s findings that match', 'fckmaleware' ), number_format_i18n( (int) $result['total'] ) ) ) . '</button></span><span class="fckmw-selectall-all" hidden>' . esc_html( sprintf( /* translators: %s: count */ __( 'All %s matching findings are selected. Quarantine applies the bulk safety policy to them.', 'fckmaleware' ), number_format_i18n( (int) $result['total'] ) ) ) . ' <button type="button" data-select-page>' . esc_html__( 'Select only this page', 'fckmaleware' ) . '</button></span></div>';
			}
		}

		echo '<div class="fckmw-table-wrap"><table class="fckmw-table fckmw-findings"><thead><tr>';
		echo $open ? '<td class="check-column"><input type="checkbox" class="fckmw-check-all" aria-label="' . esc_attr__( 'Select all on this page', 'fckmaleware' ) . '"></td>' : '<td class="check-column"></td>'; // phpcs:ignore WordPress.Security.EscapeOutput
		foreach ( array( __( 'Threat', 'fckmaleware' ), __( 'File or record', 'fckmaleware' ), __( 'Detection', 'fckmaleware' ), __( 'Confidence', 'fckmaleware' ), __( 'Detected', 'fckmaleware' ) ) as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		$sources = self::source_labels();
		foreach ( $result['rows'] as $row ) {
			$id = (int) $row['id'];
			echo '<tr>';
			echo $open ? '<th scope="row" class="check-column"><input type="checkbox" form="fckmw-bulk-form" name="ids[]" value="' . esc_attr( (string) $id ) . '" aria-label="' . esc_attr( sprintf( /* translators: %s: file */ __( 'Select %s', 'fckmaleware' ), (string) $row['file'] ) ) . '"></th>' : '<td class="check-column"></td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td>' . Ui::classification( $row ) . '<span class="fckmw-sub">' . Ui::severity( (string) $row['severity'] ) . '</span></td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td class="fckmw-file"><code>' . esc_html( (string) $row['file'] ) . '</code>' . ( (int) $row['line'] ? ' <span class="description">:' . (int) $row['line'] . '</span>' : '' ) . '</td>';
			echo '<td><strong>' . esc_html( (string) $row['signature_name'] ) . '</strong><span class="fckmw-sub">' . esc_html( ( $sources[ $row['source'] ] ?? $row['source'] ) . ' · ' . $row['signature_id'] ) . '</span></td>';
			echo '<td>' . Ui::verdict( (string) $row['verdict'], (int) $row['confidence'] ) . self::ai_badge( $row ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td class="fckmw-nowrap">' . Ui::when( (int) strtotime( (string) $row['detected_at'] . ' UTC' ) ) . ( (int) $row['occurrences'] > 1 ? '<span class="fckmw-sub">' . esc_html( sprintf( /* translators: %d: count */ __( 'seen %d times', 'fckmaleware' ), (int) $row['occurrences'] ) ) . '</span>' : '' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '</tr>';
			echo '<tr class="fckmw-detail-row"><td></td><td colspan="5"><details><summary>' . esc_html__( 'Evidence, details and actions', 'fckmaleware' ) . '</summary><div class="fckmw-detail">';
			$this->detail( $row, $ai_ready );
			echo '</div></details></td></tr>';
		}
		echo '</tbody></table></div>';

		Ui::pagination( (int) $result['total'], self::PER_PAGE, $paged );
		Ui::card_end();

		Ui::form( 'export_findings', array( 'status' => $filters['status'] ), 'fckmw-inline' );
		foreach ( array_filter( array_diff_key( $filters, array( 'status' => 1 ) ) ) as $key => $value ) {
			echo '<input type="hidden" name="filters[' . esc_attr( $key ) . ']" value="' . esc_attr( (string) $value ) . '">';
		}
		echo '<button class="button"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Export these findings (CSV)', 'fckmaleware' ) . '</button></form>';
		Ui::footer();
	}

	/** Progress panel for bulk jobs (driven by admin.js). */
	public static function job_panel(): void {
		echo '<div class="fckmw-job" id="fckmw-job" hidden aria-live="polite"><strong class="fckmw-job-title"></strong><div class="fckmw-progress"><div class="fckmw-bar"></div></div><p class="fckmw-live-text"></p><ul class="fckmw-list fckmw-job-failures"></ul><div class="fckmw-actions">';
		echo '<button type="button" class="button" data-job-cancel hidden>' . esc_html__( 'Cancel', 'fckmaleware' ) . '</button>';
		echo '<button type="button" class="button" data-job-retry hidden>' . esc_html__( 'Retry recoverable failures', 'fckmaleware' ) . '</button>';
		echo '<button type="button" class="button button-primary" data-job-reload hidden>' . esc_html__( 'Refresh list', 'fckmaleware' ) . '</button>';
		echo '</div></div>';
	}

	public static function source_labels(): array {
		return array(
			'signature' => __( 'Signature', 'fckmaleware' ),
			'heuristic' => __( 'Heuristic', 'fckmaleware' ),
			'integrity' => __( 'Integrity', 'fckmaleware' ),
			'location'  => __( 'Location', 'fckmaleware' ),
			'database'  => __( 'Database', 'fckmaleware' ),
			'behaviour' => __( 'Behaviour', 'fckmaleware' ),
			'imunify'   => __( 'Server scanner', 'fckmaleware' ),
		);
	}

	private static function filter_select( string $name, string $value, array $options ): void {
		echo '<label class="screen-reader-text" for="fckmw-filter-' . esc_attr( $name ) . '">' . esc_html( (string) reset( $options ) ) . '</label><select id="fckmw-filter-' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '">';
		foreach ( $options as $option => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( (string) $option ), selected( $value, (string) $option, false ), esc_html( $label ) );
		}
		echo '</select> ';
	}

	private static function ai_review( array $row ): ?array {
		$review = $row['ai_review'] ?? '' ? json_decode( (string) $row['ai_review'], true ) : null;
		return is_array( $review ) ? $review : null;
	}

	private static function ai_badge( array $row ): string {
		$review = self::ai_review( $row );
		return $review ? ' ' . Ui::badge( sprintf( /* translators: 1: verdict, 2: confidence */ __( 'AI: %1$s %2$d%%', 'fckmaleware' ), $review['verdict'], $review['confidence'] ), 'neutral' ) : '';
	}

	private function detail( array $row, bool $ai_ready ): void {
		$id          = (int) $row['id'];
		$remediation = $this->plugin->remediation();

		if ( $row['evidence'] ) {
			echo '<h4>' . esc_html__( 'Why this was flagged', 'fckmaleware' ) . '</h4><p class="fckmw-pre">' . esc_html( (string) $row['evidence'] ) . '</p>';
		}
		if ( $row['excerpt'] ) {
			echo '<h4>' . esc_html__( 'Excerpt (shown as text, never executed)', 'fckmaleware' ) . '</h4><pre class="fckmw-code">' . esc_html( (string) $row['excerpt'] ) . '</pre>';
		}
		if ( $row['remediation'] ) {
			$advice = array(
				'quarantine' => __( 'Quarantine the file: it is malicious as a whole and nothing legitimate depends on it.', 'fckmaleware' ),
				'clean'      => __( 'Remove the injected code from an otherwise legitimate file: reinstall the plugin or theme from its official source, or edit the file by hand. Quarantining it would also remove the legitimate code.', 'fckmaleware' ),
				'repair'     => __( 'Replace the file with the official copy.', 'fckmaleware' ),
				'review'     => __( 'Check what the code does before acting: this pattern also appears in some legitimate code.', 'fckmaleware' ),
			);
			echo '<h4>' . esc_html__( 'Recommended', 'fckmaleware' ) . '</h4><p>' . esc_html( $advice[ $row['remediation'] ] ?? (string) $row['remediation'] ) . '</p>';
		}

		// File metadata is read now (only for the rows on screen), so it reflects the file as it is.
		$size = '—';
		$now  = '';
		if ( 'file' === $row['object_type'] ) {
			$absolute = Paths::file( (string) $row['file'] );
			if ( is_wp_error( $absolute ) ) {
				$now = $absolute->get_error_message();
			} else {
				$size = size_format( (int) filesize( $absolute ) ) ?: '0 B';
				if ( '' !== $row['file_hash'] && ! hash_equals( (string) $row['file_hash'], (string) hash_file( 'sha256', $absolute ) ) ) {
					$now = __( 'The file changed since it was scanned; it is re-checked before any action.', 'fckmaleware' );
				}
			}
		}
		$sources = self::source_labels();
		echo '<dl class="fckmw-detail-meta">';
		$meta = array(
			__( 'Detection source', 'fckmaleware' ) => ( $sources[ $row['source'] ] ?? $row['source'] ),
			__( 'Rule', 'fckmaleware' )             => $row['signature_id'] . ( $row['family'] ? ' · ' . $row['family'] : '' ),
			__( 'Severity / confidence', 'fckmaleware' ) => ucfirst( (string) $row['severity'] ) . ' · ' . (int) $row['confidence'] . '%',
			__( 'Status', 'fckmaleware' )           => ucfirst( (string) $row['status'] ),
			__( 'First detected', 'fckmaleware' )   => Ui::datetime( (int) strtotime( (string) $row['detected_at'] . ' UTC' ) ),
			__( 'Last seen', 'fckmaleware' )        => $row['last_seen_at'] ? Ui::datetime( (int) strtotime( (string) $row['last_seen_at'] . ' UTC' ) ) : '—',
			__( 'File size', 'fckmaleware' )        => $size,
			__( 'SHA-256 when detected', 'fckmaleware' ) => $row['file_hash'] ?: '—',
		);
		foreach ( $meta as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( (string) $value ) . '</dd></div>';
		}
		echo '</dl>';
		if ( '' !== $now ) {
			Ui::callout( $now, 'warning' );
		}

		$review = self::ai_review( $row );
		if ( $review ) {
			echo '<div class="fckmw-ai"><h4>' . esc_html__( 'AI second opinion (advisory)', 'fckmaleware' ) . '</h4>';
			/* translators: 1: verdict, 2: confidence, 3: family, 4: model, 5: date */
			echo '<p>' . esc_html( sprintf( __( '%1$s, %2$d%% confidence, family "%3$s". Model %4$s, %5$s.', 'fckmaleware' ), $review['verdict'], $review['confidence'], $review['family'], $review['model'], Ui::datetime( (int) $review['reviewed_at'] ) ) ) . '</p>';
			echo '<p>' . esc_html( (string) $review['explanation'] ) . '</p>';
			if ( ! empty( $review['indicators'] ) ) {
				echo '<ul class="fckmw-list">';
				foreach ( (array) $review['indicators'] as $indicator ) {
					echo '<li>' . esc_html( (string) $indicator ) . '</li>';
				}
				echo '</ul>';
			}
			/* translators: %s: action */
			echo '<p class="description">' . esc_html( sprintf( __( 'Suggested action: %s. The AI cannot change anything; you decide.', 'fckmaleware' ), $review['recommended_action'] ) ) . '</p></div>';
		}

		echo '<div class="fckmw-actions">';
		$hidden = array( 'finding' => $id, 'return' => 'findings' );
		if ( 'open' === $row['status'] ) {
			$blocked = $remediation->quarantine_eligibility( $row, false );
			if ( null === $blocked ) {
				Ui::action_button( 'finding', __( 'Quarantine file', 'fckmaleware' ), $hidden + array( 'op' => 'quarantine' ), 'button button-primary', __( 'The file is re-checked, a verified copy is stored outside the public site and the original is removed. You can restore it from Quarantine. The site may break if the file is still needed.', 'fckmaleware' ) );
			}
			if ( $remediation->can_repair( $row ) ) {
				Ui::action_button( 'finding', __( 'Replace with official copy', 'fckmaleware' ), $hidden + array( 'op' => 'repair' ), 'button button-primary', __( 'Download the official file, verify it against the official checksum, back up the current file and replace it?', 'fckmaleware' ) );
			}
			if ( 'cron' === $row['object_type'] ) {
				Ui::action_button( 'finding', __( 'Remove scheduled event', 'fckmaleware' ), $hidden + array( 'op' => 'remove_cron' ), 'button button-primary', __( 'Unschedule this event? Its arguments are recorded in the activity log.', 'fckmaleware' ) );
			}
			$edit = DbScanner::edit_link( $row );
			if ( '' !== $edit ) {
				echo '<a class="button" href="' . esc_url( $edit ) . '">' . esc_html__( 'Open in editor', 'fckmaleware' ) . '</a>';
			}
			Ui::action_button( 'finding', __( 'Accept as safe', 'fckmaleware' ), $hidden + array( 'op' => 'accept' ), 'button', __( 'Accept this as legitimate (false positive)? Integrity findings record the current file as the new baseline; other findings stay hidden unless the file changes.', 'fckmaleware' ) );
			Ui::action_button( 'finding', __( 'Mark resolved', 'fckmaleware' ), $hidden + array( 'op' => 'resolve' ) );
			if ( null !== $blocked && 'file' === $row['object_type'] ) {
				echo '<span class="description">' . esc_html( $blocked ) . '</span>';
			}
		} elseif ( in_array( $row['status'], array( 'ignored', 'resolved' ), true ) ) {
			Ui::action_button( 'finding', __( 'Reopen', 'fckmaleware' ), $hidden + array( 'op' => 'reopen' ) );
		} elseif ( 'quarantined' === $row['status'] ) {
			echo '<a class="button" href="' . esc_url( Ui::url( 'quarantine' ) ) . '">' . esc_html__( 'Manage in quarantine', 'fckmaleware' ) . '</a>';
		}
		if ( $ai_ready ) {
			Ui::action_button( 'finding', $review ? __( 'Ask AI again', 'fckmaleware' ) : __( 'Ask AI for a second opinion', 'fckmaleware' ), $hidden + array( 'op' => 'ai_review' ), 'button', __( 'Send a redacted excerpt of this finding to the configured AI provider? Credentials, e-mail addresses and site paths are removed first.', 'fckmaleware' ) );
		}
		echo '</div>';

		echo '<p class="fckmw-feedback">' . esc_html__( 'Help improve detection (opens a GitHub issue you can review before submitting):', 'fckmaleware' ) . ' ';
		echo '<a href="' . esc_url( Feedback::issue_url( $row, 'false_positive', false, $this->plugin ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Report false positive', 'fckmaleware' ) . '</a> · ';
		echo '<a href="' . esc_url( Feedback::issue_url( $row, 'confirmed', false, $this->plugin ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Confirm malware', 'fckmaleware' ) . '</a></p>';
	}
}
