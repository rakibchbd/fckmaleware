<?php
/**
 * Threat Findings: filterable list with evidence, remediation actions and
 * optional advisory AI review.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Ai\Reviewer;
use Fckmaleware\DbScanner;
use Fckmaleware\Feedback;
use Fckmaleware\Findings as FindingStore;

final class Findings extends Page {

	private const PER_PAGE = 30;

	public function render( string $title ): void {
		$filters = array(
			'status'   => sanitize_key( (string) self::query( 'status', 'open' ) ),
			'source'   => sanitize_key( (string) self::query( 'source' ) ),
			'severity' => sanitize_key( (string) self::query( 'severity' ) ),
			'search'   => sanitize_text_field( (string) self::query( 's' ) ),
		);
		if ( ! in_array( $filters['status'], FindingStore::STATUSES, true ) ) {
			$filters['status'] = 'open';
		}
		$paged    = max( 1, absint( self::query( 'paged', 1 ) ) );
		$result   = $this->plugin->findings()->query( $filters, $paged, self::PER_PAGE );
		$statuses = $this->plugin->findings()->status_counts();
		$ai_ready = null === Reviewer::unavailable();

		Ui::header( $title, __( 'Every detection with its evidence. Nothing is changed until you choose an action; quarantine and repair keep a verified copy you can restore.', 'fckmaleware' ) );

		echo '<ul class="subsubsub">';
		$labels = array(
			'open'        => __( 'Open', 'fckmaleware' ),
			'quarantined' => __( 'Quarantined', 'fckmaleware' ),
			'ignored'     => __( 'Accepted', 'fckmaleware' ),
			'resolved'    => __( 'Resolved', 'fckmaleware' ),
		);
		$links = array();
		foreach ( $labels as $status => $label ) {
			$links[] = sprintf( '<li><a href="%1$s"%2$s>%3$s <span class="count">(%4$d)</span></a>', esc_url( Ui::url( 'findings', array( 'status' => $status ) ) ), $status === $filters['status'] ? ' class="current" aria-current="page"' : '', esc_html( $label ), (int) $statuses[ $status ] );
		}
		echo implode( ' | </li>', $links ) . '</li></ul>'; // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above.

		echo '<form method="get" class="fckmw-filters"><input type="hidden" name="page" value="' . esc_attr( Ui::SLUG . '-findings' ) . '"><input type="hidden" name="status" value="' . esc_attr( $filters['status'] ) . '">';
		self::filter_select( 'source', $filters['source'], array( '' => __( 'All layers', 'fckmaleware' ), 'signature' => __( 'Signature', 'fckmaleware' ), 'heuristic' => __( 'Heuristic', 'fckmaleware' ), 'integrity' => __( 'Integrity', 'fckmaleware' ), 'location' => __( 'Location', 'fckmaleware' ), 'database' => __( 'Database', 'fckmaleware' ), 'behaviour' => __( 'Behaviour', 'fckmaleware' ), 'imunify' => 'Imunify360' ) );
		self::filter_select( 'severity', $filters['severity'], array( '' => __( 'All severities', 'fckmaleware' ), 'critical' => __( 'Critical', 'fckmaleware' ), 'high' => __( 'High', 'fckmaleware' ), 'medium' => __( 'Medium', 'fckmaleware' ), 'low' => __( 'Low', 'fckmaleware' ) ) );
		echo '<label class="screen-reader-text" for="fckmw-search">' . esc_html__( 'Search findings', 'fckmaleware' ) . '</label><input type="search" id="fckmw-search" name="s" value="' . esc_attr( $filters['search'] ) . '" placeholder="' . esc_attr__( 'File or signature', 'fckmaleware' ) . '"> ';
		echo '<button class="button">' . esc_html__( 'Filter', 'fckmaleware' ) . '</button></form>';

		if ( ! $result['rows'] ) {
			Ui::card_start();
			echo '<p>' . esc_html( 'open' === $filters['status'] && ! array_filter( array( $filters['source'], $filters['severity'], $filters['search'] ) ) ? __( 'No open findings. Run a scan to check again.', 'fckmaleware' ) : __( 'No findings match.', 'fckmaleware' ) ) . '</p>';
			Ui::card_end();
			Ui::footer();
			return;
		}

		// The bulk form is empty; row checkboxes join it through the form attribute so the
		// per-row action forms below are not nested inside it.
		Ui::form( 'bulk', array( 'return' => 'findings' ), 'fckmw-bulk', 'fckmw-bulk-form' );
		if ( 'open' === $filters['status'] ) {
			echo '<div class="tablenav top"><div class="alignleft actions"><label class="screen-reader-text" for="fckmw-bulk-op">' . esc_html__( 'Bulk action', 'fckmaleware' ) . '</label><select name="op" id="fckmw-bulk-op"><option value="">' . esc_html__( 'Bulk actions', 'fckmaleware' ) . '</option><option value="quarantine">' . esc_html__( 'Quarantine files', 'fckmaleware' ) . '</option><option value="accept">' . esc_html__( 'Accept as safe', 'fckmaleware' ) . '</option><option value="resolve">' . esc_html__( 'Mark resolved', 'fckmaleware' ) . '</option></select> <button class="button" data-confirm="' . esc_attr__( 'Apply this action to all selected findings? Quarantine creates one restore point for the whole batch.', 'fckmaleware' ) . '">' . esc_html__( 'Apply', 'fckmaleware' ) . '</button></div></div>';
		}
		echo '</form>';

		$bulk = 'open' === $filters['status'];
		echo '<table class="widefat fckmw-table fckmw-findings"><thead><tr>';
		echo $bulk ? '<td class="check-column"><input type="checkbox" class="fckmw-check-all" aria-label="' . esc_attr__( 'Select all', 'fckmaleware' ) . '"></td>' : '<td></td>'; // phpcs:ignore WordPress.Security.EscapeOutput
		foreach ( array( __( 'Severity', 'fckmaleware' ), __( 'Location', 'fckmaleware' ), __( 'Detection', 'fckmaleware' ), __( 'Verdict', 'fckmaleware' ), __( 'Seen', 'fckmaleware' ) ) as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $result['rows'] as $row ) {
			$id = (int) $row['id'];
			echo '<tr>';
			echo $bulk ? '<th scope="row" class="check-column"><input type="checkbox" form="fckmw-bulk-form" name="ids[]" value="' . esc_attr( (string) $id ) . '" aria-label="' . esc_attr( sprintf( /* translators: %d: id */ __( 'Select finding %d', 'fckmaleware' ), $id ) ) . '"></th>' : '<td></td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td>' . Ui::severity( (string) $row['severity'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td class="fckmw-file"><code>' . esc_html( (string) $row['file'] ) . '</code>' . ( (int) $row['line'] ? ' <span class="description">:' . (int) $row['line'] . '</span>' : '' ) . '</td>';
			echo '<td><strong>' . esc_html( (string) $row['signature_name'] ) . '</strong><br><span class="description">' . esc_html( $row['signature_id'] . ' · ' . $row['source'] . ( $row['family'] ? ' · ' . $row['family'] : '' ) ) . '</span></td>';
			echo '<td>' . Ui::verdict( (string) $row['verdict'], (int) $row['confidence'] ) . self::ai_badge( $row ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td class="fckmw-nowrap">' . esc_html( Ui::ago( (int) strtotime( (string) ( $row['last_seen_at'] ?: $row['detected_at'] ) . ' UTC' ) ) ) . ( (int) $row['occurrences'] > 1 ? '<br><span class="description">' . esc_html( sprintf( /* translators: %d: count */ __( 'seen %d times', 'fckmaleware' ), (int) $row['occurrences'] ) ) . '</span>' : '' ) . '</td>';
			echo '</tr>';
			echo '<tr class="fckmw-detail-row"><td></td><td colspan="5"><details><summary>' . esc_html__( 'Evidence and actions', 'fckmaleware' ) . '</summary><div class="fckmw-detail">';
			$this->detail( $row, $ai_ready );
			echo '</div></details></td></tr>';
		}
		echo '</tbody></table>';

		Ui::pagination( (int) $result['total'], self::PER_PAGE, $paged );

		echo '<p>';
		Ui::form( 'export_findings', array( 'status' => $filters['status'] ), 'fckmw-inline' );
		echo '<button class="button">' . esc_html__( 'Export these findings (CSV)', 'fckmaleware' ) . '</button></form></p>';
		Ui::footer();
	}

	private static function filter_select( string $name, string $value, array $options ): void {
		echo '<label class="screen-reader-text" for="fckmw-filter-' . esc_attr( $name ) . '">' . esc_html( $options[''] ) . '</label><select id="fckmw-filter-' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '">';
		foreach ( $options as $option => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $option ), selected( $value, $option, false ), esc_html( $label ) );
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
		echo '<p class="description">' . esc_html( sprintf( /* translators: 1: date, 2: hash */ __( 'First detected %1$s. SHA-256 %2$s', 'fckmaleware' ), (string) $row['detected_at'] . ' UTC', $row['file_hash'] ?: '—' ) ) . '</p>';

		$review = self::ai_review( $row );
		if ( $review ) {
			echo '<div class="fckmw-ai"><h4>' . esc_html__( 'AI review (advisory)', 'fckmaleware' ) . '</h4>';
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
			if ( 'file' === $row['object_type'] && 'FMW-INT-003' !== $row['signature_id'] ) {
				Ui::action_button( 'finding', __( 'Quarantine file', 'fckmaleware' ), $hidden + array( 'op' => 'quarantine' ), 'button button-primary', __( 'Move this file to quarantine? A verified copy is kept and you can restore it. The site may break if the file is still needed.', 'fckmaleware' ) );
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
			Ui::action_button( 'finding', __( 'Accept as safe', 'fckmaleware' ), $hidden + array( 'op' => 'accept' ), 'button', __( 'Accept this as legitimate? Integrity findings record the current file as the new baseline; other findings stay hidden unless the file changes.', 'fckmaleware' ) );
			Ui::action_button( 'finding', __( 'Mark resolved', 'fckmaleware' ), $hidden + array( 'op' => 'resolve' ) );
		} elseif ( in_array( $row['status'], array( 'ignored', 'resolved' ), true ) ) {
			Ui::action_button( 'finding', __( 'Reopen', 'fckmaleware' ), $hidden + array( 'op' => 'reopen' ) );
		} elseif ( 'quarantined' === $row['status'] ) {
			echo '<a class="button" href="' . esc_url( Ui::url( 'quarantine' ) ) . '">' . esc_html__( 'Manage in quarantine', 'fckmaleware' ) . '</a>';
		}
		if ( $ai_ready ) {
			Ui::action_button( 'finding', $review ? __( 'Ask AI again', 'fckmaleware' ) : __( 'Ask AI for a second opinion', 'fckmaleware' ), $hidden + array( 'op' => 'ai_review' ), 'button', __( 'Send a redacted excerpt of this finding to the configured AI provider?', 'fckmaleware' ) );
		}
		echo '</div>';

		echo '<p class="fckmw-feedback">' . esc_html__( 'Help improve detection (opens a GitHub issue you can review before submitting):', 'fckmaleware' ) . ' ';
		echo '<a href="' . esc_url( Feedback::issue_url( $row, 'false_positive', false, $this->plugin ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Report false positive', 'fckmaleware' ) . '</a> · ';
		echo '<a href="' . esc_url( Feedback::issue_url( $row, 'confirmed', false, $this->plugin ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Confirm malware', 'fckmaleware' ) . '</a></p>';
	}
}
