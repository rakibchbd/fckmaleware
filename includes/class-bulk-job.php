<?php
/**
 * Bulk operations on findings (quarantine, accept, resolve) that may cover
 * thousands of rows: the selection is either explicit IDs or "every finding
 * matching these filters", walked by ID in small batches so nothing large is
 * held in memory and no request runs long.
 *
 *   preview()  Counts what a selection would affect and why rows would be
 *              skipped, without changing anything.
 *   start()    Records the job (one at a time) and its restore point.
 *   step()     Processes a time-boxed batch under a lock. Driven by the
 *              admin's browser through AJAX; it resumes when the page is
 *              reopened, and every step re-checks the capability.
 *   retry()    Starts a new job for the failures that can succeed later
 *              (busy lock, permissions fixed, disk space freed).
 *
 * Selections made with filters ("all matching" or "all eligible") use the
 * stricter bulk policy from Remediation::quarantine_eligibility(): only
 * malicious verdicts at or above the configured confidence, never core or
 * configuration files, never injected-but-legitimate files, never heuristic
 * matches inside active plugins or themes. Explicitly ticked findings only
 * get the hard safety rules, since the administrator chose each one.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class BulkJob {

	public const OPTION     = 'fckmw_bulk_job';
	public const OPS        = array( 'quarantine', 'accept', 'resolve' );
	private const LOCK      = 'bulk';
	private const BATCH     = 25;
	private const MAX_IDS   = 2000;
	private const MAX_FAILS = 200;

	/** Error codes worth retrying once the cause is fixed. */
	private const RECOVERABLE = array( 'fckmw_busy', 'fckmw_write', 'fckmw_storage', 'fckmw_unlink', 'fckmw_permissions', 'fckmw_verify', 'fckmw_read' );

	/** Error codes that mean "nothing to do any more" rather than a failure. */
	private const SKIP_CODES = array( 'fckmw_missing', 'fckmw_changed', 'fckmw_unknown' );

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public static function state(): ?array {
		wp_cache_delete( self::OPTION, 'options' );
		$job = Store::get( self::OPTION, null );
		return is_array( $job ) && isset( $job['id'] ) ? $job : null;
	}

	/** Status of the current job for the admin script ('' when none is running). */
	public static function current_status(): string {
		$job = self::state();
		return $job && 'running' === $job['status'] ? 'running' : '';
	}

	private static function save( array $job ): void {
		$job['updated'] = time();
		Store::set( self::OPTION, $job );
	}

	/**
	 * Normalize a selection coming from the admin.
	 *
	 * @param array $input op, mode (ids|filters|eligible), ids, filters.
	 * @return array|\WP_Error
	 */
	public static function selection( array $input ) {
		$op   = sanitize_key( (string) ( $input['op'] ?? '' ) );
		$mode = sanitize_key( (string) ( $input['mode'] ?? 'ids' ) );
		if ( ! in_array( $op, self::OPS, true ) || ! in_array( $mode, array( 'ids', 'filters', 'eligible' ), true ) ) {
			return new \WP_Error( 'fckmw_op', __( 'Choose findings and an action.', 'fckmaleware' ) );
		}
		$selection = array( 'op' => $op, 'mode' => $mode, 'ids' => array(), 'filters' => array( 'status' => 'open' ) );
		if ( 'ids' === $mode ) {
			$ids = array_values( array_unique( array_filter( array_map( 'absint', (array) ( $input['ids'] ?? array() ) ) ) ) );
			if ( ! $ids ) {
				return new \WP_Error( 'fckmw_op', __( 'Choose findings and an action.', 'fckmaleware' ) );
			}
			$selection['ids'] = array_slice( $ids, 0, self::MAX_IDS );
		} elseif ( 'filters' === $mode ) {
			$selection['filters'] = self::filters( (array) ( $input['filters'] ?? array() ) );
		} elseif ( 'quarantine' !== $op ) {
			return new \WP_Error( 'fckmw_op', __( '"All eligible" applies to quarantine only.', 'fckmaleware' ) );
		}
		return $selection;
	}

	/** Whitelisted finding filters (bulk actions only ever touch open findings). */
	public static function filters( array $in ): array {
		$out = array( 'status' => 'open' );
		foreach ( array( 'source', 'severity', 'verdict', 'confidence', 'file_type' ) as $key ) {
			if ( isset( $in[ $key ] ) && '' !== $in[ $key ] ) {
				$out[ $key ] = sanitize_key( (string) $in[ $key ] );
			}
		}
		if ( ! empty( $in['since_days'] ) ) {
			$out['since_days'] = absint( $in['since_days'] );
		}
		if ( isset( $in['search'] ) && '' !== $in['search'] ) {
			$out['search'] = sanitize_text_field( (string) $in['search'] );
		}
		return $out;
	}

	/** Reason a row would be skipped by this operation, or null if it would be processed. */
	private function reason( array $selection, array $row ): ?string {
		if ( 'open' !== $row['status'] ) {
			return __( 'Already handled (for example quarantined with another finding on the same file).', 'fckmaleware' );
		}
		if ( 'quarantine' !== $selection['op'] ) {
			return null;
		}
		return $this->plugin->remediation()->quarantine_eligibility( $row, 'ids' !== $selection['mode'] );
	}

	/**
	 * What a selection would do, without changing anything.
	 *
	 * @return array{total: int, eligible: int, skipped: int, reasons: array<string, int>, sample: string[]}|\WP_Error
	 */
	public function preview( array $selection ) {
		$out    = array( 'total' => 0, 'eligible' => 0, 'skipped' => 0, 'reasons' => array(), 'sample' => array() );
		$cursor = 0;
		$limit  = 50000;
		while ( $out['total'] < $limit ) {
			$rows = $this->rows( $selection, $cursor, 500 );
			if ( ! $rows ) {
				break;
			}
			foreach ( $rows as $row ) {
				$cursor = (int) $row['id'];
				$out['total']++;
				$reason = $this->reason( $selection, $row );
				if ( null === $reason ) {
					$out['eligible']++;
					if ( count( $out['sample'] ) < 5 ) {
						$out['sample'][] = (string) $row['file'];
					}
				} else {
					$out['skipped']++;
					$out['reasons'][ $reason ] = ( $out['reasons'][ $reason ] ?? 0 ) + 1;
				}
			}
		}
		arsort( $out['reasons'] );
		return $out;
	}

	/** @return array<int, array> Next rows of the selection after $cursor, in ID order. */
	private function rows( array $selection, int $cursor, int $limit ): array {
		if ( 'ids' !== $selection['mode'] ) {
			return $this->plugin->findings()->batch_after( $selection['filters'], $cursor, $limit );
		}
		$rows = array();
		$ids  = $selection['ids'];
		sort( $ids );
		foreach ( $ids as $id ) {
			if ( $id <= $cursor ) {
				continue;
			}
			$row = $this->plugin->findings()->get( $id );
			if ( $row ) {
				$rows[] = $row;
			}
			if ( count( $rows ) >= $limit ) {
				break;
			}
		}
		return $rows;
	}

	/** @return array|\WP_Error The new job. */
	public function start( array $selection ) {
		$current = self::state();
		if ( $current && 'running' === $current['status'] && time() - (int) $current['updated'] < 600 ) {
			return new \WP_Error( 'fckmw_busy', __( 'Another bulk action is still running. Wait for it to finish or cancel it.', 'fckmaleware' ) );
		}
		$total = 'ids' === $selection['mode'] ? count( $selection['ids'] ) : $this->plugin->findings()->count( $selection['filters'] );
		$labels = array(
			'quarantine' => __( 'Bulk quarantine', 'fckmaleware' ),
			'accept'     => __( 'Bulk accept as safe', 'fckmaleware' ),
			'resolve'    => __( 'Bulk mark resolved', 'fckmaleware' ),
		);
		$job = array(
			'id'        => bin2hex( random_bytes( 6 ) ),
			'op'        => $selection['op'],
			'mode'      => $selection['mode'],
			'ids'       => $selection['ids'],
			'filters'   => $selection['filters'],
			'status'    => 'running',
			'cursor'    => 0,
			'total'     => $total,
			'processed' => 0,
			'succeeded' => 0,
			'failed'    => 0,
			'skipped'   => 0,
			'failures'  => array(),
			'reasons'   => array(),
			'point'     => 'quarantine' === $selection['op'] ? $this->plugin->remediation()->create_point( $labels['quarantine'] ) : '',
			'user'      => get_current_user_id(),
			'label'     => $labels[ $selection['op'] ],
			'started'   => time(),
			'finished'  => 0,
		);
		self::save( $job );
		ActivityLog::log( 'bulk.started', sprintf( /* translators: 1: action, 2: count */ __( '%1$s started for up to %2$d findings.', 'fckmaleware' ), $job['label'], $total ), array( 'job' => $job['id'], 'op' => $job['op'], 'mode' => $job['mode'], 'filters' => $job['filters'], 'total' => $total ), 'notice' );
		return $job;
	}

	/** Process one time-boxed batch. */
	public function step( float $budget = 6.0 ): array {
		$job = self::state();
		if ( ! $job || 'running' !== $job['status'] ) {
			return $job ?? array( 'status' => 'idle' );
		}
		$token = Lock::acquire( self::LOCK, (int) ceil( $budget ) + 60 );
		if ( null === $token ) {
			return $job; // Another tab is processing this job.
		}
		try {
			$job      = (array) self::state();
			$deadline = microtime( true ) + $budget;
			while ( 'running' === $job['status'] && microtime( true ) < $deadline ) {
				$rows = $this->rows( $job, (int) $job['cursor'], self::BATCH );
				if ( ! $rows ) {
					$job = $this->complete( $job );
					break;
				}
				foreach ( $rows as $row ) {
					$job['cursor'] = (int) $row['id'];
					$job           = $this->process( $job, $row );
					if ( microtime( true ) >= $deadline ) {
						break;
					}
				}
			}
			// A cancel from another request wins over this step's progress.
			$latest = self::state();
			if ( $latest && 'cancelled' === $latest['status'] ) {
				return $latest;
			}
			self::save( $job );
			return $job;
		} finally {
			Lock::release( self::LOCK, $token );
		}
	}

	private function process( array $job, array $row ): array {
		$job['processed']++;
		$fresh  = $this->plugin->findings()->get( (int) $row['id'] ) ?? $row;
		$reason = $this->reason( $job, $fresh );
		if ( null !== $reason ) {
			$job['skipped']++;
			$job['reasons'][ $reason ] = ( $job['reasons'][ $reason ] ?? 0 ) + 1;
			return $job;
		}
		$id = (int) $row['id'];
		if ( 'quarantine' === $job['op'] ) {
			$result = $this->plugin->remediation()->quarantine( $id, (string) $job['point'] );
		} elseif ( 'accept' === $job['op'] ) {
			$result = $this->plugin->remediation()->accept( $id );
		} else {
			$result = $this->plugin->findings()->set_status( $id, 'resolved' ) ? true : new \WP_Error( 'fckmw_unknown', __( 'Finding not found.', 'fckmaleware' ) );
		}
		if ( ! is_wp_error( $result ) ) {
			$job['succeeded']++;
			return $job;
		}
		$code = (string) $result->get_error_code();
		if ( in_array( $code, self::SKIP_CODES, true ) ) {
			$job['skipped']++;
			$message                    = $result->get_error_message();
			$job['reasons'][ $message ] = ( $job['reasons'][ $message ] ?? 0 ) + 1;
			return $job;
		}
		$job['failed']++;
		if ( count( $job['failures'] ) < self::MAX_FAILS ) {
			$job['failures'][] = array(
				'id'          => $id,
				'file'        => (string) $row['file'],
				'message'     => $result->get_error_message(),
				'recoverable' => in_array( $code, self::RECOVERABLE, true ),
			);
		}
		return $job;
	}

	private function complete( array $job ): array {
		$job['status']   = 'complete';
		$job['finished'] = time();
		ActivityLog::log(
			'bulk.completed',
			sprintf(
				/* translators: 1: action, 2: succeeded, 3: failed, 4: skipped */
				__( '%1$s finished: %2$d succeeded, %3$d failed, %4$d skipped.', 'fckmaleware' ),
				$job['label'],
				$job['succeeded'],
				$job['failed'],
				$job['skipped']
			),
			array_intersect_key( $job, array_flip( array( 'id', 'op', 'mode', 'processed', 'succeeded', 'failed', 'skipped', 'point' ) ) ),
			$job['failed'] ? 'warning' : 'notice'
		);
		return $job;
	}

	public function cancel(): array {
		$job = self::state();
		if ( $job && 'running' === $job['status'] ) {
			$job['status']   = 'cancelled';
			$job['finished'] = time();
			self::save( $job );
			ActivityLog::log( 'bulk.cancelled', sprintf( /* translators: 1: action, 2: processed */ __( '%1$s cancelled after %2$d findings.', 'fckmaleware' ), $job['label'], $job['processed'] ), array( 'job' => $job['id'] ), 'notice' );
		}
		return $job ?? array( 'status' => 'idle' );
	}

	/** @return array|\WP_Error A new job for the recoverable failures of the last one. */
	public function retry() {
		$job = self::state();
		if ( ! $job || 'running' === $job['status'] ) {
			return new \WP_Error( 'fckmw_op', __( 'There is nothing to retry.', 'fckmaleware' ) );
		}
		$ids = array();
		foreach ( (array) $job['failures'] as $failure ) {
			if ( ! empty( $failure['recoverable'] ) ) {
				$ids[] = (int) $failure['id'];
			}
		}
		if ( ! $ids ) {
			return new \WP_Error( 'fckmw_op', __( 'None of the failures can be retried automatically.', 'fckmaleware' ) );
		}
		// The administrator already confirmed these findings; keep the original policy.
		return $this->start( array( 'op' => $job['op'], 'mode' => 'ids', 'ids' => $ids, 'filters' => array( 'status' => 'open' ) ) );
	}

	/** Fields the browser needs. */
	public static function public_state( ?array $job ): array {
		if ( ! $job ) {
			return array( 'status' => 'idle' );
		}
		$out                = array_intersect_key( $job, array_flip( array( 'id', 'op', 'label', 'status', 'total', 'processed', 'succeeded', 'failed', 'skipped', 'started', 'finished' ) ) );
		$out['failures']    = array_slice( (array) $job['failures'], 0, 20 );
		$out['reasons']     = array_slice( (array) $job['reasons'], 0, 8, true );
		$out['recoverable'] = count(
			array_filter(
				(array) $job['failures'],
				static function ( array $failure ): bool {
					return ! empty( $failure['recoverable'] );
				}
			)
		);
		return $out;
	}
}
