<?php
/**
 * Wires the components together and owns cron, Imunify sync and alerts.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Plugin {

	public const CRON_SCAN     = 'fckmw_scheduled_scan';
	public const CRON_CONTINUE = 'fckmw_scan_continue';

	/** @var Plugin|null */
	private static $instance;

	/** @var Signatures|null */
	private $signatures;

	/** @var Findings|null */
	private $findings;

	/** @var Scanner|null */
	private $scanner;

	/** @var Quarantine|null */
	private $quarantine;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot(): void {
		if ( Findings::DB_VERSION !== get_option( 'fckmw_db_version' ) ) {
			Findings::install();
		}

		add_action( self::CRON_SCAN, array( $this, 'run_scheduled_scan' ) );
		add_action( self::CRON_CONTINUE, array( $this, 'continue_scan' ) );
		add_action( 'fckmw_scan_complete', array( $this, 'on_scan_complete' ) );

		if ( is_admin() ) {
			( new Admin( $this ) )->register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'fckmaleware', new CLI( $this ) );
		}
	}

	public function signatures(): Signatures {
		if ( null === $this->signatures ) {
			/**
			 * Path to the signature database JSON file.
			 *
			 * @param string $path Defaults to the bundled signatures/signatures.json.
			 */
			$path = (string) apply_filters( 'fckmw_signature_file', FCKMW_DIR . 'signatures/signatures.json' );
			try {
				$this->signatures = Signatures::from_file( $path );
			} catch ( \RuntimeException $e ) {
				$this->signatures = new Signatures( array( 'version' => 'unavailable' ) );
			}
		}
		return $this->signatures;
	}

	public function findings(): Findings {
		if ( null === $this->findings ) {
			$this->findings = new Findings();
		}
		return $this->findings;
	}

	public function scanner(): Scanner {
		if ( null === $this->scanner ) {
			$this->scanner = new Scanner( $this->signatures(), $this->findings() );
		}
		return $this->scanner;
	}

	public function quarantine(): Quarantine {
		if ( null === $this->quarantine ) {
			$this->quarantine = new Quarantine();
		}
		return $this->quarantine;
	}

	public function imunify(): Imunify {
		return new Imunify( (string) Settings::get( 'imunify_binary' ), (bool) Settings::get( 'imunify_use_sudo' ) );
	}

	/**
	 * Quarantine the file behind a finding and update every open finding on that file.
	 *
	 * @return true|\WP_Error
	 */
	public function quarantine_finding( int $id ) {
		$finding = $this->findings()->get( $id );
		if ( ! $finding || 'open' !== $finding['status'] ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Finding not found or not open.', 'fckmaleware' ) );
		}
		$key = $this->quarantine()->isolate( $finding['file'], $this->is_foreign_core_file( $finding['file'] ) );
		if ( is_wp_error( $key ) ) {
			return $key;
		}
		$this->findings()->set_status_for_file( $finding['file'], 'quarantined', $key );
		return true;
	}

	/**
	 * Whether a file may be quarantined: anything outside core locations, plus
	 * files in core locations that the integrity check found are not part of WordPress.
	 */
	public function can_quarantine( string $file ): bool {
		return ! Paths::is_core( $file ) || $this->is_foreign_core_file( $file );
	}

	private function is_foreign_core_file( string $file ): bool {
		return $this->findings()->has_open( $file, 'FMW-INT-002' );
	}

	/**
	 * Pull Imunify's malicious-file list for this site into the findings table.
	 *
	 * @return int|\WP_Error Number of open Imunify findings.
	 */
	public function sync_imunify() {
		$files = $this->imunify()->malicious_files( Paths::root() );
		if ( is_wp_error( $files ) ) {
			return $files;
		}

		$this->findings()->clear_open( array( 'imunify' ) );
		$count = 0;
		foreach ( $files as $item ) {
			// Entries Imunify already cleaned or restored are not actionable here.
			if ( in_array( strtolower( $item['status'] ), array( 'cleanup_done', 'cleaned', 'restored_original', 'removed' ), true ) ) {
				continue;
			}
			$signature_id = 'IMUNIFY:' . substr( $item['signature'], 0, 180 );
			if ( $this->findings()->is_ignored_any( $item['file'], $signature_id ) ) {
				continue;
			}
			$this->findings()->add(
				array(
					'source'         => 'imunify',
					'file'           => $item['file'],
					'signature_id'   => $signature_id,
					'signature_name' => $item['signature'],
					'severity'       => 'critical',
				)
			);
			$count++;
		}
		update_option( 'fckmw_imunify_last_sync', time(), false );
		return $count;
	}

	public function run_scheduled_scan(): void {
		$state = $this->scanner()->start( 'scheduled' );
		if ( ! is_wp_error( $state ) ) {
			$this->continue_scan();
		}
	}

	/** Cron continuation: one time-boxed step, then re-queue until done. */
	public function continue_scan(): void {
		$state = $this->scanner()->step( 20.0 );
		if ( 'running' === $state['status'] && ! wp_next_scheduled( self::CRON_CONTINUE ) ) {
			wp_schedule_single_event( time() + 30, self::CRON_CONTINUE );
		}
	}

	public function on_scan_complete( array $state ): void {
		if ( Settings::get( 'imunify_enabled' ) && Settings::get( 'imunify_sync_scan' ) ) {
			$this->sync_imunify();
		}
		if ( 'manual' !== $state['trigger'] && Settings::get( 'email_alerts' ) ) {
			$this->send_alert();
		}
	}

	private function send_alert(): void {
		$counts = $this->findings()->open_counts();
		if ( 0 === $counts['total'] ) {
			return;
		}
		$to = Settings::get( 'alert_email' ) ?: get_option( 'admin_email' );

		$lines = array(
			/* translators: %s: site URL */
			sprintf( __( 'FckMaleware found suspicious files on %s.', 'fckmaleware' ), home_url() ),
			'',
		);
		foreach ( array_keys( Signatures::SEVERITIES ) as $severity ) {
			if ( $counts[ $severity ] ) {
				$lines[] = sprintf( '%s: %d', ucfirst( $severity ), $counts[ $severity ] );
			}
		}
		$lines[] = '';
		$lines[] = __( 'Review them here:', 'fckmaleware' ) . ' ' . admin_url( 'admin.php?page=fckmaleware' );

		wp_mail(
			$to,
			/* translators: 1: number of findings, 2: site name */
			sprintf( __( '[%2$s] %1$d malware findings need review', 'fckmaleware' ), $counts['total'], get_bloginfo( 'name' ) ),
			implode( "\n", $lines )
		);
	}

	public static function reschedule(): void {
		wp_clear_scheduled_hook( self::CRON_SCAN );
		$schedule = (string) Settings::get( 'schedule' );
		if ( 'off' !== $schedule ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, $schedule, self::CRON_SCAN );
		}
	}

	public static function activate(): void {
		Findings::install();
		Paths::ensure_data_dir();
		if ( false === get_option( Settings::OPTION ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', false );
		}
		self::reschedule();
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( self::CRON_SCAN );
		wp_clear_scheduled_hook( self::CRON_CONTINUE );
	}
}
