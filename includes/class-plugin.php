<?php
/**
 * Service container and lifecycle: wires components, owns cron and the
 * plugin's activation, deactivation and upgrade routines.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

use Fckmaleware\Detection\Baseline;
use Fckmaleware\Detection\Checksums;
use Fckmaleware\Detection\Engine;
use Fckmaleware\Detection\HeuristicLayer;
use Fckmaleware\Detection\IntegrityLayer;
use Fckmaleware\Detection\LocationLayer;
use Fckmaleware\Detection\SignatureLayer;

final class Plugin {

	public const CRON_SCAN     = 'fckmw_scheduled_scan';
	public const CRON_CONTINUE = 'fckmw_scan_continue';
	public const CRON_DAILY    = 'fckmw_daily_maintenance';
	public const CRON_DB       = 'fckmw_db_scan_continue';

	/** @var Plugin|null */
	private static $instance;

	/** @var array<string, object> */
	private $services = array();

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/** Capability required for every FCK Malware screen and action (network-wide on multisite). */
	public static function capability(): string {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	public function boot(): void {
		if ( ! Schema::is_current() ) {
			self::upgrade();
		}

		add_action( self::CRON_SCAN, array( $this, 'run_scheduled_scan' ) );
		add_action( self::CRON_CONTINUE, array( $this, 'continue_scan' ) );
		add_action( self::CRON_DAILY, array( $this, 'daily_maintenance' ) );
		add_action( self::CRON_DB, array( $this, 'continue_db_scan' ) );
		add_action( 'fckmw_scan_complete', array( $this, 'on_scan_complete' ) );

		( new Updater() )->register();
		$this->signature_updater()->register();
		$this->monitor()->register();
		$this->remediation()->register();
		$this->notifier()->register();
		$this->hardening()->register();

		if ( is_admin() ) {
			( new Admin( $this ) )->register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'fckmaleware', new CLI( $this ) );
		}
	}

	/** @return object */
	private function service( string $name, callable $factory ) {
		if ( ! isset( $this->services[ $name ] ) ) {
			$this->services[ $name ] = $factory();
		}
		return $this->services[ $name ];
	}

	// --- Services -------------------------------------------------------------

	public function signatures(): Signatures {
		return $this->service(
			'signatures',
			static function () {
				/**
				 * Path to a signature database JSON file that replaces the bundled
				 * and downloaded ones (e.g. a self-managed database). Empty by default.
				 *
				 * @param string $path
				 */
				$path = (string) apply_filters( 'fckmw_signature_file', '' );
				try {
					return '' !== $path ? Signatures::from_file( $path ) : ( new SignatureUpdater() )->load();
				} catch ( \RuntimeException $e ) {
					ActivityLog::log( 'signatures.error', $e->getMessage(), array(), 'critical' );
					return new Signatures( array( 'version' => 'unavailable' ) );
				}
			}
		);
	}

	public function signature_updater(): SignatureUpdater {
		return $this->service(
			'signature_updater',
			static function () {
				return new SignatureUpdater();
			}
		);
	}

	public function findings(): Findings {
		return $this->service(
			'findings',
			static function () {
				return new Findings();
			}
		);
	}

	public function file_cache(): FileCache {
		return $this->service(
			'file_cache',
			static function () {
				return new FileCache();
			}
		);
	}

	public function checksums(): Checksums {
		return $this->service(
			'checksums',
			static function () {
				return new Checksums();
			}
		);
	}

	public function baseline(): Baseline {
		return $this->service(
			'baseline',
			static function () {
				return new Baseline();
			}
		);
	}

	/**
	 * Build a detection engine.
	 *
	 * @param array<string, bool>|null $recording Baseline recording state, or null to never record baselines.
	 * @param array{images?: bool} $options
	 */
	public function engine( ?array $recording = null, array $options = array() ): Engine {
		$settings  = Settings::all();
		$integrity = new IntegrityLayer( $this->checksums(), $this->baseline(), (bool) $settings['core_integrity'], (bool) $settings['plugin_integrity'], $recording );
		$layers    = array(
			new LocationLayer( Paths::uploads_relative() ),
			new SignatureLayer( $this->signatures() ),
		);
		if ( $settings['heuristics'] ) {
			$layers[] = new HeuristicLayer( (int) $settings['heuristic_threshold'] );
		}
		$fingerprint = implode( '|', array( (int) $settings['heuristics'], (int) $settings['heuristic_threshold'], (int) $settings['core_integrity'], (int) $settings['plugin_integrity'], (int) ! empty( $options['images'] ) ) );
		return new Engine( $this->signatures(), $integrity, $layers, $fingerprint );
	}

	public function scanner(): Scanner {
		return $this->service(
			'scanner',
			function () {
				return new Scanner( array( $this, 'engine' ), $this->findings(), $this->file_cache() );
			}
		);
	}

	public function db_scanner(): DbScanner {
		return $this->service(
			'db_scanner',
			function () {
				return new DbScanner( $this->signatures(), $this->findings() );
			}
		);
	}

	public function persistence(): Persistence {
		return $this->service(
			'persistence',
			function () {
				return new Persistence( $this->findings(), $this->signatures() );
			}
		);
	}

	public function monitor(): Monitor {
		return $this->service(
			'monitor',
			function () {
				return new Monitor( $this );
			}
		);
	}

	public function quarantine(): Quarantine {
		return $this->service(
			'quarantine',
			static function () {
				return new Quarantine();
			}
		);
	}

	public function imunify(): Imunify {
		return new Imunify( (string) Settings::get( 'imunify_binary' ), (bool) Settings::get( 'imunify_use_sudo' ) );
	}

	public function hardening(): Hardening {
		return $this->service(
			'hardening',
			static function () {
				return new Hardening();
			}
		);
	}

	public function notifier(): Notifier {
		return $this->service(
			'notifier',
			static function () {
				return new Notifier();
			}
		);
	}

	public function remediation(): Remediation {
		return $this->service(
			'remediation',
			function () {
				return new Remediation( $this );
			}
		);
	}

	/** @return true|\WP_Error */
	public function quarantine_finding( int $id ) {
		$key = $this->remediation()->quarantine( $id );
		return is_wp_error( $key ) ? $key : true;
	}

	public function release_quarantine_findings( string $key, string $status ): void {
		$this->findings()->release_quarantine( $key, $status );
	}

	/**
	 * Whether a file may be quarantined: anything outside core locations, plus
	 * files in core locations that the integrity check found are not part of WordPress.
	 */
	public function can_quarantine( string $file ): bool {
		return ! Paths::is_core( $file ) || $this->findings()->has_open( $file, 'FMW-INT-002' );
	}

	/**
	 * Pull Imunify's malicious-file list for this site into the findings table.
	 *
	 * @return int|\WP_Error Number of open Imunify findings.
	 */
	public function sync_imunify() {
		$files = $this->imunify()->malicious_files( Paths::root() );
		if ( is_wp_error( $files ) ) {
			ActivityLog::log( 'imunify.error', $files->get_error_message(), array(), 'warning' );
			return $files;
		}

		$scan_id = 'imunify:' . time();
		$count   = 0;
		foreach ( $files as $item ) {
			// Entries Imunify already cleaned or restored are not actionable here.
			if ( in_array( strtolower( $item['status'] ), array( 'cleanup_done', 'cleaned', 'restored_original', 'removed' ), true ) ) {
				continue;
			}
			$result = $this->findings()->upsert(
				array(
					'scan_id'        => $scan_id,
					'source'         => 'imunify',
					'file'           => $item['file'],
					'signature_id'   => 'IMUNIFY:' . substr( $item['signature'], 0, 180 ),
					'signature_name' => $item['signature'],
					'family'         => 'Imunify360',
					'severity'       => 'critical',
					'confidence'     => 90,
					'verdict'        => 'malicious',
					'evidence'       => __( 'Reported by the Imunify360 agent on this server.', 'fckmaleware' ),
					'remediation'    => 'quarantine',
				)
			);
			if ( 'ignored' !== $result['outcome'] ) {
				$count++;
			}
		}
		$this->findings()->resolve_stale( $scan_id, array( 'imunify' ) );
		Store::set( 'fckmw_imunify_last_sync', time() );
		ActivityLog::log( 'imunify.sync', sprintf( /* translators: %d: count */ __( 'Imunify360 sync: %d open detections.', 'fckmaleware' ), $count ), array( 'count' => $count ) );
		return $count;
	}

	// --- Cron -----------------------------------------------------------------

	public function run_scheduled_scan(): void {
		$state = $this->scanner()->start( (string) Settings::get( 'scheduled_mode' ), 'scheduled' );
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
		// A scheduled file scan is followed by the database scan and persistence checks.
		if ( 'scheduled' === $state['trigger'] && Settings::get( 'scheduled_db_scan' ) ) {
			$this->persistence()->run( 'scheduled' );
			if ( ! is_wp_error( $this->db_scanner()->start( 'scheduled' ) ) ) {
				$this->continue_db_scan();
			}
		}
	}

	public function continue_db_scan(): void {
		$state = $this->db_scanner()->step( 20.0 );
		if ( 'running' === $state['status'] && ! wp_next_scheduled( self::CRON_DB ) ) {
			wp_schedule_single_event( time() + 30, self::CRON_DB );
		}
	}

	public function daily_maintenance(): void {
		ActivityLog::prune();
		$this->findings()->prune_resolved( 90 );
		$expired = $this->quarantine()->expire( (int) Settings::get( 'quarantine_retention' ) );
		if ( $expired ) {
			ActivityLog::log( 'quarantine.expired', sprintf( /* translators: %d: count */ __( 'Deleted %d quarantined copies past the retention period.', 'fckmaleware' ), $expired ), array( 'count' => $expired ) );
		}
		$this->persistence()->run( 'daily' );
	}

	// --- Lifecycle ------------------------------------------------------------

	public static function reschedule(): void {
		wp_clear_scheduled_hook( self::CRON_SCAN );
		$schedule = (string) Settings::get( 'schedule' );
		if ( 'off' !== $schedule ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, $schedule, self::CRON_SCAN );
		}
		if ( ! wp_next_scheduled( self::CRON_DAILY ) ) {
			wp_schedule_event( time() + 2 * HOUR_IN_SECONDS, 'daily', self::CRON_DAILY );
		}
		if ( ! wp_next_scheduled( SignatureUpdater::CRON ) ) {
			wp_schedule_event( time() + 10 * MINUTE_IN_SECONDS, 'twicedaily', SignatureUpdater::CRON );
		}
	}

	/** Bring 0.x data forward: schema v2, settings and quarantine index into network storage. */
	public static function upgrade(): void {
		$previous = (string) get_option( Schema::OPTION, '' );
		if ( ! Schema::install() ) {
			return; // Retried on the next request; the error is shown in the admin.
		}

		if ( is_multisite() ) {
			foreach ( array( Settings::OPTION, 'fckmw_quarantine', 'fckmw_last_scan', 'fckmw_imunify_last_sync' ) as $option ) {
				$legacy = get_option( $option, null );
				if ( null !== $legacy && false === get_site_option( $option, false ) ) {
					update_site_option( $option, $legacy );
				}
			}
		}
		// 0.x kept scan state with a different shape; a stale running scan would never finish.
		$state = Store::get( Scanner::STATE_OPTION, array() );
		if ( is_array( $state ) && isset( $state['status'] ) && ! isset( $state['phase'] ) ) {
			Store::delete( Scanner::STATE_OPTION );
		}
		Paths::ensure_data_dir();
		self::reschedule();

		if ( '' !== $previous && Schema::VERSION !== $previous ) {
			ActivityLog::log( 'plugin.upgrade', sprintf( /* translators: 1: old schema, 2: new schema */ __( 'Data upgraded from schema %1$s to %2$s.', 'fckmaleware' ), $previous, Schema::VERSION ) );
		}
	}

	public static function activate(): void {
		self::upgrade();
		if ( false === Store::get( Settings::OPTION, false ) ) {
			Store::set( Settings::OPTION, Settings::defaults() );
		}
		ActivityLog::log( 'plugin.activate', __( 'FCK Malware activated.', 'fckmaleware' ) );
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( self::CRON_SCAN );
		wp_clear_scheduled_hook( self::CRON_CONTINUE );
		wp_clear_scheduled_hook( self::CRON_DAILY );
		wp_clear_scheduled_hook( self::CRON_DB );
		wp_clear_scheduled_hook( Monitor::CRON_QUEUE );
		wp_clear_scheduled_hook( SignatureUpdater::CRON );
		wp_clear_scheduled_hook( Notifier::CRON );
	}
}
