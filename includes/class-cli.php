<?php
/**
 * WP-CLI commands: `wp fckmaleware <command>`.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class CLI {

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Run a scan in this process and list open findings.
	 *
	 * ## OPTIONS
	 *
	 * [--mode=<mode>]
	 * : Scan mode.
	 * ---
	 * default: standard
	 * options:
	 *   - quick
	 *   - standard
	 *   - deep
	 *   - custom
	 *   - core
	 *   - recent
	 * ---
	 *
	 * [--dir=<dir>]
	 * : Directory for --mode=custom, relative to the WordPress root.
	 *
	 * [--days=<days>]
	 * : Look-back window for --mode=recent.
	 * ---
	 * default: 7
	 * ---
	 *
	 * [--format=<format>]
	 * : Output format for the findings.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * ## EXIT STATUS
	 *
	 * Exits with 1 if any open critical or high findings remain, so it can gate deploys.
	 *
	 * @when after_wp_load
	 */
	public function scan( array $args, array $assoc ): void {
		$scanner  = $this->plugin->scanner();
		$progress = null;
		$done     = 0;
		$state    = $scanner->run(
			$assoc['mode'] ?? 'standard',
			'cli',
			array( 'scope' => $assoc['dir'] ?? '', 'days' => (int) ( $assoc['days'] ?? 7 ) ),
			static function ( array $state ) use ( &$progress, &$done ) {
				if ( 'scanning' !== ( $state['phase'] ?? '' ) && 'done' !== ( $state['phase'] ?? '' ) ) {
					return;
				}
				if ( null === $progress ) {
					$progress = \WP_CLI\Utils\make_progress_bar( 'Scanning files', (int) $state['total'] );
				}
				$progress->tick( (int) $state['position'] - $done );
				$done = (int) $state['position'];
			}
		);
		if ( is_wp_error( $state ) ) {
			\WP_CLI::error( $state->get_error_message() );
		}
		if ( $progress ) {
			$progress->finish();
		}

		if ( 'complete' !== $state['status'] ) {
			\WP_CLI::error( "Scan ended with status: {$state['status']}" );
		}
		\WP_CLI::log( sprintf( 'Checked %d files (%d unchanged skipped) with signatures v%s: %d detections, %d new, %d resolved.', $state['total'], $state['skipped'], $state['sig_version'], $state['found'], $state['new'], $state['resolved'] ?? 0 ) );

		$this->findings( array(), $assoc );

		$counts = $this->plugin->findings()->open_counts();
		if ( $counts['critical'] + $counts['high'] > 0 ) {
			\WP_CLI::halt( 1 );
		}
	}

	/**
	 * Scan posts, options and comments (every site on multisite) for injected code.
	 *
	 * @subcommand db-scan
	 * @when after_wp_load
	 */
	public function db_scan(): void {
		$state = $this->plugin->db_scanner()->run( 'cli' );
		if ( is_wp_error( $state ) ) {
			\WP_CLI::error( $state->get_error_message() );
		}
		\WP_CLI::success( sprintf( 'Database scan complete: %d candidate rows, %d detections, %d new, %d resolved.', $state['rows'], $state['found'], $state['new'], $state['resolved'] ) );
		$this->findings( array(), array( 'source' => 'database' ) );
	}

	/**
	 * Check for persistence: hidden or new admins, role changes, cron payloads, eval()'d hook callbacks.
	 *
	 * @when after_wp_load
	 */
	public function persistence(): void {
		$result = $this->plugin->persistence()->run( 'cli' );
		\WP_CLI::success( sprintf( 'Persistence check: %d findings, %d new, %d resolved.', $result['found'], $result['new'], $result['resolved'] ) );
		$this->findings( array(), array( 'source' => 'behaviour' ) );
	}

	/**
	 * List findings.
	 *
	 * ## OPTIONS
	 *
	 * [--status=<status>]
	 * : Finding status to list.
	 * ---
	 * default: open
	 * options:
	 *   - open
	 *   - quarantined
	 *   - ignored
	 *   - resolved
	 * ---
	 *
	 * [--source=<source>]
	 * : Only findings from one layer (signature, heuristic, integrity, location, database, behaviour, imunify, ai).
	 *
	 * [--format=<format>]
	 * : Output format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 * ---
	 *
	 * @when after_wp_load
	 */
	public function findings( array $args, array $assoc ): void {
		$result = $this->plugin->findings()->query( array( 'status' => $assoc['status'] ?? 'open', 'source' => $assoc['source'] ?? '' ), 1, 10000 );
		if ( ! $result['rows'] ) {
			\WP_CLI::success( 'No findings.' );
			return;
		}
		\WP_CLI\Utils\format_items( $assoc['format'] ?? 'table', $result['rows'], array( 'id', 'severity', 'verdict', 'confidence', 'file', 'line', 'signature_id', 'signature_name', 'source' ) );
	}

	/**
	 * Move the file behind a finding to quarantine (verified backup first).
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Finding ID.
	 *
	 * @when after_wp_load
	 */
	public function quarantine( array $args ): void {
		$key = $this->plugin->remediation()->quarantine( (int) $args[0] );
		if ( is_wp_error( $key ) ) {
			\WP_CLI::error( $key->get_error_message() );
		}
		\WP_CLI::success( "File quarantined (key {$key})." );
	}

	/**
	 * Replace a modified or missing core / wordpress.org plugin file with the verified official copy.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Finding ID (FMW-INT-001, FMW-INT-003 or FMW-INT-010).
	 *
	 * @when after_wp_load
	 */
	public function repair( array $args ): void {
		$result = $this->plugin->remediation()->repair( (int) $args[0] );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		\WP_CLI::success( 'File restored from the verified official copy. If a modified version existed it is kept as a backup (see quarantine-list).' );
	}

	/**
	 * Restore a quarantined file or a pre-repair backup.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : Quarantine key (see `wp fckmaleware quarantine-list`).
	 *
	 * @when after_wp_load
	 */
	public function restore( array $args ): void {
		$result = $this->plugin->remediation()->restore( (string) $args[0] );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		\WP_CLI::success( 'Restored.' );
	}

	/**
	 * List quarantined files and backups.
	 *
	 * @subcommand quarantine-list
	 * @when after_wp_load
	 */
	public function quarantine_list(): void {
		$rows = array();
		foreach ( $this->plugin->quarantine()->all() as $key => $item ) {
			$rows[] = array( 'key' => $key, 'kind' => $item['kind'] ?? 'quarantine', 'file' => $item['file'], 'size' => $item['size'], 'date' => gmdate( 'Y-m-d H:i', (int) $item['time'] ) );
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'key', 'kind', 'file', 'size', 'date' ) );
	}

	/**
	 * Undo every change recorded in a restore point.
	 *
	 * ## OPTIONS
	 *
	 * [<point>]
	 * : Restore point ID. Omit to list restore points.
	 *
	 * @when after_wp_load
	 */
	public function rollback( array $args ): void {
		$remediation = $this->plugin->remediation();
		if ( ! $args ) {
			$rows = array();
			foreach ( $remediation->points() as $id => $point ) {
				$rows[] = array( 'id' => $id, 'label' => $point['label'], 'items' => count( $point['items'] ), 'date' => gmdate( 'Y-m-d H:i', (int) $point['time'] ) );
			}
			\WP_CLI\Utils\format_items( 'table', $rows, array( 'id', 'label', 'items', 'date' ) );
			return;
		}
		$result = $remediation->rollback( (string) $args[0] );
		foreach ( $result['failed'] as $failure ) {
			\WP_CLI::warning( $failure );
		}
		\WP_CLI::success( sprintf( '%d files restored.', $result['restored'] ) );
	}

	/**
	 * Accept a finding as legitimate (updates baselines/snapshots where relevant, otherwise ignores it).
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Finding ID.
	 *
	 * @when after_wp_load
	 */
	public function accept( array $args ): void {
		$result = $this->plugin->remediation()->accept( (int) $args[0] );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		\WP_CLI::success( 'Accepted.' );
	}

	/**
	 * List the built-in signatures.
	 *
	 * @when after_wp_load
	 */
	public function signatures(): void {
		$sigs = $this->plugin->signatures();
		\WP_CLI::log( sprintf( 'Signature database v%s', $sigs->version() ) );
		\WP_CLI\Utils\format_items( 'table', $sigs->all(), array( 'id', 'severity', 'name' ) );
	}

	/**
	 * Manage signed signature-database updates.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status, update or rollback.
	 * ---
	 * options:
	 *   - status
	 *   - update
	 *   - rollback
	 * ---
	 *
	 * @subcommand signature-updates
	 * @when after_wp_load
	 */
	public function signature_updates( array $args ): void {
		$updater = $this->plugin->signature_updater();
		switch ( $args[0] ) {
			case 'update':
				$result = $updater->check();
				if ( 'error' === $result['status'] ) {
					\WP_CLI::error( $result['message'] );
				}
				\WP_CLI::success( 'updated' === $result['status'] ? "Updated to {$result['version']}." : "Already current ({$result['version']})." );
				break;
			case 'rollback':
				$result = $updater->rollback();
				if ( is_wp_error( $result ) ) {
					\WP_CLI::error( $result->get_error_message() );
				}
				\WP_CLI::success( "Active signature database: {$result}." );
				break;
			default:
				$state = $updater->state();
				\WP_CLI::log( 'Feed:        ' . SignatureUpdater::feed_url() );
				\WP_CLI::log( 'Active:      ' . $this->plugin->signatures()->version() );
				\WP_CLI::log( 'Downloaded:  ' . implode( ', ', array_column( $state['installed'], 'version' ) ) );
				\WP_CLI::log( 'Last check:  ' . ( $state['last_check'] ? gmdate( 'Y-m-d H:i', $state['last_check'] ) . ' UTC' : 'never' ) );
				\WP_CLI::log( 'Last error:  ' . ( $state['last_error'] ? $state['last_error'] : '-' ) );
		}
	}

	/**
	 * Talk to the Imunify360 agent.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : status, sync or scan.
	 * ---
	 * options:
	 *   - status
	 *   - sync
	 *   - scan
	 * ---
	 *
	 * @when after_wp_load
	 */
	public function imunify( array $args ): void {
		$imunify = $this->plugin->imunify();
		switch ( $args[0] ) {
			case 'status':
				$version = $imunify->version();
				if ( is_wp_error( $version ) ) {
					\WP_CLI::error( $version->get_error_message() );
				}
				\WP_CLI::success( sprintf( '%s reachable, version %s', $imunify->binary(), $version ) );
				break;
			case 'sync':
				$count = $this->plugin->sync_imunify();
				if ( is_wp_error( $count ) ) {
					\WP_CLI::error( $count->get_error_message() );
				}
				\WP_CLI::success( "Synced {$count} Imunify360 detections." );
				break;
			case 'scan':
				$result = $imunify->start_scan( Paths::root() );
				if ( is_wp_error( $result ) ) {
					\WP_CLI::error( $result->get_error_message() );
				}
				\WP_CLI::success( 'Imunify360 on-demand scan started.' );
				break;
		}
	}
}
