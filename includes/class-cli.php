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
	 * Run a full scan in this process and list open findings.
	 *
	 * ## OPTIONS
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
		$scanner = $this->plugin->scanner();
		$state   = $scanner->start( 'cli' );
		if ( is_wp_error( $state ) ) {
			\WP_CLI::error( $state->get_error_message() );
		}

		$progress = \WP_CLI\Utils\make_progress_bar( 'Scanning files', (int) $state['total'] );
		$done     = 0;
		while ( 'running' === $state['status'] ) {
			$state = $scanner->step( 5.0 );
			$progress->tick( (int) $state['position'] - $done );
			$done = (int) $state['position'];
		}
		$progress->finish();

		if ( 'complete' !== $state['status'] ) {
			\WP_CLI::error( "Scan ended with status: {$state['status']}" );
		}
		\WP_CLI::log( sprintf( 'Scanned %d files with signatures v%s.', $state['total'], $state['sig_version'] ) );

		$this->findings( array(), $assoc );

		$counts = $this->plugin->findings()->open_counts();
		if ( $counts['critical'] + $counts['high'] > 0 ) {
			\WP_CLI::halt( 1 );
		}
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
		$result = $this->plugin->findings()->query( $assoc['status'] ?? 'open', 1, 10000 );
		if ( ! $result['rows'] ) {
			\WP_CLI::success( 'No findings.' );
			return;
		}
		\WP_CLI\Utils\format_items( $assoc['format'] ?? 'table', $result['rows'], array( 'id', 'severity', 'file', 'line', 'signature_id', 'signature_name', 'source' ) );
	}

	/**
	 * Move the file behind a finding to quarantine.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Finding ID.
	 *
	 * @when after_wp_load
	 */
	public function quarantine( array $args ): void {
		$result = $this->plugin->quarantine_finding( (int) $args[0] );
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
		}
		\WP_CLI::success( 'File quarantined.' );
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
