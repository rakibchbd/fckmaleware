<?php
/**
 * Integration center for hosting security products: Imunify360, ImunifyAV
 * and cPGuard.
 *
 * Only documented local interfaces are used. Imunify360 and ImunifyAV ship a
 * command-line agent (imunify360-agent / imunify-antivirus) whose
 * "malware malicious list --json" output FCK Malware can import; it is run
 * without a shell (proc_open with an argument array) from a fixed list of
 * binary paths, never from a path or command typed into a setting.
 *
 * cPGuard has no documented interface that a WordPress site user can call,
 * so it is only detected (installation folder visible to PHP) and reported;
 * it is managed from its own panel. Nothing here claims a connection that
 * was not tested.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class ServerIntegrations {

	public const TESTS_OPTION = 'fckmw_integration_tests';

	/** Folders a cPGuard installation is known to create. */
	private const CPGUARD_PATHS = array( '/opt/cpguard', '/usr/local/cpguard' );

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** Restrictions that stop PHP from seeing or calling server tools. */
	public static function environment(): array {
		$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
		return array(
			'proc_open'   => function_exists( 'proc_open' ) && ! in_array( 'proc_open', $disabled, true ),
			'open_basedir' => '' !== (string) ini_get( 'open_basedir' ),
		);
	}

	/**
	 * Every provider with its detection and connection state.
	 *
	 * @return array<string, array>
	 */
	public function providers(): array {
		$settings = Settings::all();
		$env      = self::environment();
		$found    = Imunify::detected();
		$active   = $this->plugin->imunify();
		$tests    = (array) Store::get( self::TESTS_OPTION, array() );
		$last     = (int) Store::get( 'fckmw_imunify_last_sync', 0 );
		$out      = array();

		foreach ( array( 'imunify360' => 'Imunify360', 'imunifyav' => 'ImunifyAV' ) as $id => $name ) {
			$binary   = $found[ $name ] ?? '';
			$selected = '' !== $active->binary() && $active->product() === $name;
			$out[ $id ] = array(
				'id'           => $id,
				'name'         => $name,
				'vendor'       => 'CloudLinux',
				'detected'     => '' !== $binary,
				'binary'       => $binary,
				'enabled'      => $settings['imunify_enabled'] && $selected,
				'selected'     => $selected,
				'test'         => $tests[ $id ] ?? null,
				'last_sync'    => $selected ? $last : 0,
				'capabilities' => array(
					__( 'Import the malicious-file list for this site as findings', 'fckmaleware' ),
					__( 'Start an on-demand scan of this site', 'fckmaleware' ),
					__( 'Report the agent version', 'fckmaleware' ),
				),
				'actions'      => array( 'test', 'sync', 'scan' ),
				'blocked'      => $env['proc_open'] ? '' : __( 'PHP\'s proc_open() is disabled on this server, so the agent cannot be called from WordPress.', 'fckmaleware' ),
				'instructions' => array(
					__( 'Turn on "Use the server scanner" below and save.', 'fckmaleware' ),
					__( 'Click "Test connection". The agent usually only answers root; if the test reports a permission error, ask your host for a sudo rule that lets the web server user run exactly this binary, then enable "Run through sudo".', 'fckmaleware' ),
					__( 'Click "Sync now" to import detections. With "Sync after every FCK Malware scan" on, this happens automatically.', 'fckmaleware' ),
				),
				'troubleshooting' => array(
					__( '"Not found": the agent is not installed, or open_basedir hides /usr/bin from PHP.', 'fckmaleware' ),
					__( '"exited with code 1" or "permission denied": the web server user may not run the agent; see the sudo step above.', 'fckmaleware' ),
					__( '"timed out": the agent is busy; try again in a few minutes.', 'fckmaleware' ),
				),
			);
		}

		$cpguard = '';
		foreach ( self::CPGUARD_PATHS as $path ) {
			if ( @is_dir( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir may forbid the check.
				$cpguard = $path;
				break;
			}
		}
		$out['cpguard'] = array(
			'id'           => 'cpguard',
			'name'         => 'cPGuard',
			'vendor'       => 'OpsShield',
			'detected'     => '' !== $cpguard,
			'binary'       => $cpguard,
			'enabled'      => false,
			'selected'     => false,
			'test'         => $tests['cpguard'] ?? null,
			'last_sync'    => 0,
			'capabilities' => array( __( 'Detection of the installation (status only)', 'fckmaleware' ) ),
			'actions'      => array( 'test' ),
			'blocked'      => '',
			'instructions' => array(
				__( 'cPGuard runs at server level and is managed from its own panel (cPanel, Plesk, DirectAdmin or the cPGuard dashboard).', 'fckmaleware' ),
				__( 'It does not publish an interface a WordPress site account can call, so FCK Malware does not import its results or trigger its scans. Both products can run side by side.', 'fckmaleware' ),
				__( 'To avoid two products acting on the same file, keep FCK Malware\'s automatic quarantine off and review cPGuard\'s actions in its panel.', 'fckmaleware' ),
			),
			'troubleshooting' => array(
				__( '"Not detected" can also mean open_basedir hides the installation folder from PHP.', 'fckmaleware' ),
			),
		);
		return $out;
	}

	/**
	 * Test a provider and remember the outcome. Limited to one test per
	 * provider every 15 seconds so the button cannot be used to load the server.
	 *
	 * @return array{ok: bool, message: string, time: int}|\WP_Error
	 */
	public function test( string $id ) {
		$providers = $this->providers();
		if ( ! isset( $providers[ $id ] ) ) {
			return new \WP_Error( 'fckmw_integration', __( 'Unknown integration.', 'fckmaleware' ) );
		}
		$throttle = 'fckmw_itest_' . $id;
		if ( get_site_transient( $throttle ) ) {
			return new \WP_Error( 'fckmw_busy', __( 'A test just ran. Wait a few seconds and try again.', 'fckmaleware' ) );
		}
		set_site_transient( $throttle, 1, 15 );

		$provider = $providers[ $id ];
		if ( 'cpguard' === $id ) {
			$result = $provider['detected']
				? array( 'ok' => true, 'message' => sprintf( /* translators: %s: path */ __( 'Installation folder found at %s. Status only; there is no API to connect to.', 'fckmaleware' ), $provider['binary'] ) )
				: array( 'ok' => false, 'message' => __( 'cPGuard was not detected on this server.', 'fckmaleware' ) );
		} elseif ( ! $provider['detected'] ) {
			$result = array( 'ok' => false, 'message' => sprintf( /* translators: %s: product */ __( '%s was not found on this server.', 'fckmaleware' ), $provider['name'] ) );
		} else {
			$agent   = new Imunify( $provider['binary'], (bool) Settings::get( 'imunify_use_sudo' ), 20 );
			$version = $agent->version();
			$result  = is_wp_error( $version )
				? array( 'ok' => false, 'message' => $version->get_error_message() )
				: array( 'ok' => true, 'message' => sprintf( /* translators: %s: version */ __( 'Agent answered: version %s.', 'fckmaleware' ), $version ) );
		}
		$result['time'] = time();
		$tests          = (array) Store::get( self::TESTS_OPTION, array() );
		$tests[ $id ]   = $result;
		Store::set( self::TESTS_OPTION, $tests );
		ActivityLog::log( 'integration.test', sprintf( /* translators: 1: product, 2: result */ __( '%1$s connection test: %2$s', 'fckmaleware' ), $provider['name'], $result['message'] ), array( 'provider' => $id, 'ok' => $result['ok'] ), $result['ok'] ? 'info' : 'warning' );
		return $result;
	}

	/** One-line status for the overview: configured product or "Not configured". */
	public function summary(): array {
		foreach ( $this->providers() as $provider ) {
			if ( $provider['enabled'] ) {
				$test = $provider['test'];
				if ( is_array( $test ) && ! $test['ok'] ) {
					return array( 'label' => sprintf( /* translators: %s: product */ __( '%s: connection failed', 'fckmaleware' ), $provider['name'] ), 'tone' => 'warn' );
				}
				return array( 'label' => sprintf( /* translators: %s: product */ __( '%s connected', 'fckmaleware' ), $provider['name'] ), 'tone' => is_array( $test ) ? 'good' : 'neutral' );
			}
		}
		foreach ( $this->providers() as $provider ) {
			if ( $provider['detected'] ) {
				return array( 'label' => sprintf( /* translators: %s: product */ __( '%s detected, not configured', 'fckmaleware' ), $provider['name'] ), 'tone' => 'neutral' );
			}
		}
		return array( 'label' => __( 'Not configured', 'fckmaleware' ), 'tone' => 'off' );
	}
}
