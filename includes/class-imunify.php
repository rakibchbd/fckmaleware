<?php
/**
 * Imunify360 / ImunifyAV integration through the local agent CLI.
 *
 * The agent prints JSON when called with --json. It is normally only usable
 * by root, so most hosts need either a PHP user that the agent accepts or a
 * narrowly scoped sudoers rule (see README).
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Imunify {

	/** Paths the binary setting may point to. Anything else is rejected. */
	public const KNOWN_BINARIES = array(
		'/usr/bin/imunify360-agent',
		'/usr/sbin/imunify360-agent',
		'/usr/bin/imunify-antivirus',
		'/usr/sbin/imunify-antivirus',
	);

	private const SUDO = '/usr/bin/sudo';

	/** @var string */
	private $binary;

	/** @var bool */
	private $use_sudo;

	/** @var int */
	private $timeout;

	public function __construct( string $binary = '', bool $use_sudo = false, int $timeout = 60 ) {
		$this->binary   = in_array( $binary, self::KNOWN_BINARIES, true ) ? $binary : self::detect_binary();
		$this->use_sudo = $use_sudo;
		$this->timeout  = max( 5, $timeout );
	}

	public static function detect_binary(): string {
		foreach ( self::KNOWN_BINARIES as $path ) {
			if ( @is_executable( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir may forbid the check.
				return $path;
			}
		}
		return '';
	}

	public function binary(): string {
		return $this->binary;
	}

	/** Product behind a binary path: "Imunify360" or "ImunifyAV". */
	public static function product_of( string $binary ): string {
		return false !== strpos( basename( $binary ), 'imunify-antivirus' ) ? 'ImunifyAV' : 'Imunify360';
	}

	public function product(): string {
		return '' === $this->binary ? 'Imunify360' : self::product_of( $this->binary );
	}

	/** Known binaries that exist on this server, keyed by product. */
	public static function detected(): array {
		$out = array();
		foreach ( self::KNOWN_BINARIES as $path ) {
			if ( @is_executable( $path ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors -- open_basedir may forbid the check.
				$out[ self::product_of( $path ) ] = $out[ self::product_of( $path ) ] ?? $path;
			}
		}
		return $out;
	}

	public function is_available(): bool {
		return '' !== $this->binary && function_exists( 'proc_open' );
	}

	/** @return string|\WP_Error */
	public function version() {
		$result = $this->run( array( 'version' ) );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		return trim( $result['stdout'] );
	}

	/** @return array|\WP_Error */
	public function start_scan( string $path ) {
		return $this->run( array( 'malware', 'on-demand', 'start', '--path', $path ) );
	}

	/** @return array|\WP_Error Decoded JSON. */
	public function scan_status() {
		return $this->run_json( array( 'malware', 'on-demand', 'status', '--json' ) );
	}

	/**
	 * Malicious files Imunify knows about, limited to those under $root.
	 *
	 * @return array<int, array{file: string, signature: string, status: string}>|\WP_Error
	 */
	public function malicious_files( string $root, int $limit = 1000 ) {
		$data = $this->run_json( array( 'malware', 'malicious', 'list', '--json', '--limit', (string) $limit ) );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		return self::normalize_malicious( $data, $root );
	}

	/**
	 * Turn the agent's malicious-list JSON into a flat list of files under $root.
	 *
	 * The agent has used both {"items": [...]} and {"data": {"items": [...]}}
	 * envelopes across versions, and "file"/"path" for the file name, so all
	 * of those are accepted.
	 *
	 * @return array<int, array{file: string, signature: string, status: string}>
	 */
	public static function normalize_malicious( array $data, string $root ): array {
		$items = $data['items'] ?? $data['data']['items'] ?? $data['data'] ?? $data;
		if ( ! is_array( $items ) ) {
			return array();
		}
		$root = rtrim( $root, '/' ) . '/';
		$out  = array();
		foreach ( $items as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}
			$file = (string) ( $item['file'] ?? $item['path'] ?? '' );
			if ( '' === $file || 0 !== strpos( $file, $root ) ) {
				continue;
			}
			$out[] = array(
				'file'      => substr( $file, strlen( $root ) ),
				'signature' => (string) ( $item['type'] ?? $item['signature'] ?? $item['malicious_type'] ?? 'Imunify360 detection' ),
				'status'    => (string) ( $item['status'] ?? '' ),
			);
		}
		return $out;
	}

	/** @return array|\WP_Error */
	private function run_json( array $args ) {
		$result = $this->run( $args );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		$data = json_decode( $result['stdout'], true );
		if ( ! is_array( $data ) ) {
			return new \WP_Error( 'fckmw_imunify_json', __( 'Imunify returned output that is not JSON.', 'fckmaleware' ), $result );
		}
		return $data;
	}

	/**
	 * Run the agent without a shell (proc_open with an argv array), with a timeout.
	 *
	 * @return array{code: int, stdout: string, stderr: string}|\WP_Error
	 */
	private function run( array $args ) {
		if ( ! $this->is_available() ) {
			return new \WP_Error( 'fckmw_imunify_missing', __( 'The Imunify agent was not found, or proc_open is disabled.', 'fckmaleware' ) );
		}

		$cmd = array_merge( array( $this->binary ), $args );
		if ( $this->use_sudo ) {
			array_unshift( $cmd, self::SUDO, '-n' );
		}

		$pipes = array();
		$proc  = proc_open( $cmd, array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes );
		if ( ! is_resource( $proc ) ) {
			return new \WP_Error( 'fckmw_imunify_exec', __( 'Could not start the Imunify agent.', 'fckmaleware' ) );
		}

		stream_set_blocking( $pipes[1], false );
		stream_set_blocking( $pipes[2], false );
		$stdout   = '';
		$stderr   = '';
		$deadline = microtime( true ) + $this->timeout;

		while ( true ) {
			$stdout .= (string) stream_get_contents( $pipes[1] );
			$stderr .= (string) stream_get_contents( $pipes[2] );
			$status  = proc_get_status( $proc );
			if ( ! $status['running'] ) {
				$code = (int) $status['exitcode'];
				break;
			}
			if ( microtime( true ) > $deadline ) {
				proc_terminate( $proc );
				fclose( $pipes[1] );
				fclose( $pipes[2] );
				proc_close( $proc );
				return new \WP_Error( 'fckmw_imunify_timeout', __( 'The Imunify agent timed out.', 'fckmaleware' ) );
			}
			$read   = array( $pipes[1], $pipes[2] );
			$write  = null;
			$except = null;
			stream_select( $read, $write, $except, 0, 200000 );
		}

		$stdout .= (string) stream_get_contents( $pipes[1] );
		$stderr .= (string) stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		proc_close( $proc );

		if ( 0 !== $code ) {
			return new \WP_Error(
				'fckmw_imunify_failed',
				/* translators: 1: exit code, 2: error output */
				sprintf( __( 'Imunify agent exited with code %1$d: %2$s', 'fckmaleware' ), $code, trim( $stderr ) ?: trim( $stdout ) ),
				array( 'stdout' => $stdout, 'stderr' => $stderr )
			);
		}

		return array( 'code' => $code, 'stdout' => $stdout, 'stderr' => $stderr );
	}
}
