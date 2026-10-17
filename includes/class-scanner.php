<?php
/**
 * Resumable file scanner.
 *
 * start() writes the list of files to scan into the private data directory;
 * step() works through it for a fixed time budget, so a scan can be driven by
 * AJAX polling, WP-Cron continuations or a single WP-CLI process alike.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Scanner {

	public const STATE_OPTION  = 'fckmw_scan_state';
	private const LIST_FILE     = 'scan-files.txt';
	private const CHECKSUM_FILE = 'core-checksums.json';

	/** A running scan whose state was not touched for this long is considered dead. */
	private const STALE_AFTER = 600;

	/** @var Signatures */
	private $signatures;

	/** @var Findings */
	private $findings;

	/** @var array<string, string>|null */
	private $checksums;

	/** @var string|null */
	private $uploads_rel;

	public function __construct( Signatures $signatures, Findings $findings ) {
		$this->signatures = $signatures;
		$this->findings   = $findings;
	}

	public function state(): array {
		$state = get_option( self::STATE_OPTION, array() );
		return is_array( $state ) && $state ? $state : array( 'status' => 'idle' );
	}

	public function is_running(): bool {
		$state = $this->state();
		return 'running' === $state['status'] && ( time() - (int) $state['updated'] ) < self::STALE_AFTER;
	}

	/** @return array|\WP_Error New scan state. */
	public function start( string $trigger = 'manual' ) {
		if ( $this->is_running() ) {
			return new \WP_Error( 'fckmw_running', __( 'A scan is already running.', 'fckmaleware' ) );
		}
		if ( ! Paths::ensure_data_dir() ) {
			return new \WP_Error( 'fckmw_storage', __( 'Could not create the plugin data directory under uploads.', 'fckmaleware' ) );
		}

		$total = $this->build_file_list();
		if ( is_wp_error( $total ) ) {
			return $total;
		}

		$integrity = Settings::get( 'core_integrity' ) && $this->fetch_core_checksums();

		$this->findings->clear_open( array( 'builtin', 'integrity', 'location' ) );

		$state = array(
			'id'          => bin2hex( random_bytes( 8 ) ),
			'status'      => 'running',
			'trigger'     => $trigger,
			'total'       => $total,
			'position'    => 0,
			'found'       => 0,
			'integrity'   => $integrity,
			'sig_version' => $this->signatures->version(),
			'started'     => time(),
			'updated'     => time(),
		);
		update_option( self::STATE_OPTION, $state, false );
		return $state;
	}

	/** Process files until the time budget runs out or the list is exhausted. */
	public function step( float $budget = 10.0 ): array {
		$state = $this->state();
		if ( 'running' !== $state['status'] ) {
			return $state;
		}

		$list = Paths::data_dir() . '/' . self::LIST_FILE;
		if ( ! is_readable( $list ) ) {
			return $this->finish( $state, 'failed' );
		}

		$deadline = microtime( true ) + $budget;
		$file     = new \SplFileObject( $list, 'r' );
		$file->seek( (int) $state['position'] );

		while ( $state['position'] < $state['total'] && ! $file->eof() && microtime( true ) < $deadline ) {
			$relative = rtrim( (string) $file->current(), "\r\n" );
			$file->next();
			$state['position']++;
			if ( '' === $relative ) {
				continue;
			}
			foreach ( $this->scan_file( $relative, $state['id'] ) as $row ) {
				$this->findings->add( $row );
				$state['found']++;
			}
		}

		$state['updated'] = time();
		if ( $state['position'] >= $state['total'] || $file->eof() ) {
			$file = null;
			return $this->finish( $state, 'complete' );
		}

		update_option( self::STATE_OPTION, $state, false );
		return $state;
	}

	public function cancel(): array {
		$state = $this->state();
		if ( 'running' === $state['status'] ) {
			$state = $this->finish( $state, 'cancelled' );
		}
		return $state;
	}

	/**
	 * Check one file against core checksums, location rules and signatures.
	 *
	 * @return array<int, array<string, mixed>> Finding rows ready for Findings::add().
	 */
	public function scan_file( string $relative, string $scan_id = '' ): array {
		$absolute = Paths::root() . $relative;
		if ( ! is_file( $absolute ) || ! is_readable( $absolute ) ) {
			return array();
		}
		$type    = Signatures::file_type( $relative, (bool) Settings::get( 'scan_images' ) );
		$content = file_get_contents( $absolute ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $content || null === $type ) {
			return array();
		}
		$hash = hash( 'sha256', $content );
		$rows = array();

		$base = array(
			'scan_id'   => $scan_id,
			'file'      => $relative,
			'file_hash' => $hash,
		);

		$checksums = $this->core_checksums();
		if ( $checksums && 0 !== strpos( $relative, 'wp-content/' ) ) {
			if ( isset( $checksums[ $relative ] ) ) {
				if ( ! hash_equals( $checksums[ $relative ], md5( $content ) ) ) {
					$rows[] = $base + array(
						'source'         => 'integrity',
						'signature_id'   => 'FMW-INT-001',
						'signature_name' => __( 'Modified WordPress core file', 'fckmaleware' ),
						'severity'       => 'high',
					);
				}
			} elseif ( 'php' === $type && Paths::is_core( $relative ) && 'wp-config.php' !== $relative ) {
				$rows[] = $base + array(
					'source'         => 'integrity',
					'signature_id'   => 'FMW-INT-002',
					'signature_name' => __( 'Unknown PHP file in WordPress core directory', 'fckmaleware' ),
					'severity'       => 'high',
				);
			}
		}

		if ( 'php' === $type && '' !== $this->uploads_relative() && 0 === strpos( $relative, $this->uploads_relative() ) ) {
			$rows[] = $base + array(
				'source'         => 'location',
				'signature_id'   => 'FMW-LOC-001',
				'signature_name' => __( 'PHP file in uploads directory', 'fckmaleware' ),
				'severity'       => 'medium',
			);
		}

		foreach ( $this->signatures->match( $content, $type ) as $match ) {
			$rows[] = $base + array(
				'source'         => 'builtin',
				'signature_id'   => $match['signature']['id'],
				'signature_name' => $match['signature']['name'],
				'severity'       => $match['signature']['severity'],
				'line'           => $match['line'],
				'excerpt'        => $match['excerpt'],
			);
		}

		return array_values(
			array_filter(
				$rows,
				function ( array $row ) use ( $relative, $hash ): bool {
					return ! $this->findings->is_ignored( $relative, $row['signature_id'], $hash );
				}
			)
		);
	}

	/** @return int|\WP_Error Number of files queued. */
	private function build_file_list() {
		$handle = fopen( Paths::data_dir() . '/' . self::LIST_FILE, 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $handle ) {
			return new \WP_Error( 'fckmw_storage', __( 'Could not write the scan file list.', 'fckmaleware' ) );
		}
		$count = 0;
		foreach ( self::files( '', (bool) Settings::get( 'scan_images' ) ) as $relative ) {
			fwrite( $handle, $relative . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$count++;
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		return $count;
	}

	/**
	 * Walk the site (or a sub-directory of it) and yield the relative path of
	 * every file the signatures can handle, honouring the size limit and exclusions.
	 *
	 * @return \Generator<int, string>
	 */
	public static function files( string $subdir = '', bool $images = false ): \Generator {
		$root      = Paths::root();
		$start     = '' === $subdir ? $root : Paths::resolve( $subdir );
		$max_bytes = (int) Settings::get( 'max_file_size_mb' ) * MB_IN_BYTES;
		if ( is_wp_error( $start ) || ! is_dir( $start ) ) {
			return;
		}
		$exclude = array_filter(
			array_map(
				static function ( string $dir ) {
					$real = realpath( $dir );
					return false === $real ? null : wp_normalize_path( $real );
				},
				/**
				 * Directories (absolute paths) the scanner skips entirely.
				 *
				 * @param string[] $dirs Defaults to this plugin's own directory and its data directory.
				 */
				(array) apply_filters( 'fckmw_scan_exclude_dirs', array( FCKMW_DIR, Paths::data_dir() ) )
			)
		);

		$directory = new \RecursiveDirectoryIterator( $start, \FilesystemIterator::SKIP_DOTS );
		$filter    = new \RecursiveCallbackFilterIterator(
			$directory,
			static function ( \SplFileInfo $item ) use ( $exclude ): bool {
				if ( $item->isDir() ) {
					if ( in_array( $item->getFilename(), array( '.git', '.svn', '.hg' ), true ) ) {
						return false;
					}
					return ! in_array( wp_normalize_path( (string) $item->getRealPath() ), $exclude, true );
				}
				return true;
			}
		);
		$iterator  = new \RecursiveIteratorIterator( $filter, \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );

		foreach ( $iterator as $item ) {
			/** @var \SplFileInfo $item */
			if ( $item->isLink() || ! $item->isFile() || $item->getSize() > $max_bytes ) {
				continue;
			}
			$relative = Paths::relative( $item->getPathname() );
			if ( null === $relative || false !== strpbrk( $relative, "\r\n" ) ) {
				continue;
			}
			if ( null === Signatures::file_type( $relative, $images ) ) {
				continue;
			}
			yield $relative;
		}
	}

	private function fetch_core_checksums(): bool {
		global $wp_version;
		require_once ABSPATH . 'wp-admin/includes/update.php';

		$checksums = get_core_checksums( $wp_version, get_locale() );
		if ( ! is_array( $checksums ) ) {
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}
		if ( ! is_array( $checksums ) || ! $checksums ) {
			return false;
		}
		$this->checksums = $checksums;
		return false !== file_put_contents( Paths::data_dir() . '/' . self::CHECKSUM_FILE, wp_json_encode( $checksums ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/** @return array<string, string> */
	private function core_checksums(): array {
		if ( null === $this->checksums ) {
			$this->checksums = array();
			$state           = $this->state();
			$path            = Paths::data_dir() . '/' . self::CHECKSUM_FILE;
			if ( ! empty( $state['integrity'] ) && is_readable( $path ) ) {
				$decoded         = json_decode( (string) file_get_contents( $path ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$this->checksums = is_array( $decoded ) ? $decoded : array();
			}
		}
		return $this->checksums;
	}

	private function uploads_relative(): string {
		if ( null === $this->uploads_rel ) {
			$this->uploads_rel = Paths::uploads_relative();
		}
		return $this->uploads_rel;
	}

	private function finish( array $state, string $status ): array {
		$state['status']   = $status;
		$state['finished'] = time();
		$state['updated']  = time();
		update_option( self::STATE_OPTION, $state, false );
		wp_delete_file( Paths::data_dir() . '/' . self::LIST_FILE );
		wp_delete_file( Paths::data_dir() . '/' . self::CHECKSUM_FILE );

		if ( 'complete' === $status ) {
			update_option( 'fckmw_last_scan', $state, false );
			/**
			 * Fires after a scan has worked through every file.
			 *
			 * @param array $state Final scan state.
			 */
			do_action( 'fckmw_scan_complete', $state );
		}
		return $state;
	}
}
