<?php
/**
 * Resumable, bounded file scanner.
 *
 * A scan runs in three phases, each split into time-boxed steps so it works
 * on shared hosting with short execution limits:
 *
 *   listing     Work units (the root, wp-admin, wp-includes, each plugin,
 *               each theme, each uploads year, ...) are walked one at a time
 *               and matching files appended to a list file.
 *   scanning    The list is read from a stored byte offset in batches; each
 *               file goes through the detection engine unless the file cache
 *               shows it is unchanged and clean.
 *   finalizing  Missing core files, stale findings, events and hooks.
 *
 * Steps are driven by admin AJAX, WP-Cron, system cron or WP-CLI, and hold a
 * lock so two workers never process the same batch.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

use Fckmaleware\Detection\Engine;
use Fckmaleware\Detection\FileContext;

final class Scanner {

	public const STATE_OPTION = 'fckmw_scan_state';
	public const MODES        = array( 'quick', 'standard', 'deep', 'custom', 'core', 'recent', 'plugins', 'uploads' );

	private const LOCK        = 'scan';
	private const LIST_FILE   = 'scan-files.txt';
	private const BATCH       = 100;
	private const STALE_AFTER = 900;

	/** Sources whose open file findings a completed full scan may resolve. */
	private const FILE_SOURCES = array( 'signature', 'heuristic', 'integrity', 'location' );

	/** @var callable(?array, array): Engine */
	private $engine_factory;

	/** @var Findings */
	private $findings;

	/** @var FileCache */
	private $cache;

	/**
	 * @param callable $engine_factory function( ?array $baseline_recording, array $options ): Engine
	 */
	public function __construct( callable $engine_factory, Findings $findings, FileCache $cache ) {
		$this->engine_factory = $engine_factory;
		$this->findings       = $findings;
		$this->cache          = $cache;
	}

	// --- State ----------------------------------------------------------------

	public function state(): array {
		$state = Store::get( self::STATE_OPTION, array() );
		return is_array( $state ) && $state ? $state : array( 'status' => 'idle' );
	}

	/** Read the state bypassing the object cache (another request may have cancelled the scan). */
	private function fresh_state(): array {
		wp_cache_delete( self::STATE_OPTION, 'options' );
		wp_cache_delete( self::STATE_OPTION, 'site-options' );
		wp_cache_delete( get_current_network_id() . ':' . self::STATE_OPTION, 'site-options' );
		return $this->state();
	}

	private function save( array $state ): void {
		$state['updated'] = time();
		Store::set( self::STATE_OPTION, $state );
	}

	public function is_running(): bool {
		$state = $this->state();
		return 'running' === $state['status'] && ( time() - (int) $state['updated'] ) < self::STALE_AFTER;
	}

	// --- Lifecycle ------------------------------------------------------------

	/**
	 * @param array{scope?: string, days?: int} $options custom: scope (directory); recent: days.
	 * @return array|\WP_Error New scan state.
	 */
	public function start( string $mode = 'standard', string $trigger = 'manual', array $options = array() ) {
		if ( ! in_array( $mode, self::MODES, true ) ) {
			return new \WP_Error( 'fckmw_mode', __( 'Unknown scan mode.', 'fckmaleware' ) );
		}
		$token = Lock::acquire( self::LOCK, 60 );
		if ( null === $token ) {
			return new \WP_Error( 'fckmw_running', __( 'A scan step is in progress. Try again in a moment.', 'fckmaleware' ) );
		}
		try {
			if ( $this->is_running() ) {
				return new \WP_Error( 'fckmw_running', __( 'A scan is already running.', 'fckmaleware' ) );
			}
			if ( ! Paths::ensure_data_dir() ) {
				return new \WP_Error( 'fckmw_storage', __( 'Could not create the plugin data directory under uploads.', 'fckmaleware' ) );
			}

			$scope = '';
			if ( 'custom' === $mode ) {
				$scope    = trim( wp_normalize_path( (string) ( $options['scope'] ?? '' ) ), '/' );
				$resolved = Paths::resolve( $scope );
				if ( '' === $scope || is_wp_error( $resolved ) || ! is_dir( $resolved ) ) {
					return new \WP_Error( 'fckmw_scope', __( 'Choose an existing directory inside the WordPress installation.', 'fckmaleware' ) );
				}
				$scope = (string) Paths::relative( $resolved );
				$data  = (string) Paths::relative( wp_normalize_path( Paths::data_dir() ) );
				if ( '' !== $data && 0 === strpos( trailingslashit( $scope ), trailingslashit( $data ) ) ) {
					return new \WP_Error( 'fckmw_scope', __( 'The plugin\'s private data folder (quarantine) cannot be scanned.', 'fckmaleware' ) );
				}
			}

			if ( false === file_put_contents( Paths::data_dir() . '/' . self::LIST_FILE, '' ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				return new \WP_Error( 'fckmw_storage', __( 'Could not write the scan file list.', 'fckmaleware' ) );
			}

			$state = array(
				'id'           => bin2hex( random_bytes( 8 ) ),
				'status'       => 'running',
				'phase'        => 'listing',
				'mode'         => $mode,
				'trigger'      => $trigger,
				'scope'        => $scope,
				'since'        => 'recent' === $mode ? time() - max( 1, (int) ( $options['days'] ?? 7 ) ) * DAY_IN_SECONDS : 0,
				'units'        => self::work_units( $mode, $scope ),
				'unit'         => 0,
				'total'        => 0,
				'position'     => 0,
				'offset'       => 0,
				'skipped'      => 0,
				'found'        => 0,
				'new'          => 0,
				'reinfections' => 0,
				'errors'       => array(),
				'recording'    => array(),
				'sig_version'  => '',
				'started'      => time(),
			);
			$this->save( $state );
			ActivityLog::log( 'scan.start', sprintf( /* translators: 1: mode, 2: trigger */ __( '%1$s scan started (%2$s).', 'fckmaleware' ), ucfirst( $mode ), $trigger ), array( 'scan' => $state['id'], 'mode' => $mode, 'scope' => $scope ) );
			return $state;
		} finally {
			Lock::release( self::LOCK, $token );
		}
	}

	/** Do as much work as fits in $budget seconds. Safe to call concurrently. */
	public function step( float $budget = 10.0 ): array {
		$state = $this->fresh_state();
		if ( 'running' !== $state['status'] ) {
			return $state;
		}
		$token = Lock::acquire( self::LOCK, (int) ceil( $budget ) + 60 );
		if ( null === $token ) {
			return $state; // Another worker is on it.
		}

		try {
			$deadline = microtime( true ) + $budget;
			$state    = $this->fresh_state();
			if ( 'running' !== $state['status'] ) {
				return $state;
			}

			if ( 'listing' === $state['phase'] ) {
				$state = $this->list_units( $state, $deadline );
			}
			if ( 'scanning' === $state['phase'] && microtime( true ) < $deadline ) {
				$state = $this->scan_batch( $state, $deadline );
			}
			if ( 'finalizing' === $state['phase'] ) {
				$state = $this->finalize( $state );
			}

			// Do not resurrect a scan that was cancelled while this step ran.
			if ( 'cancelled' === $this->fresh_state()['status'] ) {
				return $this->fresh_state();
			}
			$this->save( $state );
			return $state;
		} catch ( \Throwable $e ) {
			$state['errors'][] = $e->getMessage();
			$state             = $this->finish( $state, 'failed' );
			ActivityLog::log( 'scan.failed', __( 'Scan failed: ', 'fckmaleware' ) . $e->getMessage(), array( 'scan' => $state['id'] ?? '' ), 'warning' );
			return $state;
		} finally {
			Lock::release( self::LOCK, $token );
		}
	}

	/** Run a whole scan in this process (WP-CLI, system cron). */
	public function run( string $mode = 'standard', string $trigger = 'cli', array $options = array(), ?callable $progress = null ) {
		$state = $this->start( $mode, $trigger, $options );
		if ( is_wp_error( $state ) ) {
			return $state;
		}
		while ( 'running' === $state['status'] ) {
			$state = $this->step( 10.0 );
			if ( $progress ) {
				$progress( $state );
			}
		}
		return $state;
	}

	public function cancel(): array {
		$state = $this->fresh_state();
		if ( 'running' === $state['status'] ) {
			$state = $this->finish( $state, 'cancelled' );
			ActivityLog::log( 'scan.cancelled', __( 'Scan cancelled.', 'fckmaleware' ), array( 'scan' => $state['id'] ) );
		}
		return $state;
	}

	// --- Listing --------------------------------------------------------------

	/**
	 * Split the tree into units small enough to list in one step.
	 *
	 * @return array<int, array{0: string, 1: bool}> [relative dir, recursive]
	 */
	public static function work_units( string $mode, string $scope = '' ): array {
		if ( 'custom' === $mode ) {
			return array( array( $scope, true ) );
		}
		if ( 'core' === $mode ) {
			return array( array( '', false ), array( 'wp-admin', true ), array( 'wp-includes', true ) );
		}
		$root = Paths::root();
		if ( 'plugins' === $mode || 'uploads' === $mode ) {
			$units = array();
			foreach ( self::scoped_dirs( $mode ) as $base ) {
				if ( ! is_dir( $root . $base ) ) {
					continue;
				}
				$units[] = array( $base, false );
				foreach ( self::subdirs( $root . $base ) as $child ) {
					$units[] = array( $base . '/' . $child, true );
				}
			}
			return $units;
		}

		$units = array( array( '', false ) );
		foreach ( self::subdirs( $root ) as $dir ) {
			if ( 'wp-content' === $dir ) {
				$units[] = array( 'wp-content', false );
				foreach ( self::subdirs( $root . 'wp-content' ) as $child ) {
					$path = 'wp-content/' . $child;
					if ( in_array( $child, array( 'plugins', 'themes', 'uploads' ), true ) ) {
						$units[] = array( $path, false );
						foreach ( self::subdirs( $root . $path ) as $grandchild ) {
							$units[] = array( $path . '/' . $grandchild, true );
						}
					} else {
						$units[] = array( $path, true );
					}
				}
			} else {
				$units[] = array( $dir, true );
			}
		}
		return $units;
	}

	/**
	 * Directories (relative to the root) covered by the plugins/themes and
	 * uploads modes.
	 *
	 * @return string[]
	 */
	public static function scoped_dirs( string $mode ): array {
		if ( 'uploads' === $mode ) {
			$uploads = rtrim( Paths::uploads_relative(), '/' );
			return '' === $uploads ? array() : array( $uploads );
		}
		$content = Paths::relative( wp_normalize_path( WP_CONTENT_DIR ) ) ?? 'wp-content';
		$dirs    = array();
		foreach ( array( WP_PLUGIN_DIR, WPMU_PLUGIN_DIR, get_theme_root() ) as $dir ) {
			$relative = Paths::relative( wp_normalize_path( (string) $dir ) );
			if ( null !== $relative && '' !== $relative ) {
				$dirs[] = rtrim( $relative, '/' );
			}
		}
		return $dirs ? array_values( array_unique( $dirs ) ) : array( $content . '/plugins', $content . '/themes' );
	}

	/** @return string[] Non-symlink subdirectory names, minus VCS folders. */
	private static function subdirs( string $dir ): array {
		$out = array();
		foreach ( (array) @scandir( $dir ) as $name ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( '.' === $name || '..' === $name || in_array( $name, array( '.git', '.svn', '.hg', 'node_modules' ), true ) ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( is_dir( $path ) && ! is_link( $path ) ) {
				$out[] = $name;
			}
		}
		sort( $out );
		return $out;
	}

	private function list_units( array $state, float $deadline ): array {
		$handle = fopen( Paths::data_dir() . '/' . self::LIST_FILE, 'a' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $handle ) {
			throw new \RuntimeException( 'Cannot append to the scan file list.' );
		}
		$images    = in_array( $state['mode'], array( 'deep', 'uploads' ), true ) || (bool) Settings::get( 'scan_images' );
		$max_bytes = (int) Settings::get( 'max_file_size_mb' ) * MB_IN_BYTES;
		$exclude   = self::excluded_dirs();
		$types     = 'quick' === $state['mode'] ? array( 'php', 'htaccess', 'ini' ) : null;

		while ( $state['unit'] < count( $state['units'] ) && microtime( true ) < $deadline ) {
			list( $dir, $recursive ) = $state['units'][ $state['unit'] ];
			foreach ( self::files_in( $dir, $recursive, $exclude ) as $item ) {
				/** @var \SplFileInfo $item */
				if ( $state['since'] && $item->getMTime() < $state['since'] ) {
					continue;
				}
				$relative = Paths::relative( wp_normalize_path( $item->getPathname() ) );
				if ( null === $relative || false !== strpbrk( $relative, "\r\n" ) ) {
					continue;
				}
				$type = Signatures::file_type( $relative, $images );
				if ( null === $type || ( $types && ! in_array( $type, $types, true ) ) ) {
					continue;
				}
				if ( $item->getSize() > $max_bytes ) {
					// Reported in the scan result so the gap in coverage is visible.
					$state['too_large'] = ( $state['too_large'] ?? 0 ) + 1;
					if ( count( $state['too_large_files'] ?? array() ) < 50 ) {
						$state['too_large_files'][] = $relative;
					}
					continue;
				}
				fwrite( $handle, $relative . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$state['total']++;
			}
			$state['unit']++;
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( $state['unit'] >= count( $state['units'] ) ) {
			$state['phase'] = 'scanning';
		}
		return $state;
	}

	/**
	 * Files in one directory (optionally recursive), skipping symlinks and excluded directories.
	 *
	 * @param string[] $exclude Absolute normalized directories.
	 * @return \Generator<int, \SplFileInfo>
	 */
	public static function files_in( string $dir, bool $recursive, array $exclude ): \Generator {
		$absolute = rtrim( Paths::root() . $dir, '/' );
		if ( ! is_dir( $absolute ) || is_link( $absolute ) || in_array( wp_normalize_path( $absolute ), $exclude, true ) ) {
			return;
		}
		if ( ! $recursive ) {
			foreach ( new \DirectoryIterator( $absolute ) as $item ) {
				if ( ! $item->isDot() && $item->isFile() && ! $item->isLink() ) {
					yield clone $item;
				}
			}
			return;
		}
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $absolute, \FilesystemIterator::SKIP_DOTS ),
				static function ( \SplFileInfo $item ) use ( $exclude ): bool {
					if ( $item->isLink() ) {
						return false;
					}
					if ( $item->isDir() ) {
						return ! in_array( $item->getFilename(), array( '.git', '.svn', '.hg', 'node_modules' ), true )
							&& ! in_array( wp_normalize_path( $item->getPathname() ), $exclude, true );
					}
					return true;
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);
		foreach ( $iterator as $item ) {
			if ( $item->isFile() ) {
				yield $item;
			}
		}
	}

	/** @return string[] */
	private static function excluded_dirs(): array {
		/**
		 * Absolute directories the scanner skips entirely. FCK Malware's own
		 * directory is not excluded: it is integrity-checked against its manifest.
		 *
		 * @param string[] $dirs Defaults to the private data directory.
		 */
		$dirs = array( Paths::data_dir() );
		foreach ( Settings::exclusions() as $relative ) {
			$dirs[] = Paths::root() . $relative;
		}
		$dirs = (array) apply_filters( 'fckmw_scan_exclude_dirs', $dirs );
		return array_values( array_filter( array_map( 'wp_normalize_path', array_map( 'untrailingslashit', $dirs ) ) ) );
	}

	// --- Scanning -------------------------------------------------------------

	private function engine( array $state ): Engine {
		$options = array(
			'images' => in_array( $state['mode'], array( 'deep', 'uploads' ), true ) || (bool) Settings::get( 'scan_images' ),
			'record' => in_array( $state['mode'], array( 'standard', 'deep' ), true ),
		);
		return ( $this->engine_factory )( $options['record'] ? (array) $state['recording'] : null, $options );
	}

	private function scan_batch( array $state, float $deadline ): array {
		$engine              = $this->engine( $state );
		$state['sig_version'] = $engine->signatures()->version();
		$errors_before       = $engine->signatures()->runtime_errors();
		$use_cache           = in_array( $state['mode'], array( 'quick', 'standard' ), true );
		$throttle            = (int) Settings::get( 'throttle_ms' ) * 1000;
		$memory_limit        = self::memory_limit();
		$images              = in_array( $state['mode'], array( 'deep', 'uploads' ), true ) || (bool) Settings::get( 'scan_images' );

		$handle = fopen( Paths::data_dir() . '/' . self::LIST_FILE, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $handle ) {
			throw new \RuntimeException( 'The scan file list is missing.' );
		}
		fseek( $handle, (int) $state['offset'] );

		while ( microtime( true ) < $deadline ) {
			$batch = array();
			while ( count( $batch ) < self::BATCH && false !== ( $line = fgets( $handle ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition
				$path = rtrim( $line, "\r\n" );
				if ( '' !== $path ) {
					$batch[] = $path;
				}
			}
			if ( ! $batch ) {
				$state['phase'] = 'finalizing';
				break;
			}

			$cached  = $use_cache ? $this->cache->get_many( $batch ) : array();
			$updates = array();
			foreach ( $batch as $relative ) {
				$state['position']++;
				$absolute = Paths::root() . $relative;
				$stat     = @lstat( $absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( false === $stat || is_link( $absolute ) || ! is_file( $absolute ) ) {
					continue;
				}
				$size  = (int) $stat['size'];
				$mtime = (int) $stat['mtime'];
				$row   = $cached[ $relative ] ?? null;
				if ( $row && $row['clean'] && (int) $row['size'] === $size && (int) $row['mtime'] === $mtime && $row['engine'] === $engine->fingerprint() ) {
					$state['skipped']++;
					continue;
				}

				$file       = new FileContext( $relative, $absolute, Signatures::file_type( $relative, $images ), $size, $mtime );
				$detections = $engine->inspect( $file );
				foreach ( $detections as $detection ) {
					$result = $this->findings->upsert(
						$detection + array(
							'scan_id'   => $state['id'],
							'file'      => $relative,
							'file_hash' => $file->sha256(),
						)
					);
					if ( 'ignored' !== $result['outcome'] ) {
						$state['found']++;
					}
					if ( 'new' === $result['outcome'] ) {
						$state['new']++;
					} elseif ( 'reinfection' === $result['outcome'] ) {
						$state['reinfections']++;
						ActivityLog::log( 'threat.reinfection', sprintf( /* translators: %s: file */ __( 'Reinfection detected: %s', 'fckmaleware' ), $relative ), array( 'file' => $relative, 'signature' => $detection['signature_id'], 'finding' => $result['id'] ), 'critical' );
					}
					/** Fires for each detection a scan records. */
					do_action( 'fckmw_detection', $detection + array( 'file' => $relative ), $result );
				}
				$updates[] = array(
					'path'   => $relative,
					'size'   => $size,
					'mtime'  => $mtime,
					'sha256' => $file->sha256(),
					'engine' => $engine->fingerprint(),
					'clean'  => ! $detections,
				);
				$file->release();

				if ( $throttle ) {
					usleep( $throttle );
				}
				if ( microtime( true ) >= $deadline || ( $memory_limit && memory_get_usage() > 0.8 * $memory_limit ) ) {
					// Remember exactly where we stopped inside the batch.
					$state['offset'] = self::offset_after( $handle, $batch, $relative );
					$this->cache->put_many( $updates );
					fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
					$state['recording'] = $this->recording_of( $engine, $state );
					return self::note_pattern_errors( $state, $engine, $errors_before );
				}
			}
			$this->cache->put_many( $updates );
			$state['offset'] = ftell( $handle );
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$state['recording'] = $this->recording_of( $engine, $state );
		return self::note_pattern_errors( $state, $engine, $errors_before );
	}

	/** Carry rules that hit the PCRE backtracking limit during this batch into the scan state. */
	private static function note_pattern_errors( array $state, Engine $engine, array $before ): array {
		foreach ( $engine->signatures()->runtime_errors() as $id => $count ) {
			$delta = $count - ( $before[ $id ] ?? 0 );
			if ( $delta > 0 ) {
				$state['pattern_errors'][ $id ] = ( $state['pattern_errors'][ $id ] ?? 0 ) + $delta;
			}
		}
		return $state;
	}

	private function recording_of( Engine $engine, array $state ): array {
		$integrity = $engine->integrity();
		return null !== $integrity && null !== $integrity->recording() ? $integrity->recording() : (array) $state['recording'];
	}

	/** Byte offset just after $relative inside a batch that was read ending at the current file position. */
	private static function offset_after( $handle, array $batch, string $relative ): int {
		$end       = ftell( $handle );
		$index     = array_search( $relative, $batch, true );
		$remaining = array_slice( $batch, (int) $index + 1 );
		$bytes     = 0;
		foreach ( $remaining as $path ) {
			$bytes += strlen( $path ) + 1;
		}
		return max( 0, $end - $bytes );
	}

	private static function memory_limit(): int {
		$limit = (string) ini_get( 'memory_limit' );
		if ( '-1' === $limit || '' === $limit ) {
			return 0;
		}
		return (int) wp_convert_hr_to_bytes( $limit );
	}

	// --- Finalizing -----------------------------------------------------------

	private function finalize( array $state ): array {
		$full = in_array( $state['mode'], array( 'standard', 'deep' ), true );

		if ( $full || 'core' === $state['mode'] ) {
			$engine    = $this->engine( $state );
			$integrity = $engine->integrity();
			foreach ( null === $integrity ? array() : $integrity->missing_core_files() as $missing ) {
				$result = $this->findings->upsert(
					array(
						'scan_id'        => $state['id'],
						'source'         => 'integrity',
						'file'           => $missing,
						'signature_id'   => 'FMW-INT-003',
						'signature_name' => __( 'Missing WordPress core file', 'fckmaleware' ),
						'family'         => 'Integrity.Core.Missing',
						'severity'       => 'low',
						'confidence'     => 50,
						'verdict'        => 'suspicious',
						'evidence'       => __( 'A core PHP file listed in the official checksums is missing. Deleted core files can break features or indicate tampering.', 'fckmaleware' ),
						'remediation'    => 'repair',
					)
				);
				if ( 'new' === $result['outcome'] ) {
					$state['new']++;
				}
				$state['found']++;
			}
		}

		$resolved = 0;
		if ( $full ) {
			$resolved = $this->findings->resolve_stale( $state['id'], self::FILE_SOURCES );
		} elseif ( 'custom' === $state['mode'] ) {
			$resolved = $this->findings->resolve_stale( $state['id'], self::FILE_SOURCES, 'file', trailingslashit( $state['scope'] ) );
		} elseif ( 'plugins' === $state['mode'] || 'uploads' === $state['mode'] ) {
			foreach ( self::scoped_dirs( $state['mode'] ) as $prefix ) {
				$resolved += $this->findings->resolve_stale( $state['id'], self::FILE_SOURCES, 'file', trailingslashit( $prefix ) );
			}
		} elseif ( 'core' === $state['mode'] ) {
			foreach ( array( 'wp-admin/', 'wp-includes/' ) as $prefix ) {
				$resolved += $this->findings->resolve_stale( $state['id'], array( 'integrity', 'signature', 'heuristic' ), 'file', $prefix );
			}
		}
		$state['resolved'] = $resolved;

		return $this->finish( $state, 'complete' );
	}

	private function finish( array $state, string $status ): array {
		$state['status']   = $status;
		$state['phase']    = 'done';
		$state['finished'] = time();
		unset( $state['units'] );
		$this->save( $state );
		wp_delete_file( Paths::data_dir() . '/' . self::LIST_FILE );
		ScanHistory::add(
			array(
				'kind'     => 'file',
				'id'       => (string) ( $state['id'] ?? '' ),
				'mode'     => (string) ( $state['mode'] ?? '' ),
				'trigger'  => (string) ( $state['trigger'] ?? '' ),
				'scope'    => (string) ( $state['scope'] ?? '' ),
				'status'   => $status,
				'files'    => (int) ( $state['position'] ?? 0 ),
				'total'    => (int) ( $state['total'] ?? 0 ),
				'skipped'  => (int) ( $state['skipped'] ?? 0 ),
				'found'    => (int) ( $state['found'] ?? 0 ),
				'new'      => (int) ( $state['new'] ?? 0 ),
				'errors'   => count( (array) ( $state['errors'] ?? array() ) ),
				'large'    => (int) ( $state['too_large'] ?? 0 ),
				'started'  => (int) ( $state['started'] ?? 0 ),
				'finished' => (int) $state['finished'],
			)
		);

		if ( 'complete' === $status ) {
			Store::set( 'fckmw_last_scan', $state );
			ActivityLog::log(
				'scan.complete',
				sprintf(
					/* translators: 1: mode, 2: files, 3: skipped, 4: findings, 5: new */
					__( '%1$s scan complete: %2$d files checked (%3$d unchanged skipped), %4$d detections, %5$d new.', 'fckmaleware' ),
					ucfirst( $state['mode'] ),
					$state['total'],
					$state['skipped'],
					$state['found'],
					$state['new']
				),
				array_intersect_key( $state, array_flip( array( 'id', 'mode', 'trigger', 'total', 'skipped', 'found', 'new', 'reinfections', 'resolved', 'sig_version' ) ) ),
				$state['new'] ? 'warning' : 'info'
			);
			/**
			 * Fires after a scan has worked through every file.
			 *
			 * @param array $state Final scan state.
			 */
			do_action( 'fckmw_scan_complete', $state );
		}
		return $state;
	}

	// --- Single files (event-driven protection) -------------------------------

	/**
	 * Inspect one file outside a scan, e.g. right after an upload or plugin install.
	 * Never records baselines; returns the detections that were stored.
	 *
	 * @return array<int, array>|\WP_Error
	 */
	public function inspect_file( string $relative, string $trigger ) {
		$absolute = Paths::file( $relative );
		if ( is_wp_error( $absolute ) ) {
			return $absolute;
		}
		$relative = (string) Paths::relative( $absolute );
		$engine   = ( $this->engine_factory )( null, array( 'images' => true, 'record' => false ) );
		$file     = FileContext::from_path( $relative, $absolute, Signatures::file_type( $relative, true ) ?? 'image' );
		if ( $file->size > (int) Settings::get( 'max_file_size_mb' ) * MB_IN_BYTES ) {
			ActivityLog::log( 'scan.too_large', sprintf( /* translators: 1: file, 2: size */ __( 'Not checked because it exceeds the size limit: %1$s (%2$s)', 'fckmaleware' ), $relative, size_format( $file->size ) ), array( 'file' => $relative, 'trigger' => $trigger ), 'notice' );
			return array();
		}
		$detections = $engine->inspect( $file );
		foreach ( $detections as $detection ) {
			$result = $this->findings->upsert( $detection + array( 'scan_id' => 'event:' . $trigger, 'file' => $relative, 'file_hash' => $file->sha256() ) );
			do_action( 'fckmw_detection', $detection + array( 'file' => $relative ), $result );
		}
		$this->cache->forget( $relative );
		return $detections;
	}
}
