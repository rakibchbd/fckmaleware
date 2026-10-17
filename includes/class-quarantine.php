<?php
/**
 * Quarantine and backup store.
 *
 * Files are stored compressed (raw deflate, or base64 without zlib) in the
 * private data directory, so a quarantined payload can be neither executed
 * nor served as PHP even if the web server ignores the deny rules.
 *
 * Every write follows the same sequence: resolve the path safely (no
 * traversal, no symlinks), record metadata, write the copy, read the copy
 * back and verify its SHA-256, and only then touch the original.
 *
 * Kinds: "quarantine" (original removed) and "backup" (original kept or
 * about to be replaced, e.g. before an official-copy repair).
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Quarantine {

	public const OPTION = 'fckmw_quarantine';
	private const LOCK  = 'quarantine';

	public function all(): array {
		$items = Store::get( self::OPTION, array() );
		return is_array( $items ) ? $items : array();
	}

	public function get( string $key ): ?array {
		return $this->all()[ $key ] ?? null;
	}

	/**
	 * Move a file into quarantine.
	 *
	 * @param bool $allow_core Set when the file sits in a core location but is known not to be part of WordPress.
	 * @return string|\WP_Error Quarantine key.
	 */
	public function isolate( string $relative, bool $allow_core = false, array $context = array() ) {
		if ( ! $allow_core && Paths::is_core( $relative ) ) {
			return new \WP_Error(
				'fckmw_core_file',
				__( 'This is a WordPress core or configuration file; removing it would take the site down. Use "Repair" to restore the official copy, or clean wp-config.php by hand.', 'fckmaleware' )
			);
		}
		$key = $this->store( $relative, 'quarantine', $context );
		if ( is_wp_error( $key ) ) {
			return $key;
		}
		$removed = $this->remove_verified( Paths::root() . ltrim( wp_normalize_path( $relative ), '/' ), (string) $this->get( $key )['hash'] );
		if ( is_wp_error( $removed ) ) {
			$this->purge( $key );
			return $removed;
		}
		return $key;
	}

	/**
	 * Remove the original only if it is still the file that was copied.
	 *
	 * The file is first renamed to a hidden name in the same directory (atomic,
	 * so nothing can replace it afterwards), then re-hashed. If it changed or
	 * was swapped for a symlink between the copy and now, it is put back and
	 * nothing is removed.
	 *
	 * @return true|\WP_Error
	 */
	private function remove_verified( string $absolute, string $hash ) {
		// phpcs:disable WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		$hold = dirname( $absolute ) . '/.fckmw-hold-' . bin2hex( random_bytes( 6 ) ) . '.tmp';
		if ( is_link( $absolute ) || ! @rename( $absolute, $hold ) ) {
			return new \WP_Error( 'fckmw_unlink', __( 'Could not remove the original file (check file ownership and permissions). Nothing was changed.', 'fckmaleware' ) );
		}
		clearstatcache();
		if ( is_link( $hold ) || ! hash_equals( $hash, (string) @hash_file( 'sha256', $hold ) ) ) {
			@rename( $hold, $absolute );
			return new \WP_Error( 'fckmw_changed', __( 'The file changed while it was being quarantined, so it was left in place. Scan it again before acting.', 'fckmaleware' ) );
		}
		if ( ! @unlink( $hold ) ) {
			@rename( $hold, $absolute );
			return new \WP_Error( 'fckmw_unlink', __( 'Could not remove the original file (check file ownership and permissions). Nothing was changed.', 'fckmaleware' ) );
		}
		// phpcs:enable
		clearstatcache( true, $absolute );
		return true;
	}

	/**
	 * Keep a verified copy of a file that is about to be replaced.
	 *
	 * @return string|\WP_Error Backup key.
	 */
	public function backup( string $relative, array $context = array() ) {
		return $this->store( $relative, 'backup', $context );
	}

	/** @return string|\WP_Error */
	private function store( string $relative, string $kind, array $context ) {
		$absolute = Paths::file( $relative );
		if ( is_wp_error( $absolute ) ) {
			return $absolute;
		}
		if ( 'quarantine' === $kind && ( ! is_writable( $absolute ) || ! is_writable( dirname( $absolute ) ) ) ) {
			return new \WP_Error( 'fckmw_permissions', __( 'The file or its directory is not writable by WordPress, so it cannot be moved. Fix ownership/permissions or remove it via your hosting file manager.', 'fckmaleware' ) );
		}
		if ( ! Paths::ensure_data_dir() ) {
			return new \WP_Error( 'fckmw_storage', __( 'Could not create the quarantine directory.', 'fckmaleware' ) );
		}

		$content = file_get_contents( $absolute ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $content ) {
			return new \WP_Error( 'fckmw_read', __( 'Could not read the file.', 'fckmaleware' ) );
		}

		$key      = bin2hex( random_bytes( 16 ) );
		$deflate  = function_exists( 'gzdeflate' );
		$encoded  = $deflate ? gzdeflate( $content, 6 ) : base64_encode( $content ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		$target   = Paths::quarantine_dir() . "/{$key}.quar";
		$hash     = hash( 'sha256', $content );
		$written  = Paths::write_atomic( $target, (string) $encoded, 0600 );
		if ( is_wp_error( $written ) ) {
			return $written;
		}

		// Verify the copy before anything else happens to the original.
		$check = $this->read_copy( $target, $deflate ? 'deflate' : 'base64' );
		if ( null === $check || ! hash_equals( $hash, hash( 'sha256', $check ) ) ) {
			wp_delete_file( $target );
			return new \WP_Error( 'fckmw_verify', __( 'The quarantine copy could not be verified, so the original was left untouched.', 'fckmaleware' ) );
		}

		$item = array(
			'file'     => $relative,
			'kind'     => $kind,
			'hash'     => $hash,
			'size'     => strlen( $content ),
			'perms'    => fileperms( $absolute ) & 0777,
			'mtime'    => (int) filemtime( $absolute ),
			'owner'    => function_exists( 'fileowner' ) ? (int) fileowner( $absolute ) : -1,
			'group'    => function_exists( 'filegroup' ) ? (int) filegroup( $absolute ) : -1,
			'encoding' => $deflate ? 'deflate' : 'base64',
			'time'     => time(),
			'user'     => get_current_user_id(),
			'context'  => $context,
		);
		if ( ! $this->update_index( $key, $item ) ) {
			wp_delete_file( $target );
			return new \WP_Error( 'fckmw_busy', __( 'The quarantine is busy; try again.', 'fckmaleware' ) );
		}
		return $key;
	}

	private function read_copy( string $path, string $encoding ): ?string {
		$raw = is_readable( $path ) ? file_get_contents( $path ) : false; // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $raw ) {
			return null;
		}
		$content = 'deflate' === $encoding ? @gzinflate( $raw ) : base64_decode( $raw, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.PHP.DiscouragedPHPFunctions
		return false === $content ? null : $content;
	}

	/** Verified original content of a stored item. */
	public function content( string $key ): ?string {
		$item = $this->get( $key );
		if ( ! $item ) {
			return null;
		}
		$content = $this->read_copy( Paths::quarantine_dir() . "/{$key}.quar", (string) $item['encoding'] );
		return null !== $content && hash_equals( (string) $item['hash'], hash( 'sha256', $content ) ) ? $content : null;
	}

	/**
	 * Put a stored file back. A quarantined file never overwrites an existing
	 * one; a backup does (that is its purpose: undoing a repair).
	 *
	 * @return true|\WP_Error
	 */
	public function restore( string $key ) {
		$item = $this->get( $key );
		if ( ! $item ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Unknown quarantine entry.', 'fckmaleware' ) );
		}
		$content = $this->content( $key );
		if ( null === $content ) {
			return new \WP_Error( 'fckmw_corrupt', __( 'The stored copy is missing or failed its integrity check.', 'fckmaleware' ) );
		}
		if ( ! Paths::is_clean_relative( (string) $item['file'] ) ) {
			return new \WP_Error( 'fckmw_path', __( 'The stored path is invalid.', 'fckmaleware' ) );
		}

		$target = Paths::root() . $item['file'];
		if ( is_link( $target ) ) {
			return new \WP_Error( 'fckmw_symlink', __( 'A symbolic link now sits at the original location; refusing to write through it.', 'fckmaleware' ) );
		}
		if ( file_exists( $target ) && 'backup' !== ( $item['kind'] ?? 'quarantine' ) ) {
			return new \WP_Error( 'fckmw_exists', __( 'A file already exists at the original location.', 'fckmaleware' ) );
		}
		$parent = dirname( $target );
		if ( ! is_dir( $parent ) && ! wp_mkdir_p( $parent ) ) {
			return new \WP_Error( 'fckmw_write', __( 'Could not recreate the original directory.', 'fckmaleware' ) );
		}
		$real_parent = realpath( $parent );
		if ( false === $real_parent || 0 !== strpos( trailingslashit( wp_normalize_path( $real_parent ) ), Paths::root() ) ) {
			return new \WP_Error( 'fckmw_outside', __( 'The original directory now points outside the WordPress directory.', 'fckmaleware' ) );
		}

		// A quarantined file is created exclusively, so a file that appeared at the
		// location after the check above is never overwritten. A backup replaces
		// the current file by design (it undoes a repair).
		$written = 'backup' === ( $item['kind'] ?? 'quarantine' )
			? Paths::write_atomic( $target, $content, (int) $item['perms'] ?: 0644 )
			: Paths::write_new( $target, $content, (int) $item['perms'] ?: 0644 );
		if ( is_wp_error( $written ) ) {
			return $written;
		}
		if ( ! empty( $item['mtime'] ) ) {
			@touch( $target, (int) $item['mtime'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$this->purge( $key );
		return true;
	}

	public function purge( string $key ): void {
		wp_delete_file( Paths::quarantine_dir() . "/{$key}.quar" );
		$this->update_index( $key, null );
	}

	/**
	 * Delete stored items older than $days.
	 *
	 * @return int Number removed.
	 */
	public function expire( int $days ): int {
		if ( $days <= 0 ) {
			return 0;
		}
		$cutoff  = time() - $days * DAY_IN_SECONDS;
		$removed = 0;
		foreach ( $this->all() as $key => $item ) {
			if ( (int) $item['time'] < $cutoff ) {
				$this->purge( (string) $key );
				$removed++;
			}
		}
		return $removed;
	}

	/**
	 * Items as a list for the admin table, newest first, optionally filtered by
	 * kind and a search on the original path.
	 *
	 * @return array<string, array> key => item
	 */
	public function search( string $kind = '', string $search = '' ): array {
		$items = array_filter(
			$this->all(),
			static function ( array $item ) use ( $kind, $search ): bool {
				return ( '' === $kind || $kind === ( $item['kind'] ?? 'quarantine' ) )
					&& ( '' === $search || false !== stripos( (string) $item['file'], $search ) );
			}
		);
		uasort(
			$items,
			static function ( array $a, array $b ): int {
				return (int) $b['time'] <=> (int) $a['time'];
			}
		);
		return $items;
	}

	/** @return array{items: int, bytes: int, quarantined: int, backups: int} */
	public function stats(): array {
		$stats = array( 'items' => 0, 'bytes' => 0, 'quarantined' => 0, 'backups' => 0 );
		foreach ( $this->all() as $item ) {
			$stats['items']++;
			$stats['bytes'] += (int) $item['size'];
			$stats[ 'backup' === ( $item['kind'] ?? 'quarantine' ) ? 'backups' : 'quarantined' ]++;
		}
		return $stats;
	}

	/** Update one index entry under the quarantine lock (null removes it). */
	private function update_index( string $key, ?array $item ): bool {
		$token = null;
		for ( $i = 0; $i < 20 && null === $token; $i++ ) {
			$token = Lock::acquire( self::LOCK, 30 );
			if ( null === $token ) {
				usleep( 100000 );
			}
		}
		if ( null === $token ) {
			return false;
		}
		try {
			wp_cache_delete( self::OPTION, 'options' );
			$items = $this->all();
			if ( null === $item ) {
				unset( $items[ $key ] );
			} else {
				$items[ $key ] = $item + array( 'kind' => 'quarantine' );
			}
			Store::set( self::OPTION, $items );
			return true;
		} finally {
			Lock::release( self::LOCK, $token );
		}
	}
}
