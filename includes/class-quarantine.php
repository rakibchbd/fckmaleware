<?php
/**
 * Moves infected files out of the web root's executable path and back.
 *
 * Quarantined copies are compressed (so they cannot be executed or served as
 * PHP even if the deny rules are ignored) and indexed in an option.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Quarantine {

	public const OPTION = 'fckmw_quarantine';

	public function all(): array {
		$items = get_option( self::OPTION, array() );
		return is_array( $items ) ? $items : array();
	}

	/**
	 * @param bool $allow_core Set when the file sits in a core location but is
	 *                         known not to be part of WordPress (FMW-INT-002).
	 * @return string|\WP_Error Quarantine key.
	 */
	public function isolate( string $relative, bool $allow_core = false ) {
		if ( ! $allow_core && Paths::is_core( $relative ) ) {
			return new \WP_Error(
				'fckmw_core_file',
				__( 'This is a WordPress core or configuration file; removing it would take the site down. Reinstall WordPress from Dashboard → Updates, or clean wp-config.php by hand.', 'fckmaleware' )
			);
		}

		$absolute = Paths::resolve( $relative );
		if ( is_wp_error( $absolute ) ) {
			return $absolute;
		}
		$key = $this->store( $relative, $absolute );
		if ( is_wp_error( $key ) ) {
			return $key;
		}
		if ( ! @unlink( $absolute ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			$this->purge( $key );
			return new \WP_Error( 'fckmw_unlink', __( 'Could not remove the original file (check file permissions).', 'fckmaleware' ) );
		}
		return $key;
	}

	/** @return string|\WP_Error */
	private function store( string $relative, string $absolute ) {
		if ( ! Paths::ensure_data_dir() ) {
			return new \WP_Error( 'fckmw_storage', __( 'Could not create the quarantine directory.', 'fckmaleware' ) );
		}

		$content = file_get_contents( $absolute ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $content ) {
			return new \WP_Error( 'fckmw_read', __( 'Could not read the file.', 'fckmaleware' ) );
		}

		$perms   = fileperms( $absolute ) & 0777;
		$key     = bin2hex( random_bytes( 16 ) );
		$encoded = function_exists( 'gzdeflate' ) ? gzdeflate( $content, 6 ) : base64_encode( $content ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		$target  = Paths::quarantine_dir() . "/{$key}.quar";

		if ( false === file_put_contents( $target, $encoded ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return new \WP_Error( 'fckmw_write', __( 'Could not write the quarantine copy.', 'fckmaleware' ) );
		}

		$items         = $this->all();
		$items[ $key ] = array(
			'file'     => $relative,
			'hash'     => hash( 'sha256', $content ),
			'size'     => strlen( $content ),
			'perms'    => $perms ?: 0644,
			'encoding' => function_exists( 'gzdeflate' ) ? 'deflate' : 'base64',
			'time'     => time(),
		);
		update_option( self::OPTION, $items, false );

		return $key;
	}

	/** @return true|\WP_Error */
	public function restore( string $key ) {
		$items = $this->all();
		if ( ! isset( $items[ $key ] ) ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Unknown quarantine entry.', 'fckmaleware' ) );
		}
		$item   = $items[ $key ];
		$source = Paths::quarantine_dir() . "/{$key}.quar";
		$raw    = is_readable( $source ) ? file_get_contents( $source ) : false; // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $raw ) {
			return new \WP_Error( 'fckmw_read', __( 'Quarantine copy is missing.', 'fckmaleware' ) );
		}

		$content = 'deflate' === $item['encoding'] ? gzinflate( $raw ) : base64_decode( $raw, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		if ( false === $content || ! hash_equals( $item['hash'], hash( 'sha256', $content ) ) ) {
			return new \WP_Error( 'fckmw_corrupt', __( 'Quarantine copy failed its integrity check.', 'fckmaleware' ) );
		}

		$target = Paths::root() . ltrim( $item['file'], '/' );
		if ( file_exists( $target ) ) {
			return new \WP_Error( 'fckmw_exists', __( 'A file already exists at the original location.', 'fckmaleware' ) );
		}
		$parent = dirname( $target );
		if ( ! wp_mkdir_p( $parent ) || 0 !== strpos( wp_normalize_path( (string) realpath( $parent ) ) . '/', Paths::root() ) ) {
			return new \WP_Error( 'fckmw_outside', __( 'Original directory is not usable.', 'fckmaleware' ) );
		}
		if ( false === file_put_contents( $target, $content ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return new \WP_Error( 'fckmw_write', __( 'Could not write the restored file.', 'fckmaleware' ) );
		}
		@chmod( $target, (int) $item['perms'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions

		$this->forget( $key );
		return true;
	}

	public function purge( string $key ): void {
		wp_delete_file( Paths::quarantine_dir() . "/{$key}.quar" );
		$this->forget( $key );
	}

	private function forget( string $key ): void {
		$items = $this->all();
		unset( $items[ $key ] );
		update_option( self::OPTION, $items, false );
	}
}
