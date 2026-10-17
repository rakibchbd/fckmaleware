<?php
/**
 * Filesystem helpers: site root, private data directory, path containment.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Paths {

	public static function root(): string {
		$real = realpath( ABSPATH );
		return trailingslashit( wp_normalize_path( false !== $real ? $real : ABSPATH ) );
	}

	/** Path relative to the site root, or null if outside it. */
	public static function relative( string $absolute ): ?string {
		$absolute = wp_normalize_path( $absolute );
		$root     = self::root();
		if ( 0 !== strpos( $absolute, $root ) ) {
			return null;
		}
		return substr( $absolute, strlen( $root ) );
	}

	/**
	 * Resolve a stored relative path to an absolute one, refusing anything
	 * (symlinks, "..") that escapes the site root.
	 *
	 * @return string|\WP_Error
	 */
	public static function resolve( string $relative ) {
		$real = realpath( self::root() . ltrim( $relative, '/' ) );
		if ( false === $real ) {
			return new \WP_Error( 'fckmw_missing', __( 'File no longer exists.', 'fckmaleware' ) );
		}
		$real = wp_normalize_path( $real );
		if ( 0 !== strpos( $real, self::root() ) ) {
			return new \WP_Error( 'fckmw_outside', __( 'File is outside the WordPress directory.', 'fckmaleware' ) );
		}
		return $real;
	}

	/**
	 * Files that keep the site running: removing them takes the site down, so
	 * they must be repaired (reinstall core / edit wp-config.php) instead of quarantined.
	 */
	public static function is_core( string $relative ): bool {
		if ( 0 === strpos( $relative, 'wp-admin/' ) || 0 === strpos( $relative, 'wp-includes/' ) ) {
			return true;
		}
		return false === strpos( $relative, '/' ) && 1 === preg_match( '/^(?:wp-[a-z-]+|index|xmlrpc)\.php$/', $relative );
	}

	/** Private directory under uploads for scan state and quarantined files. */
	public static function data_dir(): string {
		$uploads = wp_upload_dir( null, false );
		return trailingslashit( wp_normalize_path( $uploads['basedir'] ) ) . 'fckmaleware';
	}

	public static function quarantine_dir(): string {
		return self::data_dir() . '/quarantine';
	}

	public static function uploads_relative(): string {
		$uploads = wp_upload_dir( null, false );
		$rel     = self::relative( $uploads['basedir'] );
		return null === $rel ? '' : trailingslashit( $rel );
	}

	/** Create the data directories and lock them down against web access. */
	public static function ensure_data_dir(): bool {
		foreach ( array( self::data_dir(), self::quarantine_dir() ) as $dir ) {
			if ( ! wp_mkdir_p( $dir ) ) {
				return false;
			}
			$guards = array(
				'index.php'  => "<?php\n// Silence is golden.\n",
				'.htaccess'  => "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n",
				'web.config' => "<?xml version=\"1.0\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
			);
			foreach ( $guards as $name => $body ) {
				if ( ! file_exists( "{$dir}/{$name}" ) ) {
					file_put_contents( "{$dir}/{$name}", $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				}
			}
		}
		return true;
	}
}
