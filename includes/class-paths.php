<?php
/**
 * Filesystem helpers: site root, private data directory, path containment,
 * symlink-safe resolution and atomic writes.
 *
 * Every path the plugin acts on comes from a database row, a scan list or a
 * request, so all of them go through file()/resolve() before use.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Paths {

	private const DATA_DIR_OPTION = 'fckmw_data_dir';
	private const LEGACY_DATA_DIR = 'fckmaleware';

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

	/** Reject traversal sequences, NUL bytes and absolute paths in a stored relative path. */
	public static function is_clean_relative( string $relative ): bool {
		return '' !== $relative
			&& false === strpos( $relative, "\0" )
			&& 0 === preg_match( '#(^|/)\.\.?(/|$)#', $relative )
			&& '/' !== $relative[0]
			&& 0 === preg_match( '#^[a-zA-Z]:#', $relative );
	}

	/**
	 * Resolve a relative path to an existing regular file inside the root
	 * that is not a symlink and has no symlinked parent leading outside.
	 *
	 * @return string|\WP_Error Absolute path.
	 */
	public static function file( string $relative ) {
		$relative = ltrim( wp_normalize_path( $relative ), '/' );
		if ( ! self::is_clean_relative( $relative ) ) {
			return new \WP_Error( 'fckmw_path', __( 'Invalid file path.', 'fckmaleware' ) );
		}
		$absolute = self::root() . $relative;
		if ( is_link( $absolute ) ) {
			return new \WP_Error( 'fckmw_symlink', __( 'Refusing to act on a symbolic link.', 'fckmaleware' ) );
		}
		if ( ! is_file( $absolute ) ) {
			return new \WP_Error( 'fckmw_missing', __( 'File no longer exists.', 'fckmaleware' ) );
		}
		$parent = realpath( dirname( $absolute ) );
		if ( false === $parent || 0 !== strpos( trailingslashit( wp_normalize_path( $parent ) ), self::root() ) ) {
			return new \WP_Error( 'fckmw_outside', __( 'File is outside the WordPress directory.', 'fckmaleware' ) );
		}
		return trailingslashit( wp_normalize_path( $parent ) ) . basename( $absolute );
	}

	/**
	 * Resolve a stored relative path (file or directory) to an absolute one,
	 * refusing anything that escapes the site root.
	 *
	 * @return string|\WP_Error
	 */
	public static function resolve( string $relative ) {
		$relative = ltrim( wp_normalize_path( $relative ), '/' );
		if ( '' !== $relative && ! self::is_clean_relative( $relative ) ) {
			return new \WP_Error( 'fckmw_path', __( 'Invalid path.', 'fckmaleware' ) );
		}
		$real = realpath( self::root() . $relative );
		if ( false === $real ) {
			return new \WP_Error( 'fckmw_missing', __( 'File no longer exists.', 'fckmaleware' ) );
		}
		$real = wp_normalize_path( $real );
		if ( 0 !== strpos( trailingslashit( $real ), self::root() ) ) {
			return new \WP_Error( 'fckmw_outside', __( 'File is outside the WordPress directory.', 'fckmaleware' ) );
		}
		return $real;
	}

	/**
	 * Write a file atomically: temporary file in the same directory, then rename().
	 * Refuses to write through a symlink.
	 *
	 * @return true|\WP_Error
	 */
	public static function write_atomic( string $absolute, string $content, ?int $perms = null ) {
		if ( is_link( $absolute ) ) {
			return new \WP_Error( 'fckmw_symlink', __( 'Refusing to write through a symbolic link.', 'fckmaleware' ) );
		}
		$dir = dirname( $absolute );
		$tmp = $dir . '/.fckmw-' . bin2hex( random_bytes( 6 ) ) . '.tmp';
		// phpcs:disable WordPress.WP.AlternativeFunctions
		if ( strlen( $content ) !== file_put_contents( $tmp, $content, LOCK_EX ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new \WP_Error( 'fckmw_write', __( 'Could not write the file (disk full or permissions).', 'fckmaleware' ) );
		}
		if ( null !== $perms ) {
			@chmod( $tmp, $perms ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		if ( ! @rename( $tmp, $absolute ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new \WP_Error( 'fckmw_write', __( 'Could not move the new file into place.', 'fckmaleware' ) );
		}
		// phpcs:enable
		clearstatcache( true, $absolute );
		return true;
	}

	/**
	 * Files that keep the site running: removing them takes the site down, so
	 * they must be repaired (official copy / manual edit) instead of quarantined.
	 */
	public static function is_core( string $relative ): bool {
		if ( 0 === strpos( $relative, 'wp-admin/' ) || 0 === strpos( $relative, 'wp-includes/' ) ) {
			return true;
		}
		return false === strpos( $relative, '/' ) && 1 === preg_match( '/^(?:wp-[a-z-]+|index|xmlrpc)\.php$/', $relative );
	}

	/**
	 * Private directory under uploads for scan state, signature updates and
	 * quarantine. The name carries a random suffix so it cannot be guessed on
	 * servers that ignore .htaccess (nginx); 0.x used a fixed name and is migrated.
	 */
	public static function data_dir(): string {
		$uploads = wp_upload_dir( null, false );
		$base    = trailingslashit( wp_normalize_path( $uploads['basedir'] ) );
		$name    = (string) Store::get( self::DATA_DIR_OPTION, '' );

		if ( ! preg_match( '/^fckmaleware-[a-z0-9]{20}$/', $name ) ) {
			$name = 'fckmaleware-' . strtolower( wp_generate_password( 20, false, false ) );
			if ( is_dir( $base . self::LEGACY_DATA_DIR ) && ! is_link( $base . self::LEGACY_DATA_DIR ) ) {
				@rename( $base . self::LEGACY_DATA_DIR, $base . $name ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			}
			Store::set( self::DATA_DIR_OPTION, $name );
		}
		return $base . $name;
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
		foreach ( array( self::data_dir(), self::quarantine_dir(), self::data_dir() . '/signatures' ) as $dir ) {
			if ( ! wp_mkdir_p( $dir ) ) {
				return false;
			}
			$guards = array(
				'index.php'  => "<?php\n// Silence is golden.\n",
				'.htaccess'  => "<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n<IfModule mod_php.c>\n\tphp_flag engine off\n</IfModule>\n",
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
