<?php
/**
 * Authoritative checksum sources, cached in the private data directory:
 *
 * - WordPress core: api.wordpress.org (via get_core_checksums()), MD5.
 * - wordpress.org plugins: downloads.wordpress.org/plugin-checksums, SHA-256.
 * - FCK Malware itself: checksums.json written into the release package.
 *
 * Themes and plugins from other sources have no authoritative checksums and
 * fall back to local baselines (see Baseline).
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Paths;

final class Checksums {

	private const NEGATIVE_TTL = 7 * DAY_IN_SECONDS;

	/** @var array<string, string>|null */
	private $core;

	/** @var array<string, array<string, string[]>|null> slug@version => map */
	private $plugins = array();

	/** @var array<string, string>|null */
	private $own;

	/** @var array<string, string>|null slug => version */
	private $installed_plugins;

	/** @var array<string, string> slug => version */
	private $theme_versions = array();

	private function cache_dir(): string {
		$dir = Paths::data_dir() . '/checksums';
		wp_mkdir_p( $dir );
		return $dir;
	}

	/** @return array<string, string> Relative path => md5, empty when unavailable. */
	public function core(): array {
		if ( null !== $this->core ) {
			return $this->core;
		}
		global $wp_version;
		$locale = function_exists( 'get_locale' ) ? get_locale() : 'en_US';
		$file   = $this->cache_dir() . '/core-' . preg_replace( '/[^a-zA-Z0-9._-]/', '', $wp_version . '-' . $locale ) . '.json';

		$cached = is_readable( $file ) ? json_decode( (string) file_get_contents( $file ), true ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( is_array( $cached ) && $cached ) {
			return $this->core = $cached;
		}

		require_once ABSPATH . 'wp-admin/includes/update.php';
		$checksums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $checksums ) && 'en_US' !== $locale ) {
			$checksums = get_core_checksums( $wp_version, 'en_US' );
		}
		$this->core = is_array( $checksums ) ? $checksums : array();
		if ( $this->core ) {
			file_put_contents( $file, wp_json_encode( $this->core ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		return $this->core;
	}

	/**
	 * Official checksums for a wordpress.org plugin version.
	 *
	 * @return array<string, string[]>|null Relative path inside the plugin => list of accepted SHA-256 values; null when not available.
	 */
	public function plugin( string $slug, string $version ): ?array {
		if ( ! preg_match( '/^[a-z0-9][a-z0-9._-]{0,100}$/i', $slug ) || ! preg_match( '/^[a-z0-9][a-z0-9._+-]{0,40}$/i', $version ) ) {
			return null;
		}
		$key = $slug . '@' . $version;
		if ( array_key_exists( $key, $this->plugins ) ) {
			return $this->plugins[ $key ];
		}

		$file   = $this->cache_dir() . '/plugin-' . $slug . '-' . $version . '.json';
		$cached = is_readable( $file ) ? json_decode( (string) file_get_contents( $file ), true ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( is_array( $cached ) ) {
			if ( isset( $cached['none'] ) && time() - (int) $cached['none'] < self::NEGATIVE_TTL ) {
				return $this->plugins[ $key ] = null;
			}
			if ( isset( $cached['files'] ) ) {
				return $this->plugins[ $key ] = $cached['files'];
			}
		}

		$response = wp_remote_get(
			'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json',
			array( 'timeout' => 10 )
		);
		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 200 === $code ) {
			$data  = json_decode( wp_remote_retrieve_body( $response ), true );
			$files = array();
			foreach ( (array) ( $data['files'] ?? array() ) as $path => $hashes ) {
				$sha = array_filter( array_map( 'strtolower', (array) ( $hashes['sha256'] ?? array() ) ), 'ctype_xdigit' );
				if ( $sha ) {
					$files[ (string) $path ] = array_values( $sha );
				}
			}
			if ( $files ) {
				file_put_contents( $file, wp_json_encode( array( 'files' => $files ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				return $this->plugins[ $key ] = $files;
			}
		}
		if ( 404 === $code || 200 === $code ) {
			// Not a wordpress.org plugin (or no checksums published): remember for a week.
			file_put_contents( $file, wp_json_encode( array( 'none' => time() ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		// Network errors are not cached so the next scan retries.
		return $this->plugins[ $key ] = null;
	}

	/** @return array<string, string>|null Relative path inside FCK Malware => sha256, or null in a development checkout. */
	public function own(): ?array {
		if ( null === $this->own ) {
			$file      = FCKMW_DIR . 'checksums.json';
			$data      = is_readable( $file ) ? json_decode( (string) file_get_contents( $file ), true ) : null; // phpcs:ignore WordPress.WP.AlternativeFunctions
			$this->own = is_array( $data ) && isset( $data['files'] ) ? (array) $data['files'] : array();
		}
		return $this->own ? $this->own : null;
	}

	/** @return array<string, string> Plugin directory (or single file) => version. */
	public function installed_plugins(): array {
		if ( null === $this->installed_plugins ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$this->installed_plugins = array();
			foreach ( get_plugins() as $file => $data ) {
				$slug                             = false === strpos( $file, '/' ) ? $file : dirname( $file );
				$this->installed_plugins[ $slug ] = (string) ( $data['Version'] ?? '' );
			}
		}
		return $this->installed_plugins;
	}

	public function theme_version( string $slug ): string {
		if ( ! isset( $this->theme_versions[ $slug ] ) ) {
			$theme                         = wp_get_theme( $slug );
			$this->theme_versions[ $slug ] = $theme->exists() ? (string) $theme->get( 'Version' ) : '';
		}
		return $this->theme_versions[ $slug ];
	}
}
