<?php
/**
 * Delivers plugin updates from GitHub releases through the normal WordPress
 * update screens (Dashboard → Updates, Plugins list, auto-updates).
 *
 * The release workflow attaches fckmaleware.zip to every release; the
 * GitHub source zipball is used as a fallback, with its top-level folder
 * renamed so the plugin keeps its directory.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Updater {

	public const REPOSITORY = 'rakibchbd/fckmaleware';
	private const CACHE     = 'fckmw_github_release';
	private const ASSET     = 'fckmaleware.zip';

	/** @var string e.g. fckmaleware/fckmaleware.php */
	private $basename;

	/** @var string Directory the plugin is installed in, e.g. fckmaleware */
	private $slug;

	public function __construct() {
		$this->basename = plugin_basename( FCKMW_FILE );
		$this->slug     = dirname( $this->basename );
	}

	public function register(): void {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'inject_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 10, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_source_folder' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'flush' ), 10, 0 );
		add_action( 'load-update-core.php', array( $this, 'flush_on_force_check' ) );
	}

	public function flush(): void {
		delete_site_transient( self::CACHE );
	}

	/** "Check again" on Dashboard → Updates should really ask GitHub again. */
	public function flush_on_force_check(): void {
		if ( isset( $_GET['force-check'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$this->flush();
		}
	}

	/**
	 * Latest published release, cached for 6 hours (1 hour after a failure).
	 *
	 * @return array{version: string, package: string, url: string, notes: string, published: string}|null
	 */
	public function latest_release(): ?array {
		$cached = get_site_transient( self::CACHE );
		if ( is_array( $cached ) ) {
			return $cached['release'];
		}

		$release  = null;
		$response = wp_remote_get(
			'https://api.github.com/repos/' . self::REPOSITORY . '/releases/latest',
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept'     => 'application/vnd.github+json',
					'User-Agent' => 'FckMaleware/' . FCKMW_VERSION . '; ' . home_url(),
				),
			)
		);

		if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
			$data    = json_decode( wp_remote_retrieve_body( $response ), true );
			$version = is_array( $data ) ? ltrim( (string) ( $data['tag_name'] ?? '' ), 'vV' ) : '';
			if ( preg_match( '/^\d+(\.\d+){1,3}$/', $version ) ) {
				$package = (string) ( $data['zipball_url'] ?? '' );
				foreach ( (array) ( $data['assets'] ?? array() ) as $asset ) {
					if ( self::ASSET === ( $asset['name'] ?? '' ) ) {
						$package = (string) $asset['browser_download_url'];
					}
				}
				$release = array(
					'version'   => $version,
					'package'   => $package,
					'url'       => (string) ( $data['html_url'] ?? 'https://github.com/' . self::REPOSITORY ),
					'notes'     => (string) ( $data['body'] ?? '' ),
					'published' => (string) ( $data['published_at'] ?? '' ),
				);
			}
		}

		set_site_transient( self::CACHE, array( 'release' => $release ), $release ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
		return $release;
	}

	/**
	 * @param mixed $transient
	 * @return mixed
	 */
	public function inject_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			return $transient;
		}
		$release = $this->latest_release();
		if ( ! $release || '' === $release['package'] ) {
			return $transient;
		}

		$item = (object) array(
			'id'           => 'github.com/' . self::REPOSITORY,
			'slug'         => $this->slug,
			'plugin'       => $this->basename,
			'new_version'  => $release['version'],
			'url'          => 'https://github.com/' . self::REPOSITORY,
			'package'      => $release['package'],
			'requires_php' => '7.4',
			'requires'     => '5.8',
		);

		// Listing the plugin under no_update too is what enables the auto-update toggle.
		if ( version_compare( $release['version'], FCKMW_VERSION, '>' ) ) {
			$transient->response[ $this->basename ] = $item;
			unset( $transient->no_update[ $this->basename ] );
		} else {
			$transient->no_update[ $this->basename ] = $item;
			unset( $transient->response[ $this->basename ] );
		}
		return $transient;
	}

	/**
	 * "View details" popup on the Plugins and Updates screens.
	 *
	 * @param false|object|array $result
	 * @return false|object|array
	 */
	public function plugin_info( $result, string $action, $args ) {
		if ( 'plugin_information' !== $action || ! is_object( $args ) || ( $args->slug ?? '' ) !== $this->slug ) {
			return $result;
		}
		$release = $this->latest_release();
		if ( ! $release ) {
			return $result;
		}
		return (object) array(
			'name'          => 'FckMaleware',
			'slug'          => $this->slug,
			'version'       => $release['version'],
			'author'        => '<a href="https://github.com/' . esc_attr( self::REPOSITORY ) . '">FckMaleware</a>',
			'homepage'      => 'https://github.com/' . self::REPOSITORY,
			'download_link' => $release['package'],
			'requires'      => '5.8',
			'requires_php'  => '7.4',
			'last_updated'  => $release['published'],
			'sections'      => array(
				'description' => esc_html__( 'Malware protection for WordPress: built-in signature scanning, core integrity checks, quarantine and Imunify360 integration.', 'fckmaleware' ),
				'changelog'   => '' !== $release['notes'] ? wpautop( esc_html( $release['notes'] ) ) : esc_html__( 'See the release on GitHub.', 'fckmaleware' ),
			),
		);
	}

	/**
	 * Make sure the unpacked update lands in the plugin's existing folder,
	 * whatever the zip's top-level directory is called.
	 *
	 * @param string|\WP_Error $source
	 * @return string|\WP_Error
	 */
	public function fix_source_folder( $source, string $remote_source, $upgrader, array $hook_extra = array() ) {
		global $wp_filesystem;
		if ( is_wp_error( $source ) || ( $hook_extra['plugin'] ?? '' ) !== $this->basename ) {
			return $source;
		}
		$wanted = trailingslashit( $remote_source ) . $this->slug . '/';
		if ( untrailingslashit( $source ) === untrailingslashit( $wanted ) ) {
			return $source;
		}
		if ( ! $wp_filesystem || ! $wp_filesystem->move( $source, $wanted, true ) ) {
			return new \WP_Error( 'fckmw_update_folder', __( 'Could not prepare the FckMaleware update folder.', 'fckmaleware' ) );
		}
		return $wanted;
	}
}
