<?php
/**
 * Signed, versioned detection updates, independent of plugin releases.
 *
 * Install sequence (any failure leaves the active database untouched):
 *   1. Download manifest + detached signature over HTTPS (size-limited).
 *   2. Verify the Ed25519 signature with a key embedded in this plugin.
 *   3. Check schema, expiry (anti-replay), monotonic version, compatibility.
 *   4. Download the database; check size and SHA-256 from the manifest.
 *   5. Validate every signature (schema, compilation, ReDoS stress probes).
 *   6. Write atomically into the private data directory and activate.
 *
 * On every load the active file's hash is re-checked; on mismatch the
 * previous version (or the bundled database) is used and the event logged.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class SignatureUpdater {

	public const STATE_OPTION = 'fckmw_signature_state';
	public const CRON         = 'fckmw_signature_update';
	public const DEFAULT_FEED = 'https://raw.githubusercontent.com/rakibchbd/fckmaleware/main/feed/manifest.json';

	/**
	 * Trusted feed keys (key id => base64 Ed25519 public key). During a key
	 * rotation keep the old key here until every site has the new plugin.
	 */
	public const PUBLIC_KEYS = array(
		'fmw-2026-1' => 'EFsksq8xIx/uE8qJIUew3i44+6qIQqUl7guOJXdzCas=',
	);

	private const KEEP_VERSIONS = 3;

	public function register(): void {
		add_action( self::CRON, array( $this, 'scheduled_check' ) );
	}

	public static function feed_url(): string {
		$url = defined( 'FCKMW_SIGNATURE_FEED' ) ? (string) FCKMW_SIGNATURE_FEED : self::DEFAULT_FEED;
		/**
		 * URL of the signed detection-update manifest (must be HTTPS).
		 *
		 * @param string $url
		 */
		return (string) apply_filters( 'fckmw_signature_feed_url', $url );
	}

	/** @return array<string, string> */
	public static function keys(): array {
		/**
		 * Trusted Ed25519 public keys for the feed (key id => base64).
		 * Self-hosted feeds add their own key here.
		 *
		 * @param array<string, string> $keys
		 */
		return (array) apply_filters( 'fckmw_signature_feed_keys', self::PUBLIC_KEYS );
	}

	public function state(): array {
		$state = Store::get( self::STATE_OPTION, array() );
		return array_merge(
			array( 'active' => null, 'installed' => array(), 'last_check' => 0, 'last_success' => 0, 'last_error' => '', 'failures' => 0 ),
			is_array( $state ) ? $state : array()
		);
	}

	private function save( array $state ): void {
		Store::set( self::STATE_OPTION, $state );
	}

	public static function bundled_path(): string {
		return FCKMW_DIR . 'signatures/signatures.json';
	}

	private static function bundled_version(): string {
		static $version = null;
		if ( null === $version ) {
			$data    = json_decode( (string) file_get_contents( self::bundled_path() ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$version = (string) ( $data['version'] ?? '0' );
		}
		return $version;
	}

	/**
	 * Load the database to use: the newest of the verified downloaded versions
	 * and the bundled one. Downloaded files are re-hashed on every load.
	 */
	public function load(): Signatures {
		$state     = $this->state();
		$bundled   = self::bundled_version();
		$installed = $state['installed'];
		usort(
			$installed,
			static function ( $a, $b ) {
				return Feed::is_newer( $a['version'], $b['version'] ) ? -1 : 1;
			}
		);

		foreach ( $installed as $entry ) {
			if ( ! Feed::is_newer( $entry['version'], $bundled ) ) {
				break; // The bundled database (shipped with the plugin) is at least as new.
			}
			$path = $this->dir() . '/' . basename( $entry['file'] );
			$raw  = is_readable( $path ) ? (string) file_get_contents( $path ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( '' !== $raw && hash_equals( (string) $entry['sha256'], hash( 'sha256', $raw ) ) ) {
				$data = json_decode( $raw, true );
				if ( is_array( $data ) ) {
					if ( $state['active'] !== $entry['version'] ) {
						$state['active'] = $entry['version'];
						$this->save( $state );
					}
					return new Signatures( $data );
				}
			}
			ActivityLog::log( 'signatures.corrupt', sprintf( /* translators: %s: version */ __( 'Signature database %s failed its integrity check and was skipped.', 'fckmaleware' ), $entry['version'] ), array( 'version' => $entry['version'] ), 'critical' );
			$state['installed'] = array_values(
				array_filter(
					$state['installed'],
					static function ( $item ) use ( $entry ) {
						return $item['version'] !== $entry['version'];
					}
				)
			);
			$this->save( $state );
		}

		if ( $state['active'] !== $bundled ) {
			$state['active'] = $bundled;
			$this->save( $state );
		}
		return Signatures::from_file( self::bundled_path() );
	}

	public function scheduled_check(): void {
		if ( Settings::get( 'signature_updates' ) ) {
			$this->check();
		}
	}

	/**
	 * @return array{status: string, version?: string, message?: string}
	 */
	public function check(): array {
		$state               = $this->state();
		$state['last_check'] = time();
		$result              = $this->fetch_and_install( $state );

		if ( 'error' === $result['status'] ) {
			$state['last_error'] = $result['message'];
			$state['failures']++;
			ActivityLog::log( 'signatures.update_failed', __( 'Signature update failed: ', 'fckmaleware' ) . $result['message'], array( 'failures' => $state['failures'] ), $state['failures'] >= 3 ? 'warning' : 'info' );
		} else {
			$state['last_error']   = '';
			$state['failures']     = 0;
			$state['last_success'] = time();
		}
		$this->save( $state );
		return $result;
	}

	private function fetch_and_install( array &$state ): array {
		$url = self::feed_url();
		if ( 0 !== strpos( $url, 'https://' ) ) {
			return array( 'status' => 'error', 'message' => __( 'The feed URL must use HTTPS.', 'fckmaleware' ) );
		}

		$manifest = $this->get( $url, Feed::MAX_MANIFEST );
		$sig      = $this->get( $url . '.sig', 1024 );
		if ( is_wp_error( $manifest ) || is_wp_error( $sig ) ) {
			return array( 'status' => 'error', 'message' => is_wp_error( $manifest ) ? $manifest->get_error_message() : $sig->get_error_message() );
		}
		$key = Feed::verify( $manifest, $sig, self::keys() );
		if ( null === $key ) {
			return array( 'status' => 'error', 'message' => __( 'The manifest signature is invalid or made with an untrusted key. Update refused.', 'fckmaleware' ) );
		}

		$data     = json_decode( $manifest, true );
		$active   = (string) ( $state['active'] ?? self::bundled_version() );
		$active   = Feed::is_newer( self::bundled_version(), $active ) ? self::bundled_version() : $active;
		$problems = is_array( $data ) ? Feed::check_manifest( $data, $active, FCKMW_VERSION, time() ) : array( 'manifest is not JSON' );
		if ( $problems ) {
			return array( 'status' => 'error', 'message' => implode( '; ', $problems ) );
		}
		$entry = $data['signatures'];
		if ( ! Feed::is_newer( $entry['version'], $active ) ) {
			return array( 'status' => 'current', 'version' => $active );
		}

		$db = $this->get( substr( $url, 0, (int) strrpos( $url, '/' ) + 1 ) . $entry['file'], (int) $entry['size'] );
		if ( is_wp_error( $db ) ) {
			return array( 'status' => 'error', 'message' => $db->get_error_message() );
		}
		if ( strlen( $db ) !== (int) $entry['size'] || ! hash_equals( $entry['sha256'], hash( 'sha256', $db ) ) ) {
			return array( 'status' => 'error', 'message' => __( 'The downloaded database does not match the signed manifest. Update refused.', 'fckmaleware' ) );
		}
		$document = json_decode( $db, true );
		$errors   = is_array( $document ) ? Signatures::validate( $document ) : array( 'database is not JSON' );
		if ( ! $errors && (string) $document['version'] !== $entry['version'] ) {
			$errors[] = 'database version does not match the manifest';
		}
		if ( $errors ) {
			return array( 'status' => 'error', 'message' => __( 'The downloaded database failed validation: ', 'fckmaleware' ) . implode( '; ', array_slice( $errors, 0, 5 ) ) );
		}

		if ( ! Paths::ensure_data_dir() ) {
			return array( 'status' => 'error', 'message' => __( 'Could not create the signature directory.', 'fckmaleware' ) );
		}
		$file    = 'signatures-' . $entry['version'] . '.json';
		$written = Paths::write_atomic( $this->dir() . '/' . $file, $db, 0640 );
		if ( is_wp_error( $written ) ) {
			return array( 'status' => 'error', 'message' => $written->get_error_message() );
		}

		$previous             = $state['active'];
		$state['installed'][] = array( 'version' => $entry['version'], 'file' => $file, 'sha256' => $entry['sha256'], 'count' => count( $document['signatures'] ), 'installed' => time(), 'key' => $key );
		$state['installed']   = $this->prune( $state['installed'] );
		$state['active']      = $entry['version'];
		ActivityLog::log( 'signatures.updated', sprintf( /* translators: 1: old, 2: new, 3: count */ __( 'Signature database updated from %1$s to %2$s (%3$d signatures).', 'fckmaleware' ), (string) $previous, $entry['version'], count( $document['signatures'] ) ), array( 'from' => $previous, 'to' => $entry['version'], 'key' => $key ), 'notice' );
		return array( 'status' => 'updated', 'version' => $entry['version'] );
	}

	/** Keep the newest KEEP_VERSIONS downloads; delete older files. */
	private function prune( array $installed ): array {
		usort(
			$installed,
			static function ( $a, $b ) {
				return Feed::is_newer( $a['version'], $b['version'] ) ? -1 : 1;
			}
		);
		foreach ( array_slice( $installed, self::KEEP_VERSIONS ) as $old ) {
			wp_delete_file( $this->dir() . '/' . basename( $old['file'] ) );
		}
		return array_slice( $installed, 0, self::KEEP_VERSIONS );
	}

	/**
	 * Drop the newest downloaded version so the previous one (or the bundled
	 * database) becomes active.
	 *
	 * @return string|\WP_Error Version now active.
	 */
	public function rollback() {
		$state = $this->state();
		if ( ! $state['installed'] ) {
			return new \WP_Error( 'fckmw_no_previous', __( 'Only the bundled signature database is installed.', 'fckmaleware' ) );
		}
		$installed = $this->prune( $state['installed'] );
		$dropped   = array_shift( $installed );
		wp_delete_file( $this->dir() . '/' . basename( $dropped['file'] ) );
		$state['installed'] = $installed;
		$state['active']    = null;
		$this->save( $state );
		$now = $this->load()->version();
		ActivityLog::log( 'signatures.rollback', sprintf( /* translators: 1: dropped, 2: active */ __( 'Signature database rolled back from %1$s to %2$s.', 'fckmaleware' ), $dropped['version'], $now ), array( 'from' => $dropped['version'], 'to' => $now ), 'notice' );
		return $now;
	}

	private function dir(): string {
		return Paths::data_dir() . '/signatures';
	}

	/** @return string|\WP_Error */
	private function get( string $url, int $limit ) {
		$response = wp_safe_remote_get(
			$url,
			array(
				'timeout'             => 20,
				'limit_response_size' => $limit + 1,
				'redirection'         => 2,
				'headers'             => array( 'Accept' => 'application/json, text/plain' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			/* translators: 1: HTTP status, 2: URL */
			return new \WP_Error( 'fckmw_http', sprintf( __( 'HTTP %1$d from %2$s', 'fckmaleware' ), $code, $url ) );
		}
		$body = (string) wp_remote_retrieve_body( $response );
		if ( strlen( $body ) > $limit ) {
			return new \WP_Error( 'fckmw_size', __( 'Feed response exceeds the size limit.', 'fckmaleware' ) );
		}
		return $body;
	}
}
