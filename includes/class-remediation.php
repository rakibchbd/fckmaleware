<?php
/**
 * Remediation engine: quarantine, official-copy repair, rollback, cron
 * cleanup, acceptance of legitimate changes, restore points and the
 * narrowly scoped automatic quarantine.
 *
 * Before any file is modified the detection is re-confirmed against the
 * current file content, the path is resolved safely, a verified backup is
 * taken (see Quarantine) and an audit event is written. Every operation is
 * reversible from the Quarantine screen or by rolling back its restore point.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Remediation {

	private const POINTS_OPTION  = 'fckmw_restore_points';
	private const MAX_POINTS     = 50;
	private const MAX_DOWNLOAD   = 8388608;
	private const REPAIRABLE     = array( 'FMW-INT-001', 'FMW-INT-003', 'FMW-INT-010' );
	private const ACCEPT_INTEGRITY = array( 'FMW-INT-020', 'FMW-INT-021', 'FMW-INT-022' );
	private const ACCEPT_SNAPSHOT  = array( 'FMW-BEH-002', 'FMW-BEH-007' );

	/** @var Plugin */
	private $plugin;

	/** @var string|null Restore point collecting the current automatic run. */
	private $auto_point;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function register(): void {
		add_action( 'fckmw_detection', array( $this, 'maybe_auto_quarantine' ), 10, 2 );
	}

	// --- Quarantine -------------------------------------------------------------

	/** @return string|\WP_Error Quarantine key. */
	public function quarantine( int $finding_id, string $point = '' ) {
		$finding = $this->confirm( $finding_id );
		if ( is_wp_error( $finding ) ) {
			return $finding;
		}
		$file = (string) $finding['file'];
		$key  = $this->plugin->quarantine()->isolate( $file, $this->plugin->findings()->has_open( $file, 'FMW-INT-002' ), array( 'finding' => $finding_id, 'signature' => $finding['signature_id'] ) );
		if ( is_wp_error( $key ) ) {
			ActivityLog::log( 'quarantine.failed', sprintf( /* translators: 1: file, 2: error */ __( 'Could not quarantine %1$s: %2$s', 'fckmaleware' ), $file, $key->get_error_message() ), array( 'file' => $file, 'finding' => $finding_id ), 'warning' );
			return $key;
		}
		$this->plugin->findings()->set_status_for_file( $file, 'quarantined', $key );
		$this->plugin->file_cache()->forget( $file );
		$this->add_to_point( $point ? $point : $this->create_point( sprintf( /* translators: %s: file */ __( 'Quarantine %s', 'fckmaleware' ), $file ) ), 'quarantine', $key, $file );
		ActivityLog::log( 'quarantine.isolate', sprintf( /* translators: %s: file */ __( 'Quarantined %s', 'fckmaleware' ), $file ), array( 'file' => $file, 'key' => $key, 'finding' => $finding_id, 'signature' => $finding['signature_id'] ), 'notice' );
		return $key;
	}

	/**
	 * Re-check an open file finding against the file as it is now. If the file
	 * changed and the detection is gone, the finding is resolved instead.
	 *
	 * @return array|\WP_Error The finding.
	 */
	private function confirm( int $finding_id ) {
		$finding = $this->plugin->findings()->get( $finding_id );
		if ( ! $finding || 'open' !== $finding['status'] || 'file' !== $finding['object_type'] ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Finding not found, not open, or not a file.', 'fckmaleware' ) );
		}
		$absolute = Paths::file( (string) $finding['file'] );
		if ( is_wp_error( $absolute ) ) {
			if ( 'fckmw_missing' === $absolute->get_error_code() ) {
				$this->plugin->findings()->set_status( $finding_id, 'resolved' );
			}
			return $absolute;
		}
		if ( '' !== $finding['file_hash'] && ! hash_equals( (string) $finding['file_hash'], (string) hash_file( 'sha256', $absolute ) ) ) {
			$still = false;
			$now   = $this->plugin->scanner()->inspect_file( (string) $finding['file'], 'confirm' );
			foreach ( is_wp_error( $now ) ? array() : $now as $detection ) {
				if ( $detection['signature_id'] === $finding['signature_id'] ) {
					$still = true;
				}
			}
			if ( ! $still ) {
				$this->plugin->findings()->set_status( $finding_id, 'resolved' );
				return new \WP_Error( 'fckmw_changed', __( 'The file changed since it was scanned and no longer triggers this detection. The finding was marked resolved.', 'fckmaleware' ) );
			}
			$finding = (array) $this->plugin->findings()->get( $finding_id );
		}
		return $finding;
	}

	/** @return true|\WP_Error */
	public function restore( string $key ) {
		$item   = $this->plugin->quarantine()->get( $key );
		$result = $this->plugin->quarantine()->restore( $key );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		$this->plugin->findings()->release_quarantine( $key, 'open' );
		if ( $item ) {
			$this->plugin->file_cache()->forget( (string) $item['file'] );
		}
		ActivityLog::log( 'quarantine.restore', sprintf( /* translators: %s: file */ __( 'Restored %s from quarantine', 'fckmaleware' ), $item['file'] ?? $key ), array( 'key' => $key, 'file' => $item['file'] ?? '' ), 'notice' );
		return true;
	}

	/** @return true|\WP_Error */
	public function delete( string $key ) {
		$item = $this->plugin->quarantine()->get( $key );
		if ( ! $item ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Unknown quarantine entry.', 'fckmaleware' ) );
		}
		$this->plugin->quarantine()->purge( $key );
		$this->plugin->findings()->release_quarantine( $key, 'resolved' );
		ActivityLog::log( 'quarantine.delete', sprintf( /* translators: %s: file */ __( 'Permanently deleted quarantined copy of %s', 'fckmaleware' ), $item['file'] ), array( 'key' => $key, 'file' => $item['file'], 'sha256' => $item['hash'] ), 'notice' );
		return true;
	}

	// --- Official-copy repair ---------------------------------------------------

	public function can_repair( array $finding ): bool {
		return 'file' === $finding['object_type'] && in_array( $finding['signature_id'], self::REPAIRABLE, true );
	}

	/**
	 * Replace a modified (or missing) core / wordpress.org plugin file with the
	 * official copy, after verifying the download against the official checksum.
	 *
	 * @return true|\WP_Error
	 */
	public function repair( int $finding_id, string $point = '' ) {
		$finding = $this->plugin->findings()->get( $finding_id );
		if ( ! $finding || 'open' !== $finding['status'] || ! $this->can_repair( $finding ) ) {
			return new \WP_Error( 'fckmw_unknown', __( 'This finding cannot be repaired automatically.', 'fckmaleware' ) );
		}
		$file = (string) $finding['file'];
		if ( ! Paths::is_clean_relative( $file ) ) {
			return new \WP_Error( 'fckmw_path', __( 'Invalid file path.', 'fckmaleware' ) );
		}
		$source = $this->official_source( $file, (string) $finding['signature_id'] );
		if ( is_wp_error( $source ) ) {
			return $source;
		}

		$content = $this->download_verified( $source['urls'], $source['check'] );
		if ( is_wp_error( $content ) ) {
			ActivityLog::log( 'repair.failed', sprintf( /* translators: 1: file, 2: error */ __( 'Could not repair %1$s: %2$s', 'fckmaleware' ), $file, $content->get_error_message() ), array( 'file' => $file ), 'warning' );
			return $content;
		}

		$absolute = Paths::root() . $file;
		$backup   = '';
		$perms    = 0644;
		if ( file_exists( $absolute ) || is_link( $absolute ) ) {
			$backup = $this->plugin->quarantine()->backup( $file, array( 'finding' => $finding_id, 'reason' => 'repair' ) );
			if ( is_wp_error( $backup ) ) {
				return $backup;
			}
			$perms = fileperms( $absolute ) & 0777;
		} elseif ( ! is_dir( dirname( $absolute ) ) ) {
			return new \WP_Error( 'fckmw_missing_dir', __( 'The directory of the missing file does not exist; reinstall the component instead.', 'fckmaleware' ) );
		}

		$written = Paths::write_atomic( $absolute, $content, $perms ?: 0644 );
		if ( is_wp_error( $written ) ) {
			return $written;
		}
		$this->plugin->findings()->set_status_for_file( $file, 'resolved' );
		$this->plugin->file_cache()->forget( $file );
		$point = $point ? $point : $this->create_point( sprintf( /* translators: %s: file */ __( 'Repair %s', 'fckmaleware' ), $file ) );
		if ( $backup ) {
			$this->add_to_point( $point, 'repair', $backup, $file );
		}
		ActivityLog::log( 'repair.official', sprintf( /* translators: %s: file */ __( 'Replaced %s with the verified official copy', 'fckmaleware' ), $file ), array( 'file' => $file, 'backup' => $backup, 'source' => $source['urls'][0] ), 'notice' );
		return true;
	}

	/**
	 * @return array{urls: string[], check: callable}|\WP_Error
	 */
	private function official_source( string $file, string $signature_id ) {
		global $wp_version;
		if ( in_array( $signature_id, array( 'FMW-INT-001', 'FMW-INT-003' ), true ) ) {
			$core = $this->plugin->checksums()->core();
			if ( ! isset( $core[ $file ] ) ) {
				return new \WP_Error( 'fckmw_no_checksum', __( 'No official checksum is available for this file.', 'fckmaleware' ) );
			}
			$expected = (string) $core[ $file ];
			return array(
				'urls'  => array( 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . self::encode_path( $file ) ),
				'check' => static function ( string $body ) use ( $expected ): bool {
					return hash_equals( $expected, md5( $body ) );
				},
			);
		}

		$integrity = new Detection\IntegrityLayer( $this->plugin->checksums(), $this->plugin->baseline(), true, true );
		$component = $integrity->component( $file );
		if ( null === $component || 0 !== strpos( $component[0], 'plugin:' ) || '' === $component[1] ) {
			return new \WP_Error( 'fckmw_no_source', __( 'No official source is known for this file.', 'fckmaleware' ) );
		}
		list( $name, $version, $inner ) = $component;
		$slug     = substr( $name, 7 );
		$official = $this->plugin->checksums()->plugin( $slug, $version );
		if ( null === $official || ! isset( $official[ $inner ] ) ) {
			return new \WP_Error( 'fckmw_no_checksum', __( 'No official checksum is available for this plugin file.', 'fckmaleware' ) );
		}
		$expected = $official[ $inner ];
		$base     = 'https://plugins.svn.wordpress.org/' . rawurlencode( $slug );
		return array(
			'urls'  => array( $base . '/tags/' . rawurlencode( $version ) . '/' . self::encode_path( $inner ), $base . '/trunk/' . self::encode_path( $inner ) ),
			'check' => static function ( string $body ) use ( $expected ): bool {
				return in_array( hash( 'sha256', $body ), $expected, true );
			},
		);
	}

	private static function encode_path( string $path ): string {
		return implode( '/', array_map( 'rawurlencode', explode( '/', $path ) ) );
	}

	/** @return string|\WP_Error Body of the first URL whose content passes $check. */
	private function download_verified( array $urls, callable $check ) {
		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, array( 'timeout' => 20, 'limit_response_size' => self::MAX_DOWNLOAD ) );
			if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
				continue;
			}
			$body = (string) wp_remote_retrieve_body( $response );
			if ( $check( $body ) ) {
				return $body;
			}
		}
		return new \WP_Error( 'fckmw_unverified', __( 'Could not download a copy that matches the official checksum (network problem, or a localized file that differs from the English release). The file was not changed.', 'fckmaleware' ) );
	}

	// --- Other remediations -----------------------------------------------------

	/**
	 * Remove a scheduled event flagged by the persistence check.
	 *
	 * @return true|\WP_Error
	 */
	public function remove_cron_event( int $finding_id ) {
		$finding = $this->plugin->findings()->get( $finding_id );
		if ( ! $finding || 'cron' !== $finding['object_type'] || 'open' !== $finding['status'] ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Finding not found or not a scheduled event.', 'fckmaleware' ) );
		}
		$wanted = substr( (string) $finding['object_ref'], 5 );
		foreach ( (array) _get_cron_array() as $timestamp => $hooks ) {
			foreach ( (array) $hooks as $hook => $events ) {
				foreach ( (array) $events as $event ) {
					$payload = (string) wp_json_encode( array( $hook, $event['args'] ?? array() ), JSON_UNESCAPED_SLASHES );
					if ( md5( $hook . $payload ) === $wanted ) {
						wp_unschedule_event( (int) $timestamp, (string) $hook, (array) ( $event['args'] ?? array() ) );
						$this->plugin->findings()->set_status( $finding_id, 'resolved' );
						ActivityLog::log( 'cron.removed', sprintf( /* translators: %s: hook */ __( 'Removed scheduled event "%s"', 'fckmaleware' ), $hook ), array( 'hook' => $hook, 'timestamp' => $timestamp, 'payload' => substr( $payload, 0, 2000 ) ), 'notice' );
						return true;
					}
				}
			}
		}
		$this->plugin->findings()->set_status( $finding_id, 'resolved' );
		return new \WP_Error( 'fckmw_gone', __( 'The scheduled event no longer exists; the finding was marked resolved.', 'fckmaleware' ) );
	}

	/**
	 * Ignore a finding. For "changed since baseline" and "new admin / changed
	 * site URL" findings this means "I made this change": the baseline or
	 * snapshot is updated and the finding resolved instead.
	 *
	 * @return true|\WP_Error
	 */
	public function accept( int $finding_id ) {
		$finding = $this->plugin->findings()->get( $finding_id );
		if ( ! $finding ) {
			return new \WP_Error( 'fckmw_unknown', __( 'Finding not found.', 'fckmaleware' ) );
		}
		if ( in_array( $finding['signature_id'], self::ACCEPT_INTEGRITY, true ) ) {
			$absolute = Paths::file( (string) $finding['file'] );
			if ( is_wp_error( $absolute ) ) {
				return $absolute;
			}
			$integrity = new Detection\IntegrityLayer( $this->plugin->checksums(), $this->plugin->baseline(), true, true );
			$component = $integrity->component( (string) $finding['file'] );
			if ( null !== $component ) {
				$this->plugin->baseline()->set( (string) $finding['file'], $component[0], $component[1], (string) hash_file( 'sha256', $absolute ) );
			}
			$this->plugin->findings()->set_status( $finding_id, 'resolved' );
			ActivityLog::log( 'baseline.accepted', sprintf( /* translators: %s: file */ __( 'Accepted the current version of %s as baseline', 'fckmaleware' ), $finding['file'] ), array( 'file' => $finding['file'] ), 'notice' );
			return true;
		}
		if ( in_array( $finding['signature_id'], self::ACCEPT_SNAPSHOT, true ) ) {
			$this->plugin->persistence()->accept_current_state();
			$this->plugin->findings()->set_status( $finding_id, 'resolved' );
			ActivityLog::log( 'persistence.accepted', sprintf( /* translators: %s: object */ __( 'Accepted current state: %s', 'fckmaleware' ), $finding['file'] ), array( 'finding' => $finding_id ), 'notice' );
			return true;
		}
		$this->plugin->findings()->set_status( $finding_id, 'ignored' );
		ActivityLog::log( 'finding.ignored', sprintf( /* translators: 1: detection, 2: object */ __( 'Ignored %1$s on %2$s', 'fckmaleware' ), $finding['signature_id'], $finding['file'] ), array( 'finding' => $finding_id ), 'notice' );
		return true;
	}

	/**
	 * Why a finding must not be quarantined (null when it may be).
	 *
	 * Hard rules apply always. With $policy (bulk "all matching / all
	 * eligible" selections), weaker detections are left for review too.
	 */
	public function quarantine_eligibility( array $finding, bool $policy = true ): ?string {
		$file = (string) $finding['file'];
		if ( 'file' !== $finding['object_type'] ) {
			return __( 'Not a file (database record, account or setting): review it where it lives.', 'fckmaleware' );
		}
		if ( 'FMW-INT-003' === $finding['signature_id'] ) {
			return __( 'The file is missing, so there is nothing to quarantine.', 'fckmaleware' );
		}
		if ( Paths::is_critical_config( $file ) ) {
			return __( 'Critical configuration file: clean it by hand instead of removing it.', 'fckmaleware' );
		}
		if ( Paths::is_core( $file ) && 'FMW-INT-002' !== $finding['signature_id'] ) {
			return __( 'WordPress core file: use "Replace with official copy" instead.', 'fckmaleware' );
		}
		if ( ! $policy ) {
			return null;
		}
		if ( 'integrity' === $finding['source'] && 'FMW-INT-002' !== $finding['signature_id'] ) {
			return __( 'Modified file: replace it with the official copy or accept the change.', 'fckmaleware' );
		}
		if ( in_array( $finding['remediation'], array( 'clean', 'repair' ), true ) ) {
			return __( 'Injected code in a legitimate file: clean or reinstall it instead.', 'fckmaleware' );
		}
		if ( 'malicious' !== $finding['verdict'] ) {
			return __( 'Suspicious only: review before quarantining.', 'fckmaleware' );
		}
		$minimum = (int) Settings::get( 'bulk_min_confidence' );
		if ( (int) $finding['confidence'] < $minimum ) {
			/* translators: %d: confidence threshold */
			return sprintf( __( 'Confidence below the bulk threshold (%d%%).', 'fckmaleware' ), $minimum );
		}
		if ( 'heuristic' === $finding['source'] && self::in_active_component( $file ) ) {
			return __( 'Heuristic match in an active plugin or theme: review it first.', 'fckmaleware' );
		}
		return null;
	}

	/** Whether a path belongs to an active plugin (any site) or the active theme. */
	public static function in_active_component( string $file ): bool {
		static $prefixes = null;
		if ( null === $prefixes ) {
			$prefixes = array();
			$plugins  = array_merge( (array) get_option( 'active_plugins', array() ), is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array() );
			$base     = Paths::relative( wp_normalize_path( WP_PLUGIN_DIR ) );
			foreach ( $plugins as $plugin ) {
				$plugin = (string) $plugin;
				if ( null !== $base ) {
					$prefixes[] = trailingslashit( $base ) . ( false === strpos( $plugin, '/' ) ? $plugin : dirname( $plugin ) . '/' );
				}
			}
			foreach ( array_unique( array( get_stylesheet_directory(), get_template_directory() ) ) as $dir ) {
				$relative = Paths::relative( wp_normalize_path( $dir ) );
				if ( null !== $relative ) {
					$prefixes[] = trailingslashit( $relative );
				}
			}
			$mu = Paths::relative( wp_normalize_path( WPMU_PLUGIN_DIR ) );
			if ( null !== $mu ) {
				$prefixes[] = trailingslashit( $mu );
			}
		}
		foreach ( $prefixes as $prefix ) {
			if ( 0 === strpos( $file, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	// --- Automatic quarantine ---------------------------------------------------

	/**
	 * Only narrowly defined threats qualify: never core files, plugin or theme
	 * files (premium code has no reference copy), or ambiguous detections.
	 */
	public static function auto_eligible( array $detection, string $file ): bool {
		if ( 'malicious' !== ( $detection['verdict'] ?? '' ) || Paths::is_core( $file ) || Paths::is_critical_config( $file ) ) {
			return false;
		}
		$uploads = Paths::uploads_relative();
		$in_uploads = '' !== $uploads && 0 === strpos( $file, $uploads );
		$is_image   = 'image' === Signatures::file_type( $file, true );
		$hash_match = 'hash' === ( $detection['technique'] ?? '' );

		if ( 'signature' === $detection['source'] ) {
			return (int) $detection['confidence'] >= 90 && ( $hash_match || $is_image || $in_uploads );
		}
		if ( 'heuristic' === $detection['source'] ) {
			return (int) $detection['confidence'] >= 95 && $in_uploads;
		}
		return false;
	}

	/**
	 * @param array $detection Detection plus "file".
	 * @param array $result    Findings::upsert() result.
	 */
	public function maybe_auto_quarantine( array $detection, array $result ): void {
		if ( ! Settings::get( 'auto_quarantine' ) || 'ignored' === $result['outcome'] || empty( $detection['file'] ) ) {
			return;
		}
		// When a server scanner is the primary remediation owner, FCK Malware only
		// reports, so two products never race to move the same file.
		if ( 'server' === Settings::get( 'primary_scanner' ) && Settings::get( 'imunify_enabled' ) ) {
			return;
		}
		$file = (string) $detection['file'];
		if ( ! self::auto_eligible( $detection, $file ) || ! file_exists( Paths::root() . $file ) ) {
			return;
		}
		if ( null === $this->auto_point ) {
			$this->auto_point = $this->create_point( __( 'Automatic quarantine', 'fckmaleware' ) );
		}
		$key = $this->quarantine( (int) $result['id'], $this->auto_point );
		if ( ! is_wp_error( $key ) ) {
			ActivityLog::log( 'quarantine.auto', sprintf( /* translators: 1: file, 2: detection */ __( 'Automatically quarantined %1$s (%2$s)', 'fckmaleware' ), $file, $detection['signature_name'] ), array( 'file' => $file, 'key' => $key, 'signature' => $detection['signature_id'] ), 'critical' );
		}
	}

	// --- Restore points ---------------------------------------------------------

	public function points(): array {
		$points = Store::get( self::POINTS_OPTION, array() );
		return is_array( $points ) ? $points : array();
	}

	public function create_point( string $label ): string {
		$id               = bin2hex( random_bytes( 6 ) );
		$points           = $this->points();
		$points[ $id ]    = array( 'label' => $label, 'time' => time(), 'user' => get_current_user_id(), 'items' => array() );
		Store::set( self::POINTS_OPTION, array_slice( $points, -self::MAX_POINTS, null, true ) );
		return $id;
	}

	private function add_to_point( string $point, string $action, string $key, string $file ): void {
		$points = $this->points();
		if ( isset( $points[ $point ] ) ) {
			$points[ $point ]['items'][] = array( 'action' => $action, 'key' => $key, 'file' => $file );
			Store::set( self::POINTS_OPTION, $points );
		}
	}

	/**
	 * Undo everything recorded in a restore point (restores quarantined files
	 * and pre-repair backups that still exist).
	 *
	 * @return array{restored: int, failed: string[]}
	 */
	public function rollback( string $point ): array {
		$points = $this->points();
		$out    = array( 'restored' => 0, 'failed' => array() );
		if ( ! isset( $points[ $point ] ) ) {
			return $out;
		}
		foreach ( array_reverse( $points[ $point ]['items'] ) as $item ) {
			if ( null === $this->plugin->quarantine()->get( $item['key'] ) ) {
				continue; // Already restored or deleted.
			}
			$result = $this->restore( $item['key'] );
			if ( is_wp_error( $result ) ) {
				$out['failed'][] = $item['file'] . ': ' . $result->get_error_message();
			} else {
				$out['restored']++;
			}
		}
		unset( $points[ $point ] );
		Store::set( self::POINTS_OPTION, $points );
		ActivityLog::log( 'restore_point.rollback', sprintf( /* translators: %d: count */ __( 'Rolled back a restore point (%d files restored).', 'fckmaleware' ), $out['restored'] ), $out, 'notice' );
		return $out;
	}
}
