<?php
/**
 * Plugin settings stored in a single option, sanitized against a schema.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Settings {

	public const OPTION = 'fckmw_settings';

	public const SCHEDULES = array( 'off', 'hourly', 'twicedaily', 'daily', 'weekly' );

	/**
	 * key => [type, default, extra]; extra is the allowed values for "enum"
	 * and [min, max] for "int".
	 */
	private static function schema(): array {
		return array(
			// Scanning.
			'schedule'                 => array( 'enum', 'daily', self::SCHEDULES ),
			'scheduled_mode'           => array( 'enum', 'standard', array( 'quick', 'standard', 'deep' ) ),
			'max_file_size_mb'         => array( 'int', 4, array( 1, 64 ) ),
			'scan_images'              => array( 'bool', false ),
			'core_integrity'           => array( 'bool', true ),
			'plugin_integrity'         => array( 'bool', true ),
			'heuristics'               => array( 'bool', true ),
			'heuristic_threshold'      => array( 'int', 60, array( 30, 95 ) ),
			'scheduled_db_scan'        => array( 'bool', true ),
			'throttle_ms'              => array( 'int', 0, array( 0, 500 ) ),
			'scan_exclusions'          => array( 'paths', '' ),
			'schedule_hour'            => array( 'int', 3, array( 0, 23 ) ),
			'integrity_schedule'       => array( 'enum', 'weekly', array( 'off', 'daily', 'weekly' ) ),
			'uploads_watch'            => array( 'enum', 'twicedaily', array( 'off', 'hourly', 'twicedaily', 'daily' ) ),
			// Real-time (event-driven) protection.
			'realtime_uploads'         => array( 'bool', true ),
			'realtime_installs'        => array( 'bool', true ),
			'monitor_users'            => array( 'bool', true ),
			'monitor_options'          => array( 'bool', true ),
			'upload_block_mode'        => array( 'enum', 'malicious', array( 'malicious', 'strict', 'monitor' ) ),
			'upload_block_confidence'  => array( 'int', 80, array( 50, 100 ) ),
			'block_dangerous_extensions' => array( 'bool', true ),
			'block_mime_mismatch'      => array( 'bool', true ),
			'upload_rate_limit'        => array( 'int', 3, array( 0, 20 ) ),
			'upload_block_minutes'     => array( 'int', 60, array( 5, 1440 ) ),
			'upload_fail_mode'         => array( 'enum', 'allow', array( 'allow', 'reject' ) ),
			// Remediation.
			'auto_quarantine'          => array( 'bool', false ),
			'auto_remove_verified'     => array( 'bool', true ),
			'auto_remove_keep_days'    => array( 'int', 30, array( 0, 90 ) ),
			'quarantine_retention'     => array( 'int', 0, array( 0, 3650 ) ),
			'bulk_min_confidence'      => array( 'int', 80, array( 50, 100 ) ),
			// Notifications.
			'email_alerts'             => array( 'bool', true ),
			'alert_email'              => array( 'email', '' ),
			'notify_min_severity'      => array( 'enum', 'high', array( 'critical', 'high', 'medium', 'low' ) ),
			'notify_cooldown_hours'    => array( 'int', 24, array( 1, 168 ) ),
			'webhook_url'              => array( 'url', '' ),
			'dashboard_notices'        => array( 'bool', true ),
			'notify_scan_complete'     => array( 'bool', false ),
			// Signature updates.
			'signature_updates'        => array( 'bool', true ),
			// Imunify360.
			'imunify_enabled'          => array( 'bool', false ),
			'imunify_binary'           => array( 'enum', '', array_merge( array( '' ), Imunify::KNOWN_BINARIES ) ),
			'imunify_use_sudo'         => array( 'bool', false ),
			'imunify_sync_scan'        => array( 'bool', true ),
			'primary_scanner'          => array( 'enum', 'fckmw', array( 'fckmw', 'server' ) ),
			// Logs and data.
			'log_retention_days'       => array( 'int', 180, array( 30, 365 ) ),
			'keep_data_on_uninstall'   => array( 'bool', false ),
			// Hardening (the uploads rule kept here for 0.x compatibility).
			'block_uploads_php'        => array( 'bool', false ),
			// Optional external AI (advisory only).
			'ai_provider'              => array( 'enum', 'none', array( 'none', 'anthropic', 'openai_compatible' ) ),
			'ai_consent'               => array( 'bool', false ),
			'ai_api_key'               => array( 'secret', '' ),
			'ai_model'                 => array( 'text', '' ),
			'ai_endpoint'              => array( 'url', '' ),
			'ai_max_chars'             => array( 'int', 6000, array( 500, 20000 ) ),
			'ai_daily_limit'           => array( 'int', 25, array( 1, 1000 ) ),
		);
	}

	public static function defaults(): array {
		return array_map(
			static function ( array $spec ) {
				return $spec[1];
			},
			self::schema()
		);
	}

	public static function all(): array {
		$saved = Store::get( self::OPTION, array() );
		$all   = array_merge( self::defaults(), is_array( $saved ) ? array_intersect_key( $saved, self::schema() ) : array() );
		foreach ( self::secret_keys() as $key ) {
			$all[ $key ] = Secrets::decrypt( (string) $all[ $key ] );
		}
		if ( defined( 'FCKMW_AI_API_KEY' ) && '' !== (string) FCKMW_AI_API_KEY ) {
			$all['ai_api_key'] = (string) FCKMW_AI_API_KEY;
		}
		return $all;
	}

	/** @return string[] */
	public static function secret_keys(): array {
		return array_keys(
			array_filter(
				self::schema(),
				static function ( array $spec ): bool {
					return 'secret' === $spec[0];
				}
			)
		);
	}

	/** Relative directories excluded from scans (validated: inside the site, no traversal). */
	public static function exclusions(): array {
		return self::parse_paths( (string) self::get( 'scan_exclusions' ) );
	}

	/** @return string[] */
	public static function parse_paths( string $text ): array {
		$out = array();
		foreach ( preg_split( '/[\r\n]+/', $text ) as $line ) {
			$line = trim( str_replace( '\\', '/', $line ), " \t/" );
			if ( '' === $line || false !== strpos( $line, "\0" ) || preg_match( '#(^|/)\.\.?(/|$)#', $line ) || preg_match( '#^[a-zA-Z]:#', $line ) || ! preg_match( '#^[\w.@+ /-]+$#u', $line ) ) {
				continue;
			}
			$out[] = $line;
		}
		return array_values( array_unique( array_slice( $out, 0, 100 ) ) );
	}

	/** @return mixed */
	public static function get( string $key ) {
		$all = self::all();
		return $all[ $key ] ?? null;
	}

	/**
	 * Sanitize a (possibly partial) submission. Keys not submitted keep their
	 * current value, except checkboxes listed in $form_bools, which a form
	 * submits only when ticked.
	 *
	 * @param string[] $form_bools Boolean keys present on the submitted form.
	 */
	public static function sanitize( array $in, array $form_bools = array() ): array {
		$out = self::all();
		foreach ( self::schema() as $key => $spec ) {
			list( $type, $default ) = $spec;
			$extra = $spec[2] ?? null;

			if ( 'bool' === $type ) {
				if ( array_key_exists( $key, $in ) || in_array( $key, $form_bools, true ) ) {
					$out[ $key ] = ! empty( $in[ $key ] );
				}
				continue;
			}
			if ( ! array_key_exists( $key, $in ) ) {
				continue;
			}
			$value = is_scalar( $in[ $key ] ) ? (string) $in[ $key ] : '';
			switch ( $type ) {
				case 'enum':
					$out[ $key ] = in_array( $value, $extra, true ) ? $value : $default;
					break;
				case 'int':
					$out[ $key ] = min( $extra[1], max( $extra[0], (int) $value ) );
					break;
				case 'paths':
					$out[ $key ] = implode( "\n", self::parse_paths( $value ) );
					break;
				case 'email':
					$out[ $key ] = sanitize_email( $value );
					break;
				case 'url':
					$url         = esc_url_raw( trim( $value ), array( 'https', 'http' ) );
					$out[ $key ] = ( '' === $url || 0 === strpos( $url, 'https://' ) || 0 === strpos( $url, 'http://' ) ) ? $url : '';
					break;
				case 'secret':
					// An empty submission keeps the stored secret; "-" clears it.
					if ( '-' === trim( $value ) ) {
						$out[ $key ] = '';
					} elseif ( '' !== trim( $value ) ) {
						$out[ $key ] = sanitize_text_field( $value );
					}
					break;
				default:
					$out[ $key ] = sanitize_text_field( $value );
			}
		}
		return $out;
	}

	public static function update( array $in, array $form_bools = array() ): array {
		$clean = self::sanitize( $in, $form_bools );
		self::store( $clean );
		return $clean;
	}

	/** Persist sanitized settings; secrets are encrypted at rest. */
	private static function store( array $clean ): void {
		if ( defined( 'FCKMW_AI_API_KEY' ) && '' !== (string) FCKMW_AI_API_KEY ) {
			$saved             = Store::get( self::OPTION, array() );
			$clean['ai_api_key'] = is_array( $saved ) ? (string) ( $saved['ai_api_key'] ?? '' ) : '';
		} else {
			foreach ( self::secret_keys() as $key ) {
				$clean[ $key ] = Secrets::encrypt( (string) $clean[ $key ] );
			}
		}
		Store::set( self::OPTION, $clean );
	}

	/** Settings without secrets, for export. */
	public static function export(): array {
		return array_diff_key( self::all(), array_flip( self::secret_keys() ) );
	}

	/**
	 * Apply an exported settings array. Unknown keys and secrets are ignored;
	 * every value goes through the same validation as the settings form.
	 *
	 * @return string[] Keys that were applied.
	 */
	public static function import( array $data ): array {
		$data = array_diff_key( array_intersect_key( $data, self::schema() ), array_flip( self::secret_keys() ) );
		$bools = array_values( array_intersect( self::bool_keys(), array_keys( $data ) ) );
		foreach ( $bools as $key ) {
			$data[ $key ] = filter_var( $data[ $key ], FILTER_VALIDATE_BOOLEAN ) ? '1' : '';
		}
		self::update( $data, $bools );
		return array_keys( $data );
	}

	/** Restore defaults. Stored secrets (API keys) are kept. */
	public static function reset(): array {
		$defaults = self::defaults();
		foreach ( self::secret_keys() as $key ) {
			$defaults[ $key ] = (string) self::get( $key );
		}
		self::store( $defaults );
		return self::all();
	}

	/** Booleans in the schema, for forms that render all of them. */
	public static function bool_keys(): array {
		return array_keys(
			array_filter(
				self::schema(),
				static function ( array $spec ): bool {
					return 'bool' === $spec[0];
				}
			)
		);
	}
}
