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
			// Real-time (event-driven) protection.
			'realtime_uploads'         => array( 'bool', true ),
			'realtime_installs'        => array( 'bool', true ),
			'monitor_users'            => array( 'bool', true ),
			'monitor_options'          => array( 'bool', true ),
			// Remediation.
			'auto_quarantine'          => array( 'bool', false ),
			'quarantine_retention'     => array( 'int', 0, array( 0, 3650 ) ),
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
		return array_merge( self::defaults(), is_array( $saved ) ? array_intersect_key( $saved, self::schema() ) : array() );
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
		Store::set( self::OPTION, $clean );
		return $clean;
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
