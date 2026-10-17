<?php
/**
 * Plugin settings stored in a single option.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Settings {

	public const OPTION = 'fckmw_settings';

	public const SCHEDULES = array( 'off', 'hourly', 'twicedaily', 'daily', 'weekly' );

	public static function defaults(): array {
		return array(
			'schedule'          => 'daily',
			'max_file_size_mb'  => 4,
			'scan_images'       => false,
			'core_integrity'    => true,
			'email_alerts'      => true,
			'alert_email'       => '',
			'imunify_enabled'   => false,
			'imunify_binary'    => '',
			'imunify_use_sudo'  => false,
			'imunify_sync_scan' => true,
			'block_uploads_php' => false,
		);
	}

	public static function all(): array {
		$saved = get_option( self::OPTION, array() );
		return array_merge( self::defaults(), is_array( $saved ) ? $saved : array() );
	}

	/** @return mixed */
	public static function get( string $key ) {
		$all = self::all();
		return $all[ $key ] ?? null;
	}

	public static function sanitize( array $in ): array {
		$out = self::defaults();

		$out['schedule']          = in_array( $in['schedule'] ?? '', self::SCHEDULES, true ) ? $in['schedule'] : 'daily';
		$out['max_file_size_mb']  = min( 64, max( 1, (int) ( $in['max_file_size_mb'] ?? 4 ) ) );
		$out['alert_email']       = sanitize_email( (string) ( $in['alert_email'] ?? '' ) );
		$out['imunify_binary']    = in_array( $in['imunify_binary'] ?? '', Imunify::KNOWN_BINARIES, true ) ? $in['imunify_binary'] : '';

		foreach ( array( 'scan_images', 'core_integrity', 'email_alerts', 'imunify_enabled', 'imunify_use_sudo', 'imunify_sync_scan', 'block_uploads_php' ) as $flag ) {
			$out[ $flag ] = ! empty( $in[ $flag ] );
		}

		return $out;
	}

	public static function update( array $in ): array {
		$clean = self::sanitize( $in );
		update_option( self::OPTION, $clean, false );
		return $clean;
	}
}
