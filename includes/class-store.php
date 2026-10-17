<?php
/**
 * Plugin-owned options. The filesystem (and therefore scan state, quarantine
 * and settings) is shared by the whole network on multisite, so values live
 * in network options there and in non-autoloaded options otherwise.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Store {

	/**
	 * @param mixed $default
	 * @return mixed
	 */
	public static function get( string $key, $default = false ) {
		return is_multisite() ? get_site_option( $key, $default ) : get_option( $key, $default );
	}

	/** @param mixed $value */
	public static function set( string $key, $value ): void {
		if ( is_multisite() ) {
			update_site_option( $key, $value );
		} else {
			update_option( $key, $value, false );
		}
	}

	public static function delete( string $key ): void {
		if ( is_multisite() ) {
			delete_site_option( $key );
		} else {
			delete_option( $key );
		}
	}
}
