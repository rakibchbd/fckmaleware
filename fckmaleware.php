<?php
/**
 * Plugin Name:       FCK Malware
 * Plugin URI:        https://github.com/rakibchbd/fckmaleware
 * Description:       Free, open-source malware protection for WordPress: multi-layer detection (signatures, heuristics, integrity, behaviour), database scanning, safe remediation, signed signature updates and optional Imunify360 integration.
 * Version:           1.0.1
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Network:           true
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       fckmaleware
 * Update URI:        https://github.com/rakibchbd/fckmaleware
 *
 * @package Fckmaleware
 */

defined( 'ABSPATH' ) || exit;

define( 'FCKMW_VERSION', '1.0.1' );
define( 'FCKMW_FILE', __FILE__ );
define( 'FCKMW_DIR', plugin_dir_path( __FILE__ ) );
define( 'FCKMW_URL', plugin_dir_url( __FILE__ ) );

/*
 * Autoloader: Fckmaleware\FileCache → includes/class-file-cache.php,
 * Fckmaleware\Detection\Layer → includes/detection/interface-layer.php.
 */
spl_autoload_register(
	static function ( string $class ): void {
		if ( 0 !== strpos( $class, 'Fckmaleware\\' ) ) {
			return;
		}
		$parts = explode( '\\', substr( $class, 12 ) );
		$name  = strtolower( (string) preg_replace( '/(?<=[a-z0-9])([A-Z])/', '-$1', (string) array_pop( $parts ) ) );
		$dir   = FCKMW_DIR . 'includes/' . ( $parts ? strtolower( implode( '/', $parts ) ) . '/' : '' );
		foreach ( array( 'class-', 'interface-' ) as $prefix ) {
			if ( is_readable( $dir . $prefix . $name . '.php' ) ) {
				require_once $dir . $prefix . $name . '.php';
				return;
			}
		}
	}
);

register_activation_hook( __FILE__, array( \Fckmaleware\Plugin::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \Fckmaleware\Plugin::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( \Fckmaleware\Plugin::instance(), 'boot' ) );
