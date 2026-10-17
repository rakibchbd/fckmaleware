<?php
/**
 * Plugin Name:       FckMaleware
 * Plugin URI:        https://github.com/rakibchbd/fckmaleware
 * Description:       Malware protection for WordPress: built-in signature scanning, core integrity checks, quarantine, and Imunify360 integration.
 * Version:           0.2.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Update URI:        https://github.com/rakibchbd/fckmaleware
 * License:           GPL-3.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain:       fckmaleware
 *
 * @package Fckmaleware
 */

defined( 'ABSPATH' ) || exit;

define( 'FCKMW_VERSION', '0.2.0' );
define( 'FCKMW_FILE', __FILE__ );
define( 'FCKMW_DIR', plugin_dir_path( __FILE__ ) );
define( 'FCKMW_URL', plugin_dir_url( __FILE__ ) );

foreach ( array( 'signatures', 'imunify', 'settings', 'paths', 'findings', 'quarantine', 'scanner', 'hardening', 'updater', 'admin', 'cli', 'plugin' ) as $fckmw_class ) {
	require_once FCKMW_DIR . "includes/class-{$fckmw_class}.php";
}
unset( $fckmw_class );

register_activation_hook( __FILE__, array( \Fckmaleware\Plugin::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \Fckmaleware\Plugin::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( \Fckmaleware\Plugin::instance(), 'boot' ) );
