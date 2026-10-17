<?php
/**
 * Removes all plugin data, including quarantined files.
 *
 * @package Fckmaleware
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}fckmw_findings" ); // phpcs:ignore WordPress.DB

foreach ( array( 'fckmw_settings', 'fckmw_db_version', 'fckmw_scan_state', 'fckmw_last_scan', 'fckmw_quarantine', 'fckmw_imunify_last_sync' ) as $fckmw_option ) {
	delete_option( $fckmw_option );
}

wp_clear_scheduled_hook( 'fckmw_scheduled_scan' );
wp_clear_scheduled_hook( 'fckmw_scan_continue' );

$fckmw_uploads = wp_upload_dir( null, false );

// Remove the "no PHP in uploads" rule if it was added.
require_once ABSPATH . 'wp-admin/includes/misc.php';
if ( file_exists( $fckmw_uploads['basedir'] . '/.htaccess' ) ) {
	insert_with_markers( $fckmw_uploads['basedir'] . '/.htaccess', 'FckMaleware', array() );
}

$fckmw_data = $fckmw_uploads['basedir'] . '/fckmaleware';
if ( is_dir( $fckmw_data ) ) {
	$fckmw_items = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $fckmw_data, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $fckmw_items as $fckmw_item ) {
		$fckmw_item->isDir() ? rmdir( $fckmw_item->getPathname() ) : unlink( $fckmw_item->getPathname() ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}
	rmdir( $fckmw_data ); // phpcs:ignore WordPress.WP.AlternativeFunctions
}
