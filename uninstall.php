<?php
/**
 * Removes all plugin data: tables, options on every site, scheduled events,
 * the uploads .htaccess rule and the private data folder (including
 * quarantined files and downloaded signatures).
 *
 * When "Keep data when the plugin is deleted" is on, only the scheduled
 * events and the uploads rule are removed, so a reinstall picks up the
 * findings, quarantine, logs and settings again.
 *
 * @package Fckmaleware
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

$fckmw_settings = is_multisite() ? get_site_option( 'fckmw_settings', array() ) : get_option( 'fckmw_settings', array() );
$fckmw_keep     = is_array( $fckmw_settings ) && ! empty( $fckmw_settings['keep_data_on_uninstall'] );

// Read the data folder name before its option is deleted.
$fckmw_dir_name = is_multisite() ? get_site_option( 'fckmw_data_dir', '' ) : get_option( 'fckmw_data_dir', '' );

if ( $fckmw_keep ) {
	$fckmw_site_ids = is_multisite() ? get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) : array( get_current_blog_id() );
	foreach ( $fckmw_site_ids as $fckmw_site_id ) {
		if ( is_multisite() ) {
			switch_to_blog( $fckmw_site_id );
		}
		foreach ( (array) _get_cron_array() as $fckmw_hooks ) {
			foreach ( array_keys( (array) $fckmw_hooks ) as $fckmw_hook ) {
				if ( 0 === strpos( (string) $fckmw_hook, 'fckmw_' ) ) {
					wp_unschedule_hook( $fckmw_hook );
				}
			}
		}
		if ( is_multisite() ) {
			restore_current_blog();
		}
	}
	return;
}

// phpcs:disable WordPress.DB
foreach ( array( 'findings', 'files', 'baseline', 'events' ) as $fckmw_table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->base_prefix}fckmw_{$fckmw_table}" );
}

$fckmw_like = array( $wpdb->esc_like( 'fckmw_' ) . '%', $wpdb->esc_like( '_transient_fckmw_' ) . '%', $wpdb->esc_like( '_transient_timeout_fckmw_' ) . '%', $wpdb->esc_like( '_site_transient_fckmw_' ) . '%', $wpdb->esc_like( '_site_transient_timeout_fckmw_' ) . '%' );
$fckmw_site_ids = is_multisite() ? get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) : array( get_current_blog_id() );

foreach ( $fckmw_site_ids as $fckmw_site_id ) {
	if ( is_multisite() ) {
		switch_to_blog( $fckmw_site_id );
	}
	foreach ( $fckmw_like as $fckmw_pattern ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $fckmw_pattern ) );
	}
	wp_cache_flush();
	foreach ( (array) _get_cron_array() as $fckmw_hooks ) {
		foreach ( array_keys( (array) $fckmw_hooks ) as $fckmw_hook ) {
			if ( 0 === strpos( (string) $fckmw_hook, 'fckmw_' ) ) {
				wp_unschedule_hook( $fckmw_hook );
			}
		}
	}
	if ( is_multisite() ) {
		restore_current_blog();
	}
}

if ( is_multisite() ) {
	foreach ( $fckmw_like as $fckmw_pattern ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $fckmw_pattern ) );
	}
}
// phpcs:enable
wp_cache_flush();

$fckmw_uploads = wp_upload_dir( null, false );
$fckmw_base    = trailingslashit( wp_normalize_path( $fckmw_uploads['basedir'] ) );

// Remove the "no PHP in uploads" rule if it was added.
require_once ABSPATH . 'wp-admin/includes/misc.php';
if ( file_exists( $fckmw_base . '.htaccess' ) ) {
	insert_with_markers( $fckmw_base . '.htaccess', 'FckMaleware', array() );
}

// The randomly named data folder and the 0.x folder name.
$fckmw_dirs = array( $fckmw_base . 'fckmaleware' );
if ( is_string( $fckmw_dir_name ) && preg_match( '/^fckmaleware-[a-z0-9]{20}$/', $fckmw_dir_name ) ) {
	$fckmw_dirs[] = $fckmw_base . $fckmw_dir_name;
}
// A data folder set with FCKMW_DATA_DIR may sit next to other files of the
// account: only FCK Malware's own entries inside it are removed.
if ( defined( 'FCKMW_DATA_DIR' ) && is_string( FCKMW_DATA_DIR ) && '' !== FCKMW_DATA_DIR ) {
	$fckmw_custom = untrailingslashit( wp_normalize_path( FCKMW_DATA_DIR ) );
	if ( is_dir( $fckmw_custom ) && ! is_link( $fckmw_custom ) && ! preg_match( '#(^|/)\.\.?(/|$)#', $fckmw_custom ) ) {
		foreach ( array( 'quarantine', 'signatures', 'backups' ) as $fckmw_sub ) {
			$fckmw_dirs[] = $fckmw_custom . '/' . $fckmw_sub;
		}
		foreach ( array( 'index.php', '.htaccess', 'web.config', 'scan-files.txt' ) as $fckmw_file ) {
			if ( is_file( $fckmw_custom . '/' . $fckmw_file ) ) {
				unlink( $fckmw_custom . '/' . $fckmw_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}
	}
}
foreach ( $fckmw_dirs as $fckmw_data ) {
	if ( ! is_dir( $fckmw_data ) || is_link( $fckmw_data ) ) {
		continue;
	}
	$fckmw_items = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $fckmw_data, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $fckmw_items as $fckmw_item ) {
		// Symlinks are removed as links, never followed.
		$fckmw_item->isDir() && ! $fckmw_item->isLink() ? rmdir( $fckmw_item->getPathname() ) : unlink( $fckmw_item->getPathname() ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}
	rmdir( $fckmw_data ); // phpcs:ignore WordPress.WP.AlternativeFunctions
}
if ( isset( $fckmw_custom ) && is_dir( $fckmw_custom ) && 2 === count( (array) scandir( $fckmw_custom ) ) ) {
	rmdir( $fckmw_custom ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- only when empty.
}

// The update checker may re-cache release data later in this request; drop it last.
add_action(
	'shutdown',
	static function (): void {
		delete_site_transient( 'fckmw_github_release' );
	},
	PHP_INT_MAX
);
