<?php
/**
 * Admin router: menu, assets and dispatch to the section pages. State-changing
 * requests are handled by Admin\Actions.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

use Fckmaleware\Admin\Actions;
use Fckmaleware\Admin\Pages;
use Fckmaleware\Admin\Ui;

final class Admin {

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/** slug => [menu title, page class]. '' is the top-level Security Overview. */
	public static function pages(): array {
		return array(
			''             => array( __( 'Security Overview', 'fckmaleware' ), Pages\Overview::class ),
			'scanner'      => array( __( 'Malware Scanner', 'fckmaleware' ), Pages\Scanner::class ),
			'findings'     => array( __( 'Threat Findings', 'fckmaleware' ), Pages\Findings::class ),
			'quarantine'   => array( __( 'Quarantine', 'fckmaleware' ), Pages\Quarantine::class ),
			'realtime'     => array( __( 'Real-Time Protection', 'fckmaleware' ), Pages\Realtime::class ),
			'hardening'    => array( __( 'Security Hardening', 'fckmaleware' ), Pages\Hardening::class ),
			'ai'           => array( __( 'AI Intelligence', 'fckmaleware' ), Pages\Intelligence::class ),
			'signatures'   => array( __( 'Signature Database', 'fckmaleware' ), Pages\SignatureDatabase::class ),
			'intel'        => array( __( 'Threat Intelligence', 'fckmaleware' ), Pages\ThreatIntel::class ),
			'schedule'     => array( __( 'Scan Schedule', 'fckmaleware' ), Pages\Schedule::class ),
			'reports'      => array( __( 'Reports', 'fckmaleware' ), Pages\Reports::class ),
			'activity'     => array( __( 'Activity Log', 'fckmaleware' ), Pages\Activity::class ),
			'integrations' => array( __( 'Integrations', 'fckmaleware' ), Pages\Integrations::class ),
			'settings'     => array( __( 'Settings', 'fckmaleware' ), Pages\SettingsPage::class ),
		);
	}

	public function register(): void {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_filter( is_multisite() ? 'network_admin_plugin_action_links_' . plugin_basename( FCKMW_FILE ) : 'plugin_action_links_' . plugin_basename( FCKMW_FILE ), array( $this, 'action_links' ) );
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'schema_notice' ) );
		( new Actions( $this->plugin ) )->register();
	}

	/** A failed database upgrade must not go unnoticed: findings could not be stored. */
	public function schema_notice(): void {
		$error = get_option( 'fckmw_schema_error' );
		if ( ! is_array( $error ) || ! Ui::can() ) {
			return;
		}
		printf(
			'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s</p><p><code>%3$s</code></p></div>',
			esc_html__( 'FCK Malware could not upgrade its database tables.', 'fckmaleware' ),
			esc_html__( 'Scanning results cannot be stored until this is fixed. The upgrade is retried on every request; check that the database user may ALTER and CREATE tables.', 'fckmaleware' ),
			esc_html( trim( implode( ', ', (array) ( $error['missing'] ?? array() ) ) . ' ' . (string) ( $error['db_error'] ?? '' ) ) )
		);
	}

	public function menu(): void {
		$counts = $this->plugin->findings()->open_counts();
		$badge  = $counts['total'] ? sprintf( ' <span class="awaiting-mod">%d</span>', $counts['total'] ) : '';
		add_menu_page( __( 'FCK Malware', 'fckmaleware' ), __( 'FCK Malware', 'fckmaleware' ) . $badge, Plugin::capability(), Ui::SLUG, array( $this, 'render' ), 'dashicons-shield', 80 );
		foreach ( self::pages() as $slug => $page ) {
			add_submenu_page( Ui::SLUG, $page[0], $page[0], Plugin::capability(), '' === $slug ? Ui::SLUG : Ui::SLUG . '-' . $slug, array( $this, 'render' ) );
		}
	}

	/** Slug of the current FCK Malware screen, or null on other screens. */
	private static function current(): ?string {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- navigation only.
		if ( Ui::SLUG === $page ) {
			return '';
		}
		$prefix = Ui::SLUG . '-';
		if ( 0 === strpos( $page, $prefix ) && isset( self::pages()[ substr( $page, strlen( $prefix ) ) ] ) ) {
			return substr( $page, strlen( $prefix ) );
		}
		return null;
	}

	public function assets(): void {
		if ( null === self::current() ) {
			return;
		}
		wp_enqueue_style( 'fckmw-admin', FCKMW_URL . 'assets/admin.css', array(), FCKMW_VERSION );
		wp_enqueue_script( 'fckmw-admin', FCKMW_URL . 'assets/admin.js', array(), FCKMW_VERSION, true );
		wp_localize_script(
			'fckmw-admin',
			'fckmw',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'fckmw_scan' ),
				'scan'    => $this->plugin->scanner()->state()['status'] ?? 'idle',
				'dbScan'  => $this->plugin->db_scanner()->state()['status'] ?? 'idle',
				'i18n'    => array(
					'starting'   => __( 'Preparing the file list…', 'fckmaleware' ),
					/* translators: 1: checked, 2: total, 3: detections */
					'scanning'   => __( '%1$d of %2$d files checked, %3$d detections', 'fckmaleware' ),
					/* translators: 1: rows, 2: detections */
					'dbScanning' => __( '%1$d rows checked, %2$d detections', 'fckmaleware' ),
					'done'       => __( 'Finished. Reloading…', 'fckmaleware' ),
					'cancelled'  => __( 'Cancelled.', 'fckmaleware' ),
					'error'      => __( 'Error:', 'fckmaleware' ),
					'network'    => __( 'The request failed. Check your connection and try again; the scan resumes where it stopped.', 'fckmaleware' ),
				),
			)
		);
	}

	public function render(): void {
		if ( ! Ui::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'fckmaleware' ), 403 );
		}
		$slug  = self::current() ?? '';
		$entry = self::pages()[ $slug ];
		$class = $entry[1];
		self::nav( $slug );
		( new $class( $this->plugin ) )->render( $entry[0] );
	}

	/** Section navigation shown above every page (the admin menu holds the same links). */
	private static function nav( string $current ): void {
		echo '<nav class="fckmw-nav" aria-label="' . esc_attr__( 'FCK Malware sections', 'fckmaleware' ) . '"><ul>';
		foreach ( self::pages() as $slug => $page ) {
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a></li>',
				esc_url( Ui::url( $slug ) ),
				$slug === $current ? ' aria-current="page" class="is-current"' : '',
				esc_html( $page[0] )
			);
		}
		echo '</ul></nav>';
	}

	public function action_links( array $links ): array {
		array_unshift( $links, '<a href="' . esc_url( Ui::url() ) . '">' . esc_html__( 'Dashboard', 'fckmaleware' ) . '</a>', '<a href="' . esc_url( Ui::url( 'settings' ) ) . '">' . esc_html__( 'Settings', 'fckmaleware' ) . '</a>' );
		return $links;
	}
}
