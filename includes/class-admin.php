<?php
/**
 * Admin router: one top-level menu with five sections, each holding
 * contextual tabs, plus assets and dispatch to the tab pages.
 * State-changing requests are handled by Admin\Actions.
 *
 * Before 1.1 every screen was its own submenu (fckmaleware-findings,
 * fckmaleware-activity, ...). Those slugs are no longer registered; requests
 * for them are redirected to the matching tab so bookmarks and e-mailed links
 * keep working.
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

	/**
	 * section slug => [menu title, [tab key => [tab title, page class]]].
	 * '' is the top-level Overview. Tab keys are the pre-1.1 page slugs, so
	 * Ui::url( 'findings' ) and similar calls resolve to the right tab.
	 */
	public static function sections(): array {
		return array(
			''             => array(
				__( 'Overview', 'fckmaleware' ),
				array( '' => array( __( 'Security Overview', 'fckmaleware' ), Pages\Overview::class ) ),
			),
			'scan'         => array(
				__( 'Scan & Threats', 'fckmaleware' ),
				array(
					'scanner'    => array( __( 'Scanner', 'fckmaleware' ), Pages\Scanner::class ),
					'findings'   => array( __( 'Threat Findings', 'fckmaleware' ), Pages\Findings::class ),
					'quarantine' => array( __( 'Quarantine', 'fckmaleware' ), Pages\Quarantine::class ),
					'schedule'   => array( __( 'Schedule', 'fckmaleware' ), Pages\Schedule::class ),
				),
			),
			'protection'   => array(
				__( 'Protection', 'fckmaleware' ),
				array(
					'realtime'   => array( __( 'Real-Time Protection', 'fckmaleware' ), Pages\Realtime::class ),
					'hardening'  => array( __( 'Hardening', 'fckmaleware' ), Pages\Hardening::class ),
					'signatures' => array( __( 'Signatures', 'fckmaleware' ), Pages\SignatureDatabase::class ),
					'intel'      => array( __( 'Threat Intelligence', 'fckmaleware' ), Pages\ThreatIntel::class ),
					'ai'         => array( __( 'AI Intelligence', 'fckmaleware' ), Pages\Intelligence::class ),
				),
			),
			'integrations' => array(
				__( 'Integrations', 'fckmaleware' ),
				array(
					'integrations' => array( __( 'Server Security', 'fckmaleware' ), Pages\Integrations::class ),
					'connections'  => array( __( 'Webhooks & Updates', 'fckmaleware' ), Pages\Connections::class ),
				),
			),
			'settings'     => array(
				__( 'Settings & Logs', 'fckmaleware' ),
				array(
					'settings'    => array( __( 'Settings', 'fckmaleware' ), Pages\SettingsPage::class ),
					'activity'    => array( __( 'Activity Log', 'fckmaleware' ), Pages\Activity::class ),
					'reports'     => array( __( 'Reports', 'fckmaleware' ), Pages\Reports::class ),
					'diagnostics' => array( __( 'Diagnostics', 'fckmaleware' ), Pages\Diagnostics::class ),
				),
			),
		);
	}

	/** @return array{0: string, 1: string}|null [section, tab] for a tab key or section slug. */
	public static function locate( string $key ): ?array {
		$sections = self::sections();
		if ( isset( $sections[ $key ] ) ) {
			return array( $key, (string) array_key_first( $sections[ $key ][1] ) );
		}
		foreach ( $sections as $section => $entry ) {
			if ( isset( $entry[1][ $key ] ) ) {
				return array( (string) $section, $key );
			}
		}
		return null;
	}

	public function register(): void {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_page_access_denied', array( $this, 'redirect_legacy' ) );
		add_filter( is_multisite() ? 'network_admin_plugin_action_links_' . plugin_basename( FCKMW_FILE ) : 'plugin_action_links_' . plugin_basename( FCKMW_FILE ), array( $this, 'action_links' ) );
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'schema_notice' ) );
		add_filter( 'admin_body_class', array( $this, 'body_class' ) );
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
		add_menu_page( Ui::brand_name(), Ui::brand_name() . $badge, Plugin::capability(), Ui::SLUG, array( $this, 'render' ), 'dashicons-shield', 80 );
		foreach ( self::sections() as $slug => $section ) {
			add_submenu_page(
				Ui::SLUG,
				$section[0],
				$section[0] . ( 'scan' === $slug ? $badge : '' ),
				Plugin::capability(),
				'' === $slug ? Ui::SLUG : Ui::SLUG . '-' . $slug,
				array( $this, 'render' )
			);
		}
	}

	/**
	 * Old per-screen slugs are no longer registered, so WordPress denies them
	 * before any page code runs. Send authorised users to the new location,
	 * keeping filters such as ?status=open.
	 */
	public function redirect_legacy(): void {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- navigation only.
		$prefix = Ui::SLUG . '-';
		if ( 0 !== strpos( $page, $prefix ) || ! Ui::can() ) {
			return;
		}
		$key = substr( $page, strlen( $prefix ) );
		if ( null === self::locate( $key ) ) {
			return;
		}
		$args = array();
		foreach ( wp_unslash( $_GET ) as $name => $value ) { // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- re-encoded by add_query_arg and only used for a same-site redirect.
			if ( 'page' !== $name && is_scalar( $value ) ) {
				$args[ sanitize_key( $name ) ] = (string) $value;
			}
		}
		wp_safe_redirect( Ui::url( $key, $args ) );
		exit;
	}

	/** [section, tab] of the current FCK Malware screen, or null on other screens. */
	public static function current(): ?array {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- navigation only.
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- navigation only.
		if ( Ui::SLUG === $page ) {
			$section = '';
		} elseif ( 0 === strpos( $page, Ui::SLUG . '-' ) ) {
			$section = substr( $page, strlen( Ui::SLUG ) + 1 );
		} else {
			return null;
		}
		$sections = self::sections();
		if ( ! isset( $sections[ $section ] ) ) {
			return null;
		}
		if ( ! isset( $sections[ $section ][1][ $tab ] ) ) {
			$tab = (string) array_key_first( $sections[ $section ][1] );
		}
		return array( $section, $tab );
	}

	public function body_class( $classes ): string {
		return null === self::current() ? (string) $classes : $classes . ' fckmw-screen';
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
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'nonce'     => wp_create_nonce( 'fckmw_scan' ),
				'bulkNonce' => wp_create_nonce( 'fckmw_bulk' ),
				'scan'      => $this->plugin->scanner()->state()['status'] ?? 'idle',
				'dbScan'    => $this->plugin->db_scanner()->state()['status'] ?? 'idle',
				'bulkJob'   => BulkJob::current_status(),
				'i18n'      => array(
					'starting'     => __( 'Preparing the file list…', 'fckmaleware' ),
					/* translators: 1: checked, 2: total, 3: detections */
					'scanning'     => __( '%1$d of %2$d files checked, %3$d detections', 'fckmaleware' ),
					/* translators: 1: rows, 2: detections */
					'dbScanning'   => __( '%1$d rows checked, %2$d detections', 'fckmaleware' ),
					'done'         => __( 'Finished. Reloading…', 'fckmaleware' ),
					'cancelled'    => __( 'Cancelled.', 'fckmaleware' ),
					'error'        => __( 'Error:', 'fckmaleware' ),
					'network'      => __( 'The request failed. Check your connection and try again; the scan resumes where it stopped.', 'fckmaleware' ),
					'confirm'      => __( 'Confirm', 'fckmaleware' ),
					'cancel'       => __( 'Cancel', 'fckmaleware' ),
					'close'        => __( 'Close', 'fckmaleware' ),
					'areYouSure'   => __( 'Please confirm', 'fckmaleware' ),
					'previewing'   => __( 'Counting affected findings…', 'fckmaleware' ),
					/* translators: 1: processed, 2: total, 3: succeeded, 4: failed, 5: skipped */
					'bulkProgress' => __( '%1$d of %2$d processed: %3$d succeeded, %4$d failed, %5$d skipped', 'fckmaleware' ),
					'bulkDone'     => __( 'Bulk action finished.', 'fckmaleware' ),
					'selectFirst'  => __( 'Choose an action and at least one finding first.', 'fckmaleware' ),
					'elapsed'      => __( 'Elapsed', 'fckmaleware' ),
				),
			)
		);
	}

	public function render(): void {
		if ( ! Ui::can() ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'fckmaleware' ), 403 );
		}
		list( $section, $tab ) = self::current() ?? array( '', '' );
		$entry                 = self::sections()[ $section ][1][ $tab ];
		Ui::set_route( $section, $tab );
		Ui::set_brand( $this->brand() );
		$class = $entry[1];
		( new $class( $this->plugin ) )->render( $entry[0] );
	}

	/**
	 * Protection state for the brand bar. "Active" needs upload screening,
	 * scheduled scans and a loaded signature database; anything less is
	 * "limited" and links to the Protection screen.
	 */
	private function brand(): array {
		$settings = Settings::all();
		$sigs     = $this->plugin->signatures();
		$missing  = array();
		if ( ! $settings['realtime_uploads'] ) {
			$missing[] = 'uploads';
		}
		if ( 'off' === $settings['schedule'] ) {
			$missing[] = 'schedule';
		}
		if ( 0 === $sigs->count() ) {
			$missing[] = 'signatures';
		}
		$last = ScanHistory::latest( null, true );
		$next = wp_next_scheduled( Plugin::CRON_SCAN );
		return array(
			'label'      => $missing ? __( 'Protection limited', 'fckmaleware' ) : __( 'Protection active', 'fckmaleware' ),
			'tone'       => $missing ? ( in_array( 'signatures', $missing, true ) ? 'bad' : 'warn' ) : 'good',
			'last'       => $last ? (int) $last['finished'] : (int) ( ( (array) Store::get( 'fckmw_last_scan', array() ) )['finished'] ?? 0 ),
			'next'       => $next ? (int) $next : 0,
			'next_label' => 'off' === $settings['schedule'] ? __( 'scheduled scans are off', 'fckmaleware' ) : '',
		);
	}

	public function action_links( array $links ): array {
		array_unshift( $links, '<a href="' . esc_url( Ui::url() ) . '">' . esc_html__( 'Dashboard', 'fckmaleware' ) . '</a>', '<a href="' . esc_url( Ui::url( 'settings' ) ) . '">' . esc_html__( 'Settings', 'fckmaleware' ) . '</a>' );
		return $links;
	}
}
