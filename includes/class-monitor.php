<?php
/**
 * Event-driven ("real-time") protection through WordPress hooks.
 *
 * What this is: reactions to events WordPress itself fires (uploads, plugin
 * and theme installs/updates/activation, core updates, user and option
 * changes). What it is not: continuous filesystem monitoring. Files changed
 * outside WordPress (FTP, SSH, another compromised site on the server) are
 * only seen by the scheduled scans.
 *
 * Heavy work never runs on the triggering request: directories to inspect go
 * into a queue processed by WP-Cron in time-boxed steps. The one exception is
 * an upload, which is inspected synchronously because it can be refused before
 * it is stored.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

use Fckmaleware\Detection\FileContext;
use Fckmaleware\Detection\HeuristicLayer;
use Fckmaleware\Detection\SignatureLayer;

final class Monitor {

	public const QUEUE_OPTION = 'fckmw_event_queue';
	public const CRON_QUEUE   = 'fckmw_process_queue';

	/** Uploads carrying a detection at or above this confidence are refused. */
	private const BLOCK_CONFIDENCE = 80;

	/** Options whose change is logged (prefixed options handled separately). */
	private const WATCHED_OPTIONS = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'active_plugins', 'template', 'stylesheet' );

	/** @var Plugin */
	private $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	public function register(): void {
		$settings = Settings::all();
		add_action( self::CRON_QUEUE, array( $this, 'process_queue' ) );

		if ( $settings['realtime_uploads'] ) {
			add_filter( 'wp_handle_upload_prefilter', array( $this, 'check_upload' ) );
			add_filter( 'wp_handle_sideload_prefilter', array( $this, 'check_upload' ) );
			add_filter( 'wp_handle_upload', array( $this, 'after_upload' ) );
		}
		if ( $settings['realtime_installs'] ) {
			add_action( 'upgrader_process_complete', array( $this, 'after_upgrade' ), 20, 2 );
			add_action( 'activated_plugin', array( $this, 'plugin_activated' ), 10, 2 );
			add_action( 'deactivated_plugin', array( $this, 'plugin_deactivated' ), 10, 2 );
			add_action( 'switch_theme', array( $this, 'theme_switched' ), 10, 3 );
		}
		if ( $settings['monitor_users'] ) {
			add_action( 'user_register', array( $this, 'user_registered' ), 20 );
			add_action( 'set_user_role', array( $this, 'role_set' ), 20, 3 );
			add_action( 'add_user_role', array( $this, 'role_added' ), 20, 2 );
			add_action( 'granted_super_admin', array( $this, 'super_admin_granted' ) );
		}
		if ( $settings['monitor_options'] ) {
			add_action( 'updated_option', array( $this, 'option_updated' ), 20, 3 );
			add_action( 'update_site_option_active_sitewide_plugins', array( $this, 'network_plugins_updated' ), 20, 3 );
		}
	}

	// --- Uploads --------------------------------------------------------------

	/**
	 * Inspect an upload before WordPress moves it into place; refuse it when
	 * a high-confidence detection fires.
	 *
	 * @param array $file Entry from $_FILES (tmp_name, name, size, ...).
	 * @return array
	 */
	public function check_upload( $file ) {
		if ( ! is_array( $file ) || ! empty( $file['error'] ) || empty( $file['tmp_name'] ) || ! is_file( $file['tmp_name'] ) ) {
			return $file;
		}
		$size = (int) ( $file['size'] ?? @filesize( $file['tmp_name'] ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $size <= 0 || $size > (int) Settings::get( 'max_file_size_mb' ) * MB_IN_BYTES ) {
			return $file;
		}

		$name    = sanitize_file_name( (string) ( $file['name'] ?? 'upload' ) );
		$type    = Signatures::file_type( $name, true ) ?? 'image';
		$context = FileContext::from_path( 'upload:' . $name, (string) $file['tmp_name'], $type );
		$layers  = array( new SignatureLayer( $this->plugin->signatures() ) );
		if ( 'php' === $type && Settings::get( 'heuristics' ) ) {
			$layers[] = new HeuristicLayer( (int) Settings::get( 'heuristic_threshold' ) );
		}
		$block = null;
		foreach ( $layers as $layer ) {
			foreach ( $layer->inspect( $context ) as $detection ) {
				if ( 'malicious' === $detection['verdict'] && $detection['confidence'] >= self::BLOCK_CONFIDENCE ) {
					$block = $detection;
					break 2;
				}
			}
		}
		if ( null === $block ) {
			return $file;
		}

		ActivityLog::log(
			'upload.blocked',
			sprintf( /* translators: 1: file, 2: detection */ __( 'Blocked upload "%1$s": %2$s', 'fckmaleware' ), $name, $block['signature_name'] ),
			array( 'file' => $name, 'signature' => $block['signature_id'], 'confidence' => $block['confidence'], 'user' => get_current_user_id(), 'ip' => self::ip() ),
			'critical'
		);
		$file['error'] = sprintf(
			/* translators: %s: detection name */
			__( 'FCK Malware blocked this upload because it contains malicious code (%s).', 'fckmaleware' ),
			$block['signature_name']
		);
		return $file;
	}

	/**
	 * Record findings (e.g. lower-confidence or location rules) for an accepted upload.
	 *
	 * @param array $upload [file, url, type]
	 * @return array
	 */
	public function after_upload( $upload ) {
		if ( is_array( $upload ) && ! empty( $upload['file'] ) ) {
			$relative = Paths::relative( wp_normalize_path( (string) $upload['file'] ) );
			if ( null !== $relative ) {
				$this->plugin->scanner()->inspect_file( $relative, 'upload' );
			}
		}
		return $upload;
	}

	// --- Plugins, themes, core ------------------------------------------------

	/**
	 * @param \WP_Upgrader $upgrader
	 * @param array        $extra
	 */
	public function after_upgrade( $upgrader, $extra ): void {
		$type   = (string) ( $extra['type'] ?? '' );
		$action = (string) ( $extra['action'] ?? '' );
		$dirs   = array();

		if ( 'plugin' === $type ) {
			$plugins = (array) ( $extra['plugins'] ?? array() );
			if ( ! $plugins && is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) && $upgrader->plugin_info() ) {
				$plugins = array( $upgrader->plugin_info() );
			}
			foreach ( $plugins as $plugin ) {
				$slug = false === strpos( $plugin, '/' ) ? $plugin : dirname( $plugin );
				$this->plugin->baseline()->forget( 'plugin:' . $slug );
				$dirs[] = 'wp-content/plugins/' . $slug;
				ActivityLog::log( "plugin.{$action}", sprintf( /* translators: 1: plugin, 2: action */ __( 'Plugin %1$s: %2$s', 'fckmaleware' ), $plugin, $action ), array( 'plugin' => $plugin, 'user' => get_current_user_id() ), 'notice' );
			}
		} elseif ( 'theme' === $type ) {
			$themes = (array) ( $extra['themes'] ?? array() );
			if ( ! $themes && is_object( $upgrader ) && method_exists( $upgrader, 'theme_info' ) && $upgrader->theme_info() ) {
				$themes = array( $upgrader->theme_info()->get_stylesheet() );
			}
			foreach ( $themes as $theme ) {
				$this->plugin->baseline()->forget( 'theme:' . $theme );
				$dirs[] = 'wp-content/themes/' . $theme;
				ActivityLog::log( "theme.{$action}", sprintf( /* translators: 1: theme, 2: action */ __( 'Theme %1$s: %2$s', 'fckmaleware' ), $theme, $action ), array( 'theme' => $theme, 'user' => get_current_user_id() ), 'notice' );
			}
		} elseif ( 'core' === $type ) {
			$dirs = array( 'wp-admin', 'wp-includes' );
			ActivityLog::log( 'core.updated', __( 'WordPress core was updated.', 'fckmaleware' ), array( 'version' => $GLOBALS['wp_version'] ?? '' ), 'notice' );
		}

		foreach ( $dirs as $dir ) {
			$this->enqueue( $dir, "{$type}.{$action}" );
		}
	}

	public function plugin_activated( string $plugin, bool $network = false ): void {
		$slug = false === strpos( $plugin, '/' ) ? $plugin : dirname( $plugin );
		ActivityLog::log( 'plugin.activated', sprintf( /* translators: %s: plugin */ __( 'Plugin activated: %s', 'fckmaleware' ), $plugin ), array( 'plugin' => $plugin, 'network' => $network, 'user' => get_current_user_id() ), 'notice' );
		$this->enqueue( 'wp-content/plugins/' . $slug, 'plugin.activated' );
	}

	public function plugin_deactivated( string $plugin, bool $network = false ): void {
		$own = plugin_basename( FCKMW_FILE ) === $plugin;
		ActivityLog::log(
			'plugin.deactivated',
			sprintf( /* translators: %s: plugin */ __( 'Plugin deactivated: %s', 'fckmaleware' ), $plugin ),
			array( 'plugin' => $plugin, 'network' => $network, 'user' => get_current_user_id(), 'ip' => self::ip() ),
			$own ? 'warning' : 'info'
		);
	}

	/**
	 * @param string    $name
	 * @param \WP_Theme $theme
	 */
	public function theme_switched( $name, $theme, $old = null ): void {
		$slug = is_object( $theme ) ? $theme->get_stylesheet() : (string) $name;
		ActivityLog::log( 'theme.switched', sprintf( /* translators: %s: theme */ __( 'Active theme changed to %s', 'fckmaleware' ), $slug ), array( 'theme' => $slug, 'user' => get_current_user_id() ), 'notice' );
		$this->enqueue( 'wp-content/themes/' . $slug, 'theme.switched' );
	}

	// --- Users ----------------------------------------------------------------

	/**
	 * WordPress fires set_user_role, add_user_role and user_register for one
	 * change, so user events are collected and logged once at shutdown.
	 *
	 * @var array<int, array{created: bool, promoted: bool, previous: array}>
	 */
	private $user_events = array();

	private function note_user( int $user_id, string $what, array $previous = array() ): void {
		if ( ! $this->user_events ) {
			add_action( 'shutdown', array( $this, 'flush_user_events' ) );
		}
		$event              = $this->user_events[ $user_id ] ?? array( 'created' => false, 'promoted' => false, 'previous' => array() );
		$event[ $what ]     = true;
		$event['previous']  = $event['previous'] ? $event['previous'] : $previous;
		$this->user_events[ $user_id ] = $event;
	}

	public function user_registered( int $user_id ): void {
		$user = get_userdata( $user_id );
		if ( $user && in_array( 'administrator', (array) $user->roles, true ) ) {
			$this->note_user( $user_id, 'created' );
		}
	}

	public function role_set( int $user_id, string $role, array $old_roles = array() ): void {
		if ( 'administrator' === $role && ! in_array( 'administrator', $old_roles, true ) ) {
			$this->note_user( $user_id, 'promoted', $old_roles );
		}
	}

	public function role_added( int $user_id, string $role ): void {
		if ( 'administrator' === $role ) {
			$this->note_user( $user_id, 'promoted' );
		}
	}

	public function flush_user_events(): void {
		foreach ( $this->user_events as $user_id => $event ) {
			$user = get_userdata( $user_id );
			if ( $event['created'] ) {
				ActivityLog::log(
					'user.admin_created',
					sprintf( /* translators: 1: login, 2: email */ __( 'Administrator account created: %1$s (%2$s)', 'fckmaleware' ), $user ? $user->user_login : (string) $user_id, $user ? $user->user_email : '' ),
					array( 'user_id' => $user_id, 'by' => get_current_user_id(), 'ip' => self::ip() ),
					'critical'
				);
			} elseif ( $event['promoted'] ) {
				ActivityLog::log(
					'user.promoted',
					sprintf( /* translators: %s: login */ __( 'User promoted to administrator: %s', 'fckmaleware' ), $user ? $user->user_login : (string) $user_id ),
					array( 'user_id' => $user_id, 'previous' => $event['previous'], 'by' => get_current_user_id(), 'ip' => self::ip() ),
					'critical'
				);
			}
		}
		$this->user_events = array();
	}

	public function super_admin_granted( int $user_id ): void {
		$user = get_userdata( $user_id );
		ActivityLog::log( 'user.super_admin', sprintf( /* translators: %s: login */ __( 'Super admin granted: %s', 'fckmaleware' ), $user ? $user->user_login : (string) $user_id ), array( 'user_id' => $user_id, 'by' => get_current_user_id(), 'ip' => self::ip() ), 'critical' );
	}

	// --- Options --------------------------------------------------------------

	/**
	 * @param mixed $old
	 * @param mixed $new
	 */
	public function option_updated( string $option, $old, $new ): void {
		global $wpdb;
		$watched = in_array( $option, self::WATCHED_OPTIONS, true ) || $wpdb->get_blog_prefix() . 'user_roles' === $option;
		if ( ! $watched || $old === $new ) {
			return;
		}
		$severity = 'notice';
		if ( 'default_role' === $option && 'administrator' === $new ) {
			$severity = 'critical';
		} elseif ( in_array( $option, array( 'siteurl', 'home' ), true ) && wp_parse_url( (string) $old, PHP_URL_HOST ) !== wp_parse_url( (string) $new, PHP_URL_HOST ) ) {
			$severity = 'critical';
		} elseif ( $wpdb->get_blog_prefix() . 'user_roles' === $option || 'users_can_register' === $option || 'admin_email' === $option ) {
			$severity = 'warning';
		}
		ActivityLog::log(
			'option.changed',
			sprintf( /* translators: %s: option */ __( 'Security-relevant option changed: %s', 'fckmaleware' ), $option ),
			array( 'option' => $option, 'old' => self::summarize( $old ), 'new' => self::summarize( $new ), 'by' => get_current_user_id(), 'ip' => self::ip() ),
			$severity
		);
	}

	/**
	 * @param mixed $new
	 * @param mixed $old
	 */
	public function network_plugins_updated( $new, $old, $option = '' ): void {
		$this->option_updated( 'active_sitewide_plugins', $old, $new );
	}

	/** @param mixed $value */
	private static function summarize( $value ): string {
		$text = is_scalar( $value ) ? (string) $value : (string) wp_json_encode( $value );
		return strlen( $text ) > 300 ? substr( $text, 0, 300 ) . '…' : $text;
	}

	private static function ip(): string {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	// --- Queue ----------------------------------------------------------------

	public function enqueue( string $dir, string $reason ): void {
		$queue = (array) Store::get( self::QUEUE_OPTION, array() );
		foreach ( $queue as $item ) {
			if ( $item['dir'] === $dir ) {
				return;
			}
		}
		$queue[] = array( 'dir' => $dir, 'reason' => $reason, 'offset' => 0, 'queued' => time() );
		Store::set( self::QUEUE_OPTION, array_slice( $queue, -50 ) );
		if ( ! wp_next_scheduled( self::CRON_QUEUE ) ) {
			wp_schedule_single_event( time() + 15, self::CRON_QUEUE );
		}
	}

	/** Inspect queued directories file by file for a bounded time; re-queue the rest. */
	public function process_queue( float $budget = 20.0 ): void {
		$token = Lock::acquire( 'event-queue', (int) $budget + 60 );
		if ( null === $token ) {
			return;
		}
		try {
			$deadline = microtime( true ) + $budget;
			$queue    = (array) Store::get( self::QUEUE_OPTION, array() );
			$scanner  = $this->plugin->scanner();
			$exclude  = array( wp_normalize_path( Paths::data_dir() ) );

			while ( $queue && microtime( true ) < $deadline ) {
				$item  = $queue[0];
				$index = 0;
				$done  = true;
				foreach ( Scanner::files_in( $item['dir'], true, $exclude ) as $file ) {
					if ( $index++ < $item['offset'] ) {
						continue;
					}
					$relative = Paths::relative( wp_normalize_path( $file->getPathname() ) );
					if ( null !== $relative && null !== Signatures::file_type( $relative, false ) ) {
						$scanner->inspect_file( $relative, $item['reason'] );
					}
					if ( microtime( true ) >= $deadline ) {
						$queue[0]['offset'] = $index;
						$done               = false;
						break;
					}
				}
				if ( $done ) {
					array_shift( $queue );
					ActivityLog::log( 'event.scanned', sprintf( /* translators: %s: directory */ __( 'Event-triggered check finished: %s', 'fckmaleware' ), $item['dir'] ), array( 'dir' => $item['dir'], 'reason' => $item['reason'], 'files' => $index ) );
				}
			}
			Store::set( self::QUEUE_OPTION, $queue );
			if ( $queue ) {
				wp_schedule_single_event( time() + 30, self::CRON_QUEUE );
			}
		} finally {
			Lock::release( 'event-queue', $token );
		}
	}
}
