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

	/** Extensions that run as code on common servers; never accepted as uploads. */
	public const DANGEROUS_EXTENSIONS = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps', 'pl', 'py', 'cgi', 'asp', 'aspx', 'jsp', 'sh', 'shtml' );

	private const ATTEMPTS_OPTION = 'fckmw_upload_attempts';
	private const BLOCKS_OPTION   = 'fckmw_upload_blocks';

	/**
	 * Inspect an upload before WordPress moves it into place and refuse it
	 * according to the upload policy:
	 *
	 * 1. accounts (or anonymous addresses) temporarily blocked after repeated
	 *    malicious uploads are refused;
	 * 2. executable extensions, including double extensions such as
	 *    "photo.php.jpg", and .htaccess / .user.ini are refused;
	 * 3. an image extension whose content holds PHP open tags is refused;
	 * 4. signature and heuristic detections are refused per upload_block_mode
	 *    (malicious at or above the threshold, "strict" also blocks suspicious
	 *    detections, "monitor" only records findings).
	 *
	 * The visitor gets a generic message; the details go to the activity log.
	 * Files over the size limit are allowed and logged as not inspected. If
	 * inspection itself fails, upload_fail_mode decides (allow and log, or reject).
	 *
	 * @param array $file Entry from $_FILES (tmp_name, name, size, ...).
	 * @return array
	 */
	public function check_upload( $file ) {
		if ( ! is_array( $file ) || ! empty( $file['error'] ) || empty( $file['tmp_name'] ) || ! is_file( $file['tmp_name'] ) ) {
			return $file;
		}
		$settings = Settings::all();
		$original = wp_basename( (string) ( $file['name'] ?? 'upload' ) );
		$name     = sanitize_file_name( $original );
		$actor    = self::actor();

		if ( self::is_blocked( $actor ) ) {
			ActivityLog::log( 'upload.refused', sprintf( /* translators: %s: file */ __( 'Upload "%s" refused: this account is temporarily blocked after repeated malicious uploads.', 'fckmaleware' ), $name ), array( 'file' => $name, 'actor' => self::actor_label( $actor ), 'ip' => self::ip() ), 'warning' );
			$file['error'] = __( 'Uploads are temporarily unavailable for your account. Please try again later or contact the site administrator.', 'fckmaleware' );
			return $file;
		}

		if ( $settings['block_dangerous_extensions'] && self::is_dangerous_name( $original ) ) {
			return $this->refuse( $file, $name, $actor, 'extension', __( 'Executable file type', 'fckmaleware' ), 'FMW-UPLOAD-EXT', 100 );
		}

		$size = (int) ( $file['size'] ?? @filesize( $file['tmp_name'] ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $size <= 0 ) {
			return $file;
		}
		if ( $size > (int) $settings['max_file_size_mb'] * MB_IN_BYTES ) {
			ActivityLog::log( 'upload.not_inspected', sprintf( /* translators: 1: file, 2: size */ __( 'Upload "%1$s" (%2$s) was accepted without inspection because it exceeds the scan size limit.', 'fckmaleware' ), $name, size_format( $size ) ), array( 'file' => $name, 'size' => $size ), 'notice' );
			return $file;
		}

		$type = Signatures::file_type( $name, true ) ?? 'image';
		if ( $settings['block_mime_mismatch'] && self::is_image_name( $name ) && self::has_php_tag( (string) $file['tmp_name'] ) ) {
			return $this->refuse( $file, $name, $actor, 'mime_mismatch', __( 'PHP code inside an image file', 'fckmaleware' ), 'FMW-UPLOAD-MIME', 95 );
		}

		try {
			$context = FileContext::from_path( 'upload:' . $name, (string) $file['tmp_name'], $type );
			$layers  = array( new SignatureLayer( $this->plugin->signatures() ) );
			if ( 'php' === $type && $settings['heuristics'] ) {
				$layers[] = new HeuristicLayer( (int) $settings['heuristic_threshold'] );
			}
			$detections = array();
			foreach ( $layers as $layer ) {
				$detections = array_merge( $detections, $layer->inspect( $context ) );
			}
		} catch ( \Throwable $e ) {
			ActivityLog::log( 'upload.inspection_failed', sprintf( /* translators: 1: file, 2: error */ __( 'Upload "%1$s" could not be inspected: %2$s', 'fckmaleware' ), $name, $e->getMessage() ), array( 'file' => $name, 'policy' => $settings['upload_fail_mode'] ), 'warning' );
			if ( 'reject' === $settings['upload_fail_mode'] ) {
				$file['error'] = __( 'This file could not be checked by the site\'s security policy, so it was not accepted. Please try again later.', 'fckmaleware' );
			}
			return $file;
		}

		$block = self::blocking_detection( $detections, (string) $settings['upload_block_mode'], (int) $settings['upload_block_confidence'] );
		if ( null === $block ) {
			return $file;
		}
		return $this->refuse( $file, $name, $actor, 'detection', (string) $block['signature_name'], (string) $block['signature_id'], (int) $block['confidence'] );
	}

	/**
	 * The detection that blocks an upload under the given policy, or null.
	 *
	 * @param array<int, array> $detections
	 */
	public static function blocking_detection( array $detections, string $mode, int $threshold ): ?array {
		if ( 'monitor' === $mode ) {
			return null;
		}
		foreach ( $detections as $detection ) {
			$confidence = (int) ( $detection['confidence'] ?? 0 );
			if ( 'malicious' === ( $detection['verdict'] ?? '' ) && $confidence >= $threshold ) {
				return $detection;
			}
			if ( 'strict' === $mode && $confidence >= min( $threshold, 60 ) ) {
				return $detection;
			}
		}
		return null;
	}

	/** Executable extension anywhere in the name (shell.php.jpg), or server config files. */
	public static function is_dangerous_name( string $name ): bool {
		$name = strtolower( trim( $name ) );
		if ( in_array( $name, array( '.htaccess', '.user.ini', 'php.ini', 'web.config' ), true ) ) {
			return true;
		}
		$parts = explode( '.', $name );
		array_shift( $parts );
		foreach ( $parts as $part ) {
			if ( in_array( trim( $part ), self::DANGEROUS_EXTENSIONS, true ) ) {
				return true;
			}
		}
		return false;
	}

	/** Raster image extensions (the ones that can never legitimately hold PHP). */
	public static function is_image_name( string $name ): bool {
		return in_array( strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) ), array( 'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'ico', 'avif', 'heic', 'tif', 'tiff' ), true );
	}

	/** PHP open tag in the first 2 MB of a file (images never legitimately contain one). */
	public static function has_php_tag( string $path ): bool {
		$head = (string) @file_get_contents( $path, false, null, 0, 2 * MB_IN_BYTES ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		return 1 === preg_match( '/<\?(?:php\b|=)/i', $head );
	}

	/**
	 * Refuse an upload, log it, count the attempt and block the actor for a
	 * while once the limit is reached. The visitor never sees which rule fired.
	 */
	private function refuse( array $file, string $name, string $actor, string $reason, string $label, string $rule, int $confidence ): array {
		ActivityLog::log(
			'upload.blocked',
			sprintf( /* translators: 1: file, 2: detection */ __( 'Blocked upload "%1$s": %2$s', 'fckmaleware' ), $name, $label ),
			array( 'file' => $name, 'reason' => $reason, 'signature' => $rule, 'confidence' => $confidence, 'user' => get_current_user_id(), 'ip' => self::ip() ),
			'critical'
		);
		self::count_attempt( $actor );
		$file['error'] = __( 'This file was rejected by the site\'s security policy.', 'fckmaleware' );
		return $file;
	}

	/** "user:ID" for logged-in users, "ip:ADDRESS" otherwise (REMOTE_ADDR only; forwarded headers can be forged). */
	private static function actor(): string {
		$user = get_current_user_id();
		return $user ? 'user:' . $user : 'ip:' . self::ip();
	}

	public static function actor_label( string $actor ): string {
		if ( 0 === strpos( $actor, 'user:' ) ) {
			$user = get_userdata( (int) substr( $actor, 5 ) );
			return $user ? $user->user_login : $actor;
		}
		return substr( $actor, 3 );
	}

	private static function count_attempt( string $actor ): void {
		$limit = (int) Settings::get( 'upload_rate_limit' );
		if ( $limit <= 0 ) {
			return;
		}
		$attempts = (array) Store::get( self::ATTEMPTS_OPTION, array() );
		$cutoff   = time() - HOUR_IN_SECONDS;
		foreach ( $attempts as $key => $times ) {
			$attempts[ $key ] = array_values(
				array_filter(
					(array) $times,
					static function ( $time ) use ( $cutoff ): bool {
						return (int) $time >= $cutoff;
					}
				)
			);
			if ( ! $attempts[ $key ] ) {
				unset( $attempts[ $key ] );
			}
		}
		$attempts[ $actor ][] = time();
		if ( count( $attempts[ $actor ] ) >= $limit ) {
			$minutes                = (int) Settings::get( 'upload_block_minutes' );
			$blocks                 = self::blocks();
			$blocks[ $actor ]       = array( 'until' => time() + $minutes * MINUTE_IN_SECONDS, 'since' => time(), 'attempts' => count( $attempts[ $actor ] ) );
			Store::set( self::BLOCKS_OPTION, $blocks );
			unset( $attempts[ $actor ] );
			ActivityLog::log(
				'upload.actor_blocked',
				sprintf( /* translators: 1: account or address, 2: minutes */ __( 'Uploads from %1$s are blocked for %2$d minutes after repeated malicious uploads.', 'fckmaleware' ), self::actor_label( $actor ), $minutes ),
				array( 'actor' => self::actor_label( $actor ), 'minutes' => $minutes, 'ip' => self::ip() ),
				'warning'
			);
		}
		Store::set( self::ATTEMPTS_OPTION, array_slice( $attempts, -200, null, true ) );
	}

	/** Active temporary upload blocks: actor => [until, since, attempts]. */
	public static function blocks(): array {
		$blocks = (array) Store::get( self::BLOCKS_OPTION, array() );
		return array_filter(
			$blocks,
			static function ( $block ): bool {
				return is_array( $block ) && (int) ( $block['until'] ?? 0 ) > time();
			}
		);
	}

	public static function is_blocked( string $actor ): bool {
		return isset( self::blocks()[ $actor ] );
	}

	/** Lift temporary upload blocks (all, or one actor). */
	public static function clear_blocks( string $actor = '' ): int {
		$blocks = self::blocks();
		$count  = '' === $actor ? count( $blocks ) : (int) isset( $blocks[ $actor ] );
		if ( '' === $actor ) {
			$blocks = array();
		} else {
			unset( $blocks[ $actor ] );
		}
		Store::set( self::BLOCKS_OPTION, $blocks );
		Store::delete( self::ATTEMPTS_OPTION );
		return $count;
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

	/**
	 * Queue a directory for a background check.
	 *
	 * @param int $since Only check files modified at or after this time (0: all).
	 */
	public function enqueue( string $dir, string $reason, int $since = 0 ): void {
		$queue = (array) Store::get( self::QUEUE_OPTION, array() );
		foreach ( $queue as $item ) {
			if ( $item['dir'] === $dir ) {
				return;
			}
		}
		$queue[] = array( 'dir' => $dir, 'reason' => $reason, 'offset' => 0, 'queued' => time(), 'since' => $since );
		Store::set( self::QUEUE_OPTION, array_slice( $queue, -50 ) );
		if ( ! wp_next_scheduled( self::CRON_QUEUE ) ) {
			wp_schedule_single_event( time() + 15, self::CRON_QUEUE );
		}
	}

	/**
	 * Periodic uploads check: files written to uploads by other plugins, FTP or
	 * the control panel never pass WordPress's upload hooks. This finds them
	 * on the next run (detection, not prevention): only files modified since
	 * the previous run are inspected.
	 */
	public function watch_uploads(): void {
		$uploads = rtrim( Paths::uploads_relative(), '/' );
		if ( '' === $uploads ) {
			Plugin::record_task( 'uploads', 'error', __( 'The uploads directory is outside the WordPress directory.', 'fckmaleware' ) );
			return;
		}
		$last = (int) Store::get( 'fckmw_uploads_watch_last', 0 );
		$now  = time();
		// First run: look back one day rather than reading every old upload.
		$this->enqueue( $uploads, 'uploads.watch', $last > 0 ? $last - 60 : $now - DAY_IN_SECONDS );
		Store::set( 'fckmw_uploads_watch_last', $now );
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
					if ( ! empty( $item['since'] ) && $file->getMTime() < (int) $item['since'] ) {
						$relative = null;
					}
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
					if ( 'uploads.watch' === $item['reason'] ) {
						Plugin::record_task( 'uploads', 'ok', sprintf( /* translators: %d: files */ __( '%d files looked at.', 'fckmaleware' ), $index ) );
					}
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
