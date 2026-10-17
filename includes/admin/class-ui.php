<?php
/**
 * Rendering helpers and reusable components shared by the admin pages:
 * page shell (breadcrumbs, title, contextual tabs, notices), metric tiles,
 * status pills, empty states, forms and pagination. Everything printed goes
 * through esc_html / esc_attr / esc_url here or at the call site.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin;

use Fckmaleware\Admin as Router;
use Fckmaleware\Plugin;

final class Ui {

	public const SLUG = 'fckmaleware';

	/** @var string Current section slug. */
	private static $section = '';

	/** @var string Current tab key. */
	private static $tab = '';

	/** @var array{label: string, tone: string, last: int, next: int, next_label: string} Brand bar data. */
	private static $brand = array();

	public static function set_route( string $section, string $tab ): void {
		self::$section = $section;
		self::$tab     = $tab;
	}

	public static function set_brand( array $brand ): void {
		self::$brand = $brand;
	}

	/** Product name shown in the admin. The plugin itself keeps its "FCK Malware" identity. */
	public static function brand_name(): string {
		return __( 'FCK Security', 'fckmaleware' );
	}

	/**
	 * URL of a screen. $page is a tab key (the pre-1.1 page slug such as
	 * "findings"), a section slug ("scan") or '' for the overview.
	 */
	public static function url( string $page = '', array $args = array() ): string {
		$base     = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		$location = '' === $page ? null : Router::locate( $page );
		$query    = array( 'page' => self::SLUG );
		if ( null !== $location && '' !== $location[0] ) {
			$query['page'] = self::SLUG . '-' . $location[0];
			$tabs          = Router::sections()[ $location[0] ][1];
			if ( (string) array_key_first( $tabs ) !== $location[1] ) {
				$query['tab'] = $location[1];
			}
		}
		unset( $args['page'], $args['tab'] );
		return add_query_arg( array_merge( $query, $args ), $base );
	}

	/** Hidden page/tab fields for GET filter forms that must stay on the current screen. */
	public static function location_fields( string $page ): void {
		parse_str( (string) wp_parse_url( self::url( $page ), PHP_URL_QUERY ), $query );
		foreach ( array( 'page', 'tab' ) as $name ) {
			if ( isset( $query[ $name ] ) ) {
				echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( (string) $query[ $name ] ) . '">';
			}
		}
	}

	public static function post_url(): string {
		return is_multisite() ? network_admin_url( 'edit.php?action=fckmw' ) : admin_url( 'admin-post.php' );
	}

	/**
	 * Page shell: breadcrumbs, title, intro, section tabs and the flash notice.
	 *
	 * @param string $actions Pre-escaped HTML for header actions (buttons).
	 */
	public static function header( string $title, string $intro = '', string $actions = '' ): void {
		$sections = Router::sections();
		$section  = $sections[ self::$section ] ?? $sections[''];

		echo '<div class="wrap fckmw">';
		self::brandbar();
		echo '<div class="fckmw-header">';
		echo '<nav class="fckmw-breadcrumbs" aria-label="' . esc_attr__( 'Breadcrumb', 'fckmaleware' ) . '"><ol>';
		echo '<li><a href="' . esc_url( self::url() ) . '"><span class="dashicons dashicons-shield" aria-hidden="true"></span> ' . esc_html( self::brand_name() ) . '</a></li>';
		if ( '' !== self::$section ) {
			echo '<li><a href="' . esc_url( self::url( self::$section ) ) . '">' . esc_html( $section[0] ) . '</a></li>';
			echo '<li aria-current="page">' . esc_html( $title ) . '</li>';
		}
		echo '</ol></nav>';
		echo '<div class="fckmw-header-main"><h1 class="fckmw-title">' . esc_html( $title ) . '</h1>';
		if ( '' !== $actions ) {
			echo '<div class="fckmw-header-actions">' . $actions . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built from escaped parts by the caller.
		}
		echo '</div>';
		if ( '' !== $intro ) {
			echo '<p class="fckmw-intro">' . esc_html( $intro ) . '</p>';
		}
		echo '</div>';

		if ( count( $section[1] ) > 1 ) {
			echo '<nav class="fckmw-tabs" aria-label="' . esc_attr( $section[0] ) . '"><ul>';
			foreach ( $section[1] as $key => $tab ) {
				printf(
					'<li><a href="%1$s"%2$s>%3$s</a></li>',
					esc_url( self::url( (string) $key ) ),
					(string) $key === self::$tab ? ' aria-current="page" class="is-current"' : '',
					esc_html( $tab[0] )
				);
			}
			echo '</ul></nav>';
		}
		// WordPress moves notices printed before the first h1/h2 inside .wrap; this anchor keeps them here.
		echo '<hr class="wp-header-end">';
		self::notice();
	}

	/** Product bar on every screen: protection state, last and next scan (all live values). */
	private static function brandbar(): void {
		$brand = self::$brand + array( 'label' => '', 'tone' => 'neutral', 'last' => 0, 'next' => 0, 'next_label' => '' );
		echo '<div class="fckmw-brandbar">';
		echo '<a class="fckmw-brand" href="' . esc_url( self::url() ) . '"><span class="fckmw-brand-mark"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span></span><span><span class="fckmw-brand-name">' . esc_html( self::brand_name() ) . '</span><span class="fckmw-brand-sub">' . esc_html__( 'WordPress Malware Protection Center', 'fckmaleware' ) . '</span></span></a>';
		echo '<div class="fckmw-brand-meta">';
		if ( '' !== $brand['label'] ) {
			echo '<a class="fckmw-pill fckmw-tone-' . esc_attr( $brand['tone'] ) . '" href="' . esc_url( self::url( 'realtime' ) ) . '"><span class="dashicons dashicons-' . ( 'good' === $brand['tone'] ? 'shield' : 'warning' ) . '" aria-hidden="true"></span>' . esc_html( $brand['label'] ) . '</a>';
		}
		echo '<span><span class="dashicons dashicons-calendar-alt" aria-hidden="true"></span>' . esc_html__( 'Last scan:', 'fckmaleware' ) . ' ' . self::when( (int) $brand['last'] ) . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput -- when() escapes.
		echo '<span><span class="dashicons dashicons-clock" aria-hidden="true"></span>' . esc_html__( 'Next scan:', 'fckmaleware' ) . ' ' . ( $brand['next'] ? esc_html( self::datetime( (int) $brand['next'] ) ) : esc_html( '' !== $brand['next_label'] ? $brand['next_label'] : __( 'not scheduled', 'fckmaleware' ) ) ) . '</span>';
		echo '</div></div>';
	}

	public static function footer(): void {
		echo '<footer class="fckmw-footer"><span>' . esc_html( self::brand_name() ) . ' · ' . esc_html( sprintf( /* translators: %s: version */ __( 'FCK Malware %s', 'fckmaleware' ), FCKMW_VERSION ) ) . '</span>';
		echo '<span><a href="https://github.com/rakibchbd/fckmaleware#readme" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Documentation', 'fckmaleware' ) . '</a> · <a href="https://github.com/rakibchbd/fckmaleware/issues" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Support', 'fckmaleware' ) . '</a> · <a href="' . esc_url( self::url( 'diagnostics' ) ) . '">' . esc_html__( 'Diagnostics', 'fckmaleware' ) . '</a></span></footer>';
		echo '</div>';
	}

	private static function notice(): void {
		$key    = 'fckmw_notice_' . get_current_user_id();
		$notice = get_site_transient( $key );
		if ( is_array( $notice ) ) {
			delete_site_transient( $key );
			printf( '<div class="notice notice-%1$s is-dismissible fckmw-flash"><p>%2$s</p></div>', esc_attr( $notice[0] ), esc_html( $notice[1] ) );
		}
	}

	public static function set_notice( string $type, string $message ): void {
		set_site_transient( 'fckmw_notice_' . get_current_user_id(), array( $type, $message ), MINUTE_IN_SECONDS );
	}

	/** Inline (non-flash) message box. $tone: info, success, warning, error. */
	public static function callout( string $message, string $tone = 'info', string $title = '' ): void {
		printf(
			'<div class="fckmw-callout fckmw-callout-%1$s">%2$s<p>%3$s</p></div>',
			esc_attr( $tone ),
			'' !== $title ? '<p class="fckmw-callout-title">' . esc_html( $title ) . '</p>' : '',
			esc_html( $message )
		);
	}

	public static function card_start( string $title = '', string $class = '', string $description = '', string $id = '' ): void {
		echo '<section class="fckmw-card ' . esc_attr( $class ) . '"' . ( '' !== $id ? ' id="' . esc_attr( $id ) . '"' : '' ) . '>';
		if ( '' !== $title ) {
			echo '<h2 class="fckmw-card-title">' . esc_html( $title ) . '</h2>';
		}
		if ( '' !== $description ) {
			echo '<p class="fckmw-card-desc">' . esc_html( $description ) . '</p>';
		}
	}

	public static function card_end(): void {
		echo '</section>';
	}

	/** Collapsible group for advanced or secondary content (progressive disclosure). */
	public static function disclosure_start( string $summary, bool $open = false, string $class = '' ): void {
		echo '<details class="fckmw-disclosure ' . esc_attr( $class ) . '"' . ( $open ? ' open' : '' ) . '><summary>' . esc_html( $summary ) . '</summary><div class="fckmw-disclosure-body">';
	}

	public static function disclosure_end(): void {
		echo '</div></details>';
	}

	/** A number tile. $tone: neutral, good, warn, bad, critical. */
	public static function stat( string $label, string $value, string $tone = 'neutral', string $sub = '', string $link = '' ): void {
		$inner = '<span class="fckmw-stat-label">' . esc_html( $label ) . '</span><span class="fckmw-stat-value">' . esc_html( $value ) . '</span>';
		if ( '' !== $sub ) {
			$inner .= '<span class="fckmw-stat-sub">' . esc_html( $sub ) . '</span>';
		}
		if ( '' !== $link ) {
			printf( '<a class="fckmw-stat fckmw-tone-%1$s" href="%2$s">%3$s</a>', esc_attr( $tone ), esc_url( $link ), $inner ); // phpcs:ignore WordPress.Security.EscapeOutput -- built from escaped parts.
		} else {
			printf( '<div class="fckmw-stat fckmw-tone-%1$s">%2$s</div>', esc_attr( $tone ), $inner ); // phpcs:ignore WordPress.Security.EscapeOutput
		}
	}

	public static function badge( string $text, string $tone = 'neutral' ): string {
		return '<span class="fckmw-badge fckmw-tone-' . esc_attr( $tone ) . '">' . esc_html( $text ) . '</span>';
	}

	/** Status indicator with a dot: good, warn, bad, neutral, off. */
	public static function status( string $text, string $tone = 'neutral' ): string {
		return '<span class="fckmw-status fckmw-tone-' . esc_attr( $tone ) . '"><span class="fckmw-dot" aria-hidden="true"></span>' . esc_html( $text ) . '</span>';
	}

	/** Key/value row list: [[label, value-html], ...]. Values must be escaped by the caller. */
	public static function kv( array $rows ): void {
		echo '<dl class="fckmw-dl">';
		foreach ( $rows as $row ) {
			echo '<dt>' . esc_html( (string) $row[0] ) . '</dt><dd>' . $row[1] . '</dd>'; // phpcs:ignore WordPress.Security.EscapeOutput -- escaped by the caller.
		}
		echo '</dl>';
	}

	public static function empty_state( string $title, string $text = '', string $action_html = '', string $icon = 'yes-alt' ): void {
		echo '<div class="fckmw-empty"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span><p class="fckmw-empty-title">' . esc_html( $title ) . '</p>';
		if ( '' !== $text ) {
			echo '<p>' . esc_html( $text ) . '</p>';
		}
		if ( '' !== $action_html ) {
			echo '<p>' . $action_html . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput -- built by the caller from escaped parts.
		}
		echo '</div>';
	}

	public static function button_link( string $url, string $label, string $class = 'button' ): string {
		return '<a class="' . esc_attr( $class ) . '" href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
	}

	public static function severity( string $severity ): string {
		$tones = array( 'critical' => 'critical', 'high' => 'bad', 'medium' => 'warn', 'low' => 'neutral' );
		return self::badge( ucfirst( $severity ), $tones[ $severity ] ?? 'neutral' );
	}

	/**
	 * How certain a finding is, in words: confirmed malware (exact or very
	 * high-confidence matches), likely malicious, suspicious, or a change that
	 * needs review. Never shows every suspicious file as malware.
	 */
	public static function classification( array $row ): string {
		$class  = \Fckmaleware\Findings::classify( $row );
		$labels = array(
			'confirmed'  => array( __( 'Confirmed malware', 'fckmaleware' ), 'critical' ),
			'likely'     => array( __( 'Likely malicious', 'fckmaleware' ), 'bad' ),
			'suspicious' => array( __( 'Suspicious', 'fckmaleware' ), 'warn' ),
			'change'     => array( __( 'Unverified change', 'fckmaleware' ), 'neutral' ),
		);
		return self::badge( $labels[ $class ][0], $labels[ $class ][1] );
	}

	public static function verdict( string $verdict, int $confidence ): string {
		return self::badge( sprintf( '%s · %d%%', $verdict, $confidence ), 'malicious' === $verdict ? 'bad' : 'warn' );
	}

	public static function state( string $state ): string {
		$map = array(
			'pass'    => array( __( 'Pass', 'fckmaleware' ), 'good' ),
			'warn'    => array( __( 'Needs attention', 'fckmaleware' ), 'warn' ),
			'fail'    => array( __( 'Fail', 'fckmaleware' ), 'bad' ),
			'info'    => array( __( 'Info', 'fckmaleware' ), 'neutral' ),
			'unknown' => array( __( 'Unknown', 'fckmaleware' ), 'neutral' ),
		);
		list( $label, $tone ) = $map[ $state ] ?? $map['unknown'];
		return self::status( $label, $tone );
	}

	/** Opening tag of a POST form to the FCK Malware action handler. */
	public static function form( string $command, array $hidden = array(), string $class = '', string $id = '' ): void {
		echo '<form method="post" action="' . esc_url( self::post_url() ) . '" class="' . esc_attr( $class ) . '"' . ( '' !== $id ? ' id="' . esc_attr( $id ) . '"' : '' ) . '>';
		wp_nonce_field( 'fckmw_' . $command );
		echo '<input type="hidden" name="action" value="fckmw">';
		echo '<input type="hidden" name="fckmw_command" value="' . esc_attr( $command ) . '">';
		foreach ( $hidden as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( (string) $value ) . '">';
		}
	}

	/**
	 * A one-button form. A non-empty $confirm opens a confirmation dialog
	 * first; buttons with the button-link-delete class get a destructive dialog.
	 */
	public static function action_button( string $command, string $label, array $hidden = array(), string $class = 'button', string $confirm = '' ): void {
		self::form( $command, $hidden, 'fckmw-inline' );
		printf(
			'<button type="submit" class="%1$s"%2$s>%3$s</button></form>',
			esc_attr( $class ),
			'' !== $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '" data-confirm-label="' . esc_attr( $label ) . '"' : '',
			esc_html( $label )
		);
	}

	/** Settings checkbox; the field name is registered so an unticked box saves as false. */
	public static function toggle( string $key, bool $value, string $label, string $help = '' ): void {
		printf(
			'<div class="fckmw-field fckmw-field-toggle"><input type="hidden" name="fckmw_bools[]" value="%1$s"><label class="fckmw-switch" for="fckmw-%1$s"><input type="checkbox" role="switch" id="fckmw-%1$s" name="fckmw[%1$s]" value="1"%2$s%5$s><span class="fckmw-switch-track" aria-hidden="true"></span><span class="fckmw-switch-label">%3$s</span></label>%4$s</div>',
			esc_attr( $key ),
			checked( $value, true, false ),
			esc_html( $label ),
			'' !== $help ? '<p class="description" id="fckmw-' . esc_attr( $key ) . '-help">' . esc_html( $help ) . '</p>' : '',
			'' !== $help ? ' aria-describedby="fckmw-' . esc_attr( $key ) . '-help"' : ''
		);
	}

	public static function select( string $key, string $value, array $options, string $label, string $help = '' ): void {
		echo '<div class="fckmw-field"><label for="fckmw-' . esc_attr( $key ) . '">' . esc_html( $label ) . '</label> <select id="fckmw-' . esc_attr( $key ) . '" name="fckmw[' . esc_attr( $key ) . ']"' . ( '' !== $help ? ' aria-describedby="fckmw-' . esc_attr( $key ) . '-help"' : '' ) . '>';
		foreach ( $options as $option => $text ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( (string) $option ), selected( $value, (string) $option, false ), esc_html( $text ) );
		}
		echo '</select>' . ( '' !== $help ? '<p class="description" id="fckmw-' . esc_attr( $key ) . '-help">' . esc_html( $help ) . '</p>' : '' ) . '</div>';
	}

	public static function input( string $key, string $value, string $label, string $type = 'text', string $help = '', array $attrs = array() ): void {
		$extra = '';
		foreach ( $attrs as $name => $attr ) {
			$extra .= ' ' . esc_attr( $name ) . '="' . esc_attr( (string) $attr ) . '"';
		}
		printf(
			'<div class="fckmw-field"><label for="fckmw-%1$s">%2$s</label> <input id="fckmw-%1$s" type="%3$s" name="fckmw[%1$s]" value="%4$s"%5$s%7$s>%6$s</div>',
			esc_attr( $key ),
			esc_html( $label ),
			esc_attr( $type ),
			esc_attr( $value ),
			$extra, // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above.
			'' !== $help ? '<p class="description" id="fckmw-' . esc_attr( $key ) . '-help">' . esc_html( $help ) . '</p>' : '',
			'' !== $help ? ' aria-describedby="fckmw-' . esc_attr( $key ) . '-help"' : ''
		);
	}

	public static function textarea( string $key, string $value, string $label, string $help = '', int $rows = 4 ): void {
		printf(
			'<div class="fckmw-field fckmw-field-block"><label for="fckmw-%1$s">%2$s</label><textarea id="fckmw-%1$s" name="fckmw[%1$s]" rows="%4$d" class="large-text code"%6$s>%3$s</textarea>%5$s</div>',
			esc_attr( $key ),
			esc_html( $label ),
			esc_textarea( $value ),
			(int) $rows,
			'' !== $help ? '<p class="description" id="fckmw-' . esc_attr( $key ) . '-help">' . esc_html( $help ) . '</p>' : '',
			'' !== $help ? ' aria-describedby="fckmw-' . esc_attr( $key ) . '-help"' : ''
		);
	}

	/** Start of a settings form that saves through the "settings" command. */
	public static function settings_form( string $return, string $anchor = '' ): void {
		self::form( 'settings', array( 'return' => $return, 'anchor' => $anchor ), 'fckmw-settings' );
	}

	public static function submit( string $label, string $class = 'button button-primary' ): void {
		echo '<div class="fckmw-form-footer"><button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></div>';
	}

	public static function pagination( int $total, int $per_page, int $current ): void {
		$pages = (int) ceil( $total / $per_page );
		if ( $pages < 2 ) {
			return;
		}
		echo '<div class="tablenav fckmw-pagination"><div class="tablenav-pages"><span class="displaying-num">' . esc_html( sprintf( /* translators: %s: count */ _n( '%s item', '%s items', $total, 'fckmaleware' ), number_format_i18n( $total ) ) ) . '</span> ';
		echo paginate_links( // phpcs:ignore WordPress.Security.EscapeOutput
			array(
				'base'    => add_query_arg( 'paged', '%#%' ),
				'format'  => '',
				'current' => $current,
				'total'   => $pages,
			)
		);
		echo '</div></div>';
	}

	public static function ago( int $timestamp ): string {
		if ( $timestamp <= 0 ) {
			return __( 'never', 'fckmaleware' );
		}
		/* translators: %s: human time difference */
		return $timestamp > time() ? sprintf( __( 'in %s', 'fckmaleware' ), human_time_diff( $timestamp ) ) : sprintf( __( '%s ago', 'fckmaleware' ), human_time_diff( $timestamp ) );
	}

	public static function datetime( int $timestamp ): string {
		return $timestamp > 0 ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ) : '—';
	}

	/** "<time> (in 3 hours)" with the exact date in a tooltip. */
	public static function when( int $timestamp ): string {
		if ( $timestamp <= 0 ) {
			return esc_html__( 'never', 'fckmaleware' );
		}
		return '<time datetime="' . esc_attr( gmdate( 'c', $timestamp ) ) . '" title="' . esc_attr( self::datetime( $timestamp ) ) . '">' . esc_html( self::ago( $timestamp ) ) . '</time>';
	}

	public static function can(): bool {
		return current_user_can( Plugin::capability() );
	}
}
