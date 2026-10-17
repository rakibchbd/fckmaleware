<?php
/**
 * Small rendering helpers shared by the admin pages. Everything printed goes
 * through esc_html / esc_attr / esc_url here or at the call site.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin;

use Fckmaleware\Plugin;

final class Ui {

	public const SLUG = 'fckmaleware';

	public static function url( string $page = '', array $args = array() ): string {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => '' === $page ? self::SLUG : self::SLUG . '-' . $page ), $args ), $base );
	}

	public static function post_url(): string {
		return is_multisite() ? network_admin_url( 'edit.php?action=fckmw' ) : admin_url( 'admin-post.php' );
	}

	public static function header( string $title, string $intro = '' ): void {
		echo '<div class="wrap fckmw">';
		echo '<h1 class="fckmw-title"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span> ' . esc_html( $title ) . '</h1>';
		if ( '' !== $intro ) {
			echo '<p class="fckmw-intro">' . esc_html( $intro ) . '</p>';
		}
		self::notice();
	}

	public static function footer(): void {
		echo '</div>';
	}

	private static function notice(): void {
		$key    = 'fckmw_notice_' . get_current_user_id();
		$notice = get_site_transient( $key );
		if ( is_array( $notice ) ) {
			delete_site_transient( $key );
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $notice[0] ), esc_html( $notice[1] ) );
		}
	}

	public static function set_notice( string $type, string $message ): void {
		set_site_transient( 'fckmw_notice_' . get_current_user_id(), array( $type, $message ), MINUTE_IN_SECONDS );
	}

	public static function card_start( string $title = '', string $class = '' ): void {
		echo '<section class="fckmw-card ' . esc_attr( $class ) . '">';
		if ( '' !== $title ) {
			echo '<h2 class="fckmw-card-title">' . esc_html( $title ) . '</h2>';
		}
	}

	public static function card_end(): void {
		echo '</section>';
	}

	/** A number tile. $tone: neutral, good, warn, bad. */
	public static function stat( string $label, string $value, string $tone = 'neutral', string $sub = '', string $link = '' ): void {
		$inner = '<span class="fckmw-stat-value">' . esc_html( $value ) . '</span><span class="fckmw-stat-label">' . esc_html( $label ) . '</span>';
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

	public static function severity( string $severity ): string {
		$tones = array( 'critical' => 'critical', 'high' => 'bad', 'medium' => 'warn', 'low' => 'neutral' );
		return self::badge( ucfirst( $severity ), $tones[ $severity ] ?? 'neutral' );
	}

	public static function verdict( string $verdict, int $confidence ): string {
		return self::badge( sprintf( '%s · %d%%', $verdict, $confidence ), 'malicious' === $verdict ? 'bad' : 'warn' );
	}

	public static function state( string $state ): string {
		$map = array(
			'pass'    => array( __( 'Pass', 'fckmaleware' ), 'good' ),
			'warn'    => array( __( 'Warning', 'fckmaleware' ), 'warn' ),
			'fail'    => array( __( 'Fail', 'fckmaleware' ), 'bad' ),
			'info'    => array( __( 'Info', 'fckmaleware' ), 'neutral' ),
			'unknown' => array( __( 'Unknown', 'fckmaleware' ), 'neutral' ),
		);
		list( $label, $tone ) = $map[ $state ] ?? $map['unknown'];
		return self::badge( $label, $tone );
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

	/** A one-button form. */
	public static function action_button( string $command, string $label, array $hidden = array(), string $class = 'button', string $confirm = '' ): void {
		self::form( $command, $hidden, 'fckmw-inline' );
		printf(
			'<button type="submit" class="%1$s"%2$s>%3$s</button></form>',
			esc_attr( $class ),
			'' !== $confirm ? ' data-confirm="' . esc_attr( $confirm ) . '"' : '',
			esc_html( $label )
		);
	}

	/** Settings checkbox; the field name is registered so an unticked box saves as false. */
	public static function toggle( string $key, bool $value, string $label, string $help = '' ): void {
		printf(
			'<div class="fckmw-field"><input type="hidden" name="fckmw_bools[]" value="%1$s"><label class="fckmw-switch"><input type="checkbox" name="fckmw[%1$s]" value="1"%2$s> <span>%3$s</span></label>%4$s</div>',
			esc_attr( $key ),
			checked( $value, true, false ),
			esc_html( $label ),
			'' !== $help ? '<p class="description">' . esc_html( $help ) . '</p>' : ''
		);
	}

	public static function select( string $key, string $value, array $options, string $label, string $help = '' ): void {
		echo '<div class="fckmw-field"><label for="fckmw-' . esc_attr( $key ) . '">' . esc_html( $label ) . '</label> <select id="fckmw-' . esc_attr( $key ) . '" name="fckmw[' . esc_attr( $key ) . ']">';
		foreach ( $options as $option => $text ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( (string) $option ), selected( $value, (string) $option, false ), esc_html( $text ) );
		}
		echo '</select>' . ( '' !== $help ? '<p class="description">' . esc_html( $help ) . '</p>' : '' ) . '</div>';
	}

	public static function input( string $key, string $value, string $label, string $type = 'text', string $help = '', array $attrs = array() ): void {
		$extra = '';
		foreach ( $attrs as $name => $attr ) {
			$extra .= ' ' . esc_attr( $name ) . '="' . esc_attr( (string) $attr ) . '"';
		}
		printf(
			'<div class="fckmw-field"><label for="fckmw-%1$s">%2$s</label> <input id="fckmw-%1$s" type="%3$s" name="fckmw[%1$s]" value="%4$s"%5$s>%6$s</div>',
			esc_attr( $key ),
			esc_html( $label ),
			esc_attr( $type ),
			esc_attr( $value ),
			$extra, // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above.
			'' !== $help ? '<p class="description">' . esc_html( $help ) . '</p>' : ''
		);
	}

	/** Start of a settings form that saves through the "settings" command. */
	public static function settings_form( string $return ): void {
		self::form( 'settings', array( 'return' => $return ), 'fckmw-settings' );
	}

	public static function pagination( int $total, int $per_page, int $current ): void {
		$pages = (int) ceil( $total / $per_page );
		if ( $pages < 2 ) {
			return;
		}
		echo '<div class="tablenav"><div class="tablenav-pages">';
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

	public static function can(): bool {
		return current_user_can( Plugin::capability() );
	}
}
