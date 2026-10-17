<?php
/**
 * Webhooks & Updates: signed webhook delivery, plugin updates from GitHub
 * and the WP-CLI reference.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\ActivityLog;
use Fckmaleware\Admin\Ui;
use Fckmaleware\Notifier;
use Fckmaleware\Settings;
use Fckmaleware\Updater;

final class Connections extends Page {

	public function render( string $title ): void {
		$settings = Settings::all();

		Ui::header( $title, __( 'Alert delivery to other systems, plugin updates and the command-line interface.', 'fckmaleware' ) );

		echo '<div class="fckmw-grid fckmw-grid-2">';
		Ui::card_start( __( 'Webhook', 'fckmaleware' ), '', __( 'Sends alerts as JSON to Slack-compatible or custom receivers. Each request carries an X-FCKMW-Signature header: the HMAC-SHA256 of the body with the secret below. Only public addresses are allowed.', 'fckmaleware' ) );
		Ui::settings_form( 'connections' );
		Ui::input( 'webhook_url', (string) $settings['webhook_url'], __( 'Webhook URL', 'fckmaleware' ), 'url', '', array( 'class' => 'regular-text', 'placeholder' => 'https://' ) );
		Ui::submit( __( 'Save', 'fckmaleware' ), 'button' );
		echo '</form>';
		if ( '' !== $settings['webhook_url'] ) {
			echo '<details><summary>' . esc_html__( 'Show signing secret', 'fckmaleware' ) . '</summary><p><code class="fckmw-secret">' . esc_html( Notifier::webhook_secret() ) . '</code></p></details>';
			echo '<div class="fckmw-actions">';
			Ui::action_button( 'notify_test', __( 'Send test', 'fckmaleware' ), array( 'return' => 'connections' ) );
			Ui::action_button( 'webhook_secret', __( 'Create new secret', 'fckmaleware' ), array( 'return' => 'connections' ), 'button', __( 'The current secret stops working immediately. Continue?', 'fckmaleware' ) );
			echo '</div>';
		}
		$log = ActivityLog::query( array( 'type' => 'notify.' ), 1, 5 )['rows'];
		if ( $log ) {
			echo '<h3>' . esc_html__( 'Recent deliveries', 'fckmaleware' ) . '</h3><ul class="fckmw-events">';
			foreach ( $log as $row ) {
				list( $icon, $tone ) = Overview::event_style( (string) $row['type'], (string) $row['severity'] );
				printf( '<li><span class="fckmw-event-icon fckmw-tone-%1$s"><span class="dashicons dashicons-%2$s" aria-hidden="true"></span></span><span class="fckmw-event-text">%3$s</span><span class="fckmw-event-time">%4$s</span></li>', esc_attr( $tone ), esc_attr( $icon ), esc_html( (string) $row['message'] ), Ui::when( (int) $row['created_at'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput
			}
			echo '</ul>';
		}
		Ui::card_end();

		Ui::card_start( __( 'Plugin updates', 'fckmaleware' ) );
		/* translators: %s: repository */
		echo '<p>' . esc_html( sprintf( __( 'New versions come from the GitHub repository %s and appear in Dashboard → Updates like any other plugin.', 'fckmaleware' ), Updater::REPOSITORY ) ) . '</p>';
		$cached  = get_site_transient( 'fckmw_github_release' );
		$release = is_array( $cached ) ? $cached['release'] : null;
		$rows    = array( array( __( 'Installed', 'fckmaleware' ), esc_html( FCKMW_VERSION ) ) );
		if ( $release ) {
			$rows[] = array( __( 'Latest available', 'fckmaleware' ), esc_html( $release['version'] ) . ' · <a href="' . esc_url( $release['url'] ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Release notes', 'fckmaleware' ) . '</a>' );
		} else {
			$rows[] = array( __( 'Latest available', 'fckmaleware' ), esc_html( is_array( $cached ) ? __( 'No newer version found at the last check.', 'fckmaleware' ) : __( 'Not checked recently.', 'fckmaleware' ) ) );
		}
		Ui::kv( $rows );
		echo '<p><a class="button" href="' . esc_url( is_multisite() ? network_admin_url( 'update-core.php?force-check=1' ) : admin_url( 'update-core.php?force-check=1' ) ) . '">' . esc_html__( 'Check for updates', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();
		echo '</div>';

		Ui::card_start( 'WP-CLI', '', __( 'Everything on these screens is also available from the command line:', 'fckmaleware' ) );
		echo '<pre class="fckmw-code">';
		echo esc_html(
			implode(
				"\n",
				array(
					'wp fckmaleware scan --mode=standard|quick|deep|core|plugins|uploads|recent|custom',
					'wp fckmaleware findings --format=table',
					'wp fckmaleware quarantine <id>',
					'wp fckmaleware restore <key>',
					'wp fckmaleware db-scan',
					'wp fckmaleware persistence',
					'wp fckmaleware signature-updates status',
					'wp fckmaleware hardening status',
					'wp fckmaleware imunify status|sync|scan',
				)
			)
		);
		echo '</pre>';
		Ui::card_end();
		Ui::footer();
	}
}
