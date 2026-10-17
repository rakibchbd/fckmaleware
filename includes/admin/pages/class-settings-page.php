<?php
/**
 * Settings: detection, notifications, updates, retention and the optional
 * external AI provider. Schedule, real-time and integration settings live on
 * their own screens.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Admin\Ui;
use Fckmaleware\Ai\AnthropicProvider;
use Fckmaleware\Paths;
use Fckmaleware\Settings;

final class SettingsPage extends Page {

	public function render( string $title ): void {
		$s = Settings::all();

		Ui::header( $title );

		Ui::settings_form( 'settings' );

		Ui::card_start( __( 'Detection', 'fckmaleware' ) );
		Ui::toggle( 'core_integrity', $s['core_integrity'], __( 'Verify WordPress core files', 'fckmaleware' ), __( 'Compares core files with the official checksums from api.wordpress.org.', 'fckmaleware' ) );
		Ui::toggle( 'plugin_integrity', $s['plugin_integrity'], __( 'Verify wordpress.org plugins', 'fckmaleware' ), __( 'Compares plugin files with checksums from downloads.wordpress.org. Plugins and themes from elsewhere get a local baseline on the first standard scan instead.', 'fckmaleware' ) );
		Ui::toggle( 'heuristics', $s['heuristics'], __( 'Heuristic analysis', 'fckmaleware' ), __( 'Finds unknown malware by what the code does. Recommended.', 'fckmaleware' ) );
		Ui::input( 'heuristic_threshold', (string) $s['heuristic_threshold'], __( 'Heuristic threshold (30-95)', 'fckmaleware' ), 'number', __( 'Lower finds more but may flag unusual legitimate code; 60 found no false positives in 40,000 clean WordPress files.', 'fckmaleware' ), array( 'min' => 30, 'max' => 95, 'class' => 'small-text' ) );
		Ui::toggle( 'scan_images', $s['scan_images'], __( 'Check image files in standard scans', 'fckmaleware' ), __( 'Finds PHP hidden in images. Deep scans always do this.', 'fckmaleware' ) );
		Ui::card_end();

		Ui::card_start( __( 'Notifications', 'fckmaleware' ) );
		Ui::toggle( 'email_alerts', $s['email_alerts'], __( 'E-mail alerts', 'fckmaleware' ) );
		Ui::input( 'alert_email', (string) $s['alert_email'], __( 'Send to', 'fckmaleware' ), 'email', __( 'Empty uses the site administrator e-mail.', 'fckmaleware' ), array( 'class' => 'regular-text', 'placeholder' => (string) get_site_option( 'admin_email' ) ) );
		Ui::select( 'notify_min_severity', $s['notify_min_severity'], array( 'critical' => __( 'Critical only', 'fckmaleware' ), 'high' => __( 'High and critical', 'fckmaleware' ), 'medium' => __( 'Medium and above', 'fckmaleware' ), 'low' => __( 'Everything', 'fckmaleware' ) ), __( 'Alert on findings of', 'fckmaleware' ) );
		Ui::input( 'notify_cooldown_hours', (string) $s['notify_cooldown_hours'], __( 'Repeat the same alert after (hours)', 'fckmaleware' ), 'number', __( 'Alerts arriving within two minutes are grouped into one message.', 'fckmaleware' ), array( 'min' => 1, 'max' => 168, 'class' => 'small-text' ) );
		Ui::toggle( 'notify_scan_complete', $s['notify_scan_complete'], __( 'Send a summary after each scheduled scan', 'fckmaleware' ) );
		Ui::toggle( 'dashboard_notices', $s['dashboard_notices'], __( 'Show an admin notice while high or critical findings are open, or after a critical event', 'fckmaleware' ) );
		echo '<p class="description"><a href="' . esc_url( Ui::url( 'integrations' ) ) . '">' . esc_html__( 'Webhook settings are under Integrations.', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( __( 'Updates and retention', 'fckmaleware' ) );
		Ui::toggle( 'signature_updates', $s['signature_updates'], __( 'Download signed signature updates', 'fckmaleware' ), __( 'Checks twice daily. Only databases signed with a key built into the plugin are accepted.', 'fckmaleware' ) );
		Ui::input( 'quarantine_retention', (string) $s['quarantine_retention'], __( 'Delete quarantined files after (days)', 'fckmaleware' ), 'number', __( '0 keeps them until you delete them.', 'fckmaleware' ), array( 'min' => 0, 'max' => 3650, 'class' => 'small-text' ) );
		Ui::card_end();

		echo '<div id="ai"></div>';
		Ui::card_start( __( 'External AI review (optional)', 'fckmaleware' ) );
		echo '<p>' . esc_html__( 'Off by default. When enabled, an administrator can ask a model for a second opinion on a single finding; a redacted excerpt is sent to the provider you choose and the answer is stored with the finding. The model never changes anything.', 'fckmaleware' ) . '</p>';
		Ui::select( 'ai_provider', $s['ai_provider'], array( 'none' => __( 'Off', 'fckmaleware' ), 'anthropic' => 'Anthropic Claude', 'openai_compatible' => __( 'OpenAI-compatible endpoint', 'fckmaleware' ) ), __( 'Provider', 'fckmaleware' ), __( 'An OpenAI-compatible endpoint can be a self-hosted model (Ollama, LM Studio, vLLM) so no code leaves your infrastructure.', 'fckmaleware' ) );
		Ui::toggle( 'ai_consent', $s['ai_consent'], __( 'I agree that redacted excerpts of flagged code may be sent to this provider', 'fckmaleware' ) );
		Ui::input( 'ai_api_key', '', __( 'API key', 'fckmaleware' ), 'password', '' !== $s['ai_api_key'] ? __( 'A key is stored. Leave empty to keep it, enter - to remove it.', 'fckmaleware' ) : __( 'Required for Anthropic; optional for a local endpoint.', 'fckmaleware' ), array( 'class' => 'regular-text', 'autocomplete' => 'new-password' ) );
		/* translators: %s: default model */
		Ui::input( 'ai_model', (string) $s['ai_model'], __( 'Model', 'fckmaleware' ), 'text', sprintf( __( 'Empty uses %s for Anthropic. Required for an OpenAI-compatible endpoint.', 'fckmaleware' ), AnthropicProvider::DEFAULT_MODEL ), array( 'class' => 'regular-text' ) );
		Ui::input( 'ai_endpoint', (string) $s['ai_endpoint'], __( 'Endpoint URL (OpenAI-compatible only)', 'fckmaleware' ), 'url', __( 'The chat completions URL, e.g. http://127.0.0.1:11434/v1/chat/completions', 'fckmaleware' ), array( 'class' => 'regular-text' ) );
		Ui::input( 'ai_max_chars', (string) $s['ai_max_chars'], __( 'Maximum excerpt length (characters)', 'fckmaleware' ), 'number', '', array( 'min' => 500, 'max' => 20000, 'class' => 'small-text' ) );
		Ui::input( 'ai_daily_limit', (string) $s['ai_daily_limit'], __( 'Maximum reviews per day', 'fckmaleware' ), 'number', '', array( 'min' => 1, 'max' => 1000, 'class' => 'small-text' ) );
		Ui::card_end();

		submit_button( __( 'Save settings', 'fckmaleware' ) );
		echo '</form>';

		Ui::card_start( __( 'Storage and removal', 'fckmaleware' ) );
		/* translators: %s: directory */
		echo '<p>' . esc_html( sprintf( __( 'Private data folder: %s (randomly named, protected by deny rules).', 'fckmaleware' ), (string) Paths::relative( Paths::data_dir() ) ) ) . '</p>';
		echo '<p>' . esc_html__( 'Deleting the plugin from the Plugins screen removes all of its data: findings, activity log, settings, baselines, downloaded signatures and every quarantined file. Restore or download anything you need first. Deactivating keeps everything.', 'fckmaleware' ) . '</p>';
		Ui::card_end();

		Ui::footer();
	}
}
