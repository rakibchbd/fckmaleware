<?php
/**
 * Settings: every option in one place, grouped (general, scanning,
 * automatic protection, quarantine, notifications, integrations,
 * performance, privacy, advanced), with import, export and reset.
 * Essential controls come first; advanced ones are collapsed.
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
		$s      = Settings::all();
		$groups = array(
			'general'       => __( 'General', 'fckmaleware' ),
			'scanning'      => __( 'Scanning', 'fckmaleware' ),
			'protection'    => __( 'Automatic protection', 'fckmaleware' ),
			'quarantine'    => __( 'Quarantine', 'fckmaleware' ),
			'notifications' => __( 'Notifications', 'fckmaleware' ),
			'integrations'  => __( 'Integrations', 'fckmaleware' ),
			'performance'   => __( 'Performance', 'fckmaleware' ),
			'ai'            => __( 'Privacy & AI', 'fckmaleware' ),
			'advanced'      => __( 'Advanced', 'fckmaleware' ),
		);

		Ui::header( $title, __( 'Sensible defaults are already in place. Every value is validated when saved.', 'fckmaleware' ) );

		echo '<div class="fckmw-settings-layout"><nav class="fckmw-settings-nav fckmw-card" aria-label="' . esc_attr__( 'Settings sections', 'fckmaleware' ) . '"><ul>';
		foreach ( $groups as $id => $label ) {
			echo '<li><a href="#' . esc_attr( $id ) . '">' . esc_html( $label ) . '</a></li>';
		}
		echo '</ul></nav><div>';

		Ui::settings_form( 'settings' );

		Ui::card_start( $groups['general'], '', '', 'general' );
		Ui::select( 'schedule', $s['schedule'], array( 'off' => __( 'Off', 'fckmaleware' ), 'hourly' => __( 'Hourly', 'fckmaleware' ), 'twicedaily' => __( 'Twice daily', 'fckmaleware' ), 'daily' => __( 'Daily', 'fckmaleware' ), 'weekly' => __( 'Weekly', 'fckmaleware' ) ), __( 'Automatic file scans', 'fckmaleware' ), __( 'More options (time of day, integrity check, uploads check) under Scan & Threats → Schedule.', 'fckmaleware' ) );
		Ui::toggle( 'signature_updates', $s['signature_updates'], __( 'Download signed signature updates', 'fckmaleware' ), __( 'Checks twice daily. Only databases signed with a key built into the plugin are accepted.', 'fckmaleware' ) );
		Ui::toggle( 'dashboard_notices', $s['dashboard_notices'], __( 'Show an admin notice while high or critical findings are open', 'fckmaleware' ) );
		Ui::card_end();

		Ui::card_start( $groups['scanning'], '', '', 'scanning' );
		Ui::toggle( 'core_integrity', $s['core_integrity'], __( 'Verify WordPress core files', 'fckmaleware' ), __( 'Compares core files with the official checksums from api.wordpress.org.', 'fckmaleware' ) );
		Ui::toggle( 'plugin_integrity', $s['plugin_integrity'], __( 'Verify wordpress.org plugins', 'fckmaleware' ), __( 'Compares plugin files with checksums from downloads.wordpress.org. Plugins and themes from elsewhere get a local baseline on the first full scan instead.', 'fckmaleware' ) );
		Ui::toggle( 'heuristics', $s['heuristics'], __( 'Heuristic analysis', 'fckmaleware' ), __( 'Finds unknown malware by what the code does. Recommended.', 'fckmaleware' ) );
		Ui::toggle( 'scan_images', $s['scan_images'], __( 'Check image files in full scans', 'fckmaleware' ), __( 'Finds PHP hidden in images. Deep and uploads scans always do this.', 'fckmaleware' ) );
		Ui::disclosure_start( __( 'Advanced scanning options', 'fckmaleware' ) );
		Ui::input( 'heuristic_threshold', (string) $s['heuristic_threshold'], __( 'Heuristic threshold (30-95)', 'fckmaleware' ), 'number', __( 'Lower finds more but may flag unusual legitimate code; 60 found no false positives in 40,000 clean WordPress files.', 'fckmaleware' ), array( 'min' => 30, 'max' => 95, 'class' => 'small-text' ) );
		Ui::textarea( 'scan_exclusions', (string) $s['scan_exclusions'], __( 'Excluded directories', 'fckmaleware' ), __( 'One directory per line, relative to the WordPress root (for example wp-content/cache). Warning: malware placed in an excluded directory is never found. Exclude only large folders you trust, such as caches and backups that are not web-accessible.', 'fckmaleware' ) );
		Ui::disclosure_end();
		Ui::card_end();

		Ui::card_start( $groups['protection'], '', __( 'The essentials. All prevention, detection and blocking options are on the Protection screen.', 'fckmaleware' ), 'protection' );
		Ui::toggle( 'realtime_uploads', $s['realtime_uploads'], __( 'Screen uploads and refuse malicious files', 'fckmaleware' ) );
		Ui::toggle( 'realtime_installs', $s['realtime_installs'], __( 'Check plugins and themes after install or update', 'fckmaleware' ) );
		Ui::toggle( 'monitor_users', $s['monitor_users'], __( 'Watch administrator accounts', 'fckmaleware' ) );
		Ui::toggle( 'monitor_options', $s['monitor_options'], __( 'Watch security-relevant options', 'fckmaleware' ) );
		echo '<p><a href="' . esc_url( Ui::url( 'realtime' ) ) . '">' . esc_html__( 'All protection options', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( $groups['quarantine'], '', '', 'quarantine' );
		Ui::toggle( 'auto_remove_verified', $s['auto_remove_verified'], __( 'Remove verified malware automatically, immediately', 'fckmaleware' ), __( 'Signature, exact-hash and server-scanner matches of 90% or more for files that are malicious as a whole. Never core or configuration files.', 'fckmaleware' ) );
		Ui::input( 'auto_remove_keep_days', (string) $s['auto_remove_keep_days'], __( 'Keep a recovery copy for (days)', 'fckmaleware' ), 'number', __( '0 deletes removed malware permanently at once.', 'fckmaleware' ), array( 'min' => 0, 'max' => 90, 'class' => 'small-text' ) );
		Ui::toggle( 'auto_quarantine', $s['auto_quarantine'], __( 'Also quarantine very-high-confidence heuristic detections in uploads', 'fckmaleware' ), __( 'Off by default.', 'fckmaleware' ) );
		Ui::input( 'bulk_min_confidence', (string) $s['bulk_min_confidence'], __( 'Bulk quarantine minimum confidence (%)', 'fckmaleware' ), 'number', '', array( 'min' => 50, 'max' => 100, 'class' => 'small-text' ) );
		Ui::input( 'quarantine_retention', (string) $s['quarantine_retention'], __( 'Delete quarantined copies after (days)', 'fckmaleware' ), 'number', __( '0 keeps them until you delete them. Expired copies are removed by the daily cleanup and logged.', 'fckmaleware' ), array( 'min' => 0, 'max' => 3650, 'class' => 'small-text' ) );
		Ui::card_end();

		Ui::card_start( $groups['notifications'], '', '', 'notifications' );
		Ui::toggle( 'email_alerts', $s['email_alerts'], __( 'E-mail alerts', 'fckmaleware' ) );
		Ui::input( 'alert_email', (string) $s['alert_email'], __( 'Send to', 'fckmaleware' ), 'email', __( 'Empty uses the site administrator e-mail.', 'fckmaleware' ), array( 'class' => 'regular-text', 'placeholder' => (string) get_site_option( 'admin_email' ) ) );
		Ui::select( 'notify_min_severity', $s['notify_min_severity'], array( 'critical' => __( 'Critical only', 'fckmaleware' ), 'high' => __( 'High and critical', 'fckmaleware' ), 'medium' => __( 'Medium and above', 'fckmaleware' ), 'low' => __( 'Everything', 'fckmaleware' ) ), __( 'Alert on findings of', 'fckmaleware' ) );
		Ui::input( 'notify_cooldown_hours', (string) $s['notify_cooldown_hours'], __( 'Repeat the same alert after (hours)', 'fckmaleware' ), 'number', __( 'Alerts arriving within two minutes are grouped into one message.', 'fckmaleware' ), array( 'min' => 1, 'max' => 168, 'class' => 'small-text' ) );
		Ui::toggle( 'notify_scan_complete', $s['notify_scan_complete'], __( 'Send a summary after each scheduled scan', 'fckmaleware' ) );
		echo '<p class="description"><a href="' . esc_url( Ui::url( 'connections' ) ) . '">' . esc_html__( 'Webhook settings', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( $groups['integrations'], '', '', 'integrations' );
		echo '<p>' . esc_html__( 'Imunify360, ImunifyAV and cPGuard detection, connection tests and the remediation policy when several scanners run are configured in the integration center.', 'fckmaleware' ) . '</p><p><a class="button" href="' . esc_url( Ui::url( 'integrations' ) ) . '">' . esc_html__( 'Open integrations', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::card_start( $groups['performance'], '', '', 'performance' );
		Ui::input( 'throttle_ms', (string) $s['throttle_ms'], __( 'Pause between files (ms)', 'fckmaleware' ), 'number', __( 'Use 5-50 on busy shared hosting to reduce load; 0 for the fastest scans.', 'fckmaleware' ), array( 'min' => 0, 'max' => 500, 'class' => 'small-text' ) );
		Ui::input( 'max_file_size_mb', (string) $s['max_file_size_mb'], __( 'Skip files larger than (MB)', 'fckmaleware' ), 'number', __( 'Larger files are listed as not checked in the scan result, never silently ignored.', 'fckmaleware' ), array( 'min' => 1, 'max' => 64, 'class' => 'small-text' ) );
		Ui::card_end();

		Ui::card_start( $groups['ai'], '', __( 'External AI review is off by default and never required. When enabled, an administrator can ask a model for a second opinion on a single finding: a redacted excerpt (site paths, domain, credentials, keys and e-mail addresses removed) is sent to the provider you choose and the answer is stored with the finding. Nothing is sent automatically and the model never changes anything.', 'fckmaleware' ), 'ai' );
		Ui::select( 'ai_provider', $s['ai_provider'], array( 'none' => __( 'Off', 'fckmaleware' ), 'anthropic' => 'Anthropic Claude', 'openai_compatible' => __( 'OpenAI-compatible endpoint', 'fckmaleware' ) ), __( 'Provider', 'fckmaleware' ), __( 'An OpenAI-compatible endpoint can be a self-hosted model (Ollama, LM Studio, vLLM) so no code leaves your infrastructure.', 'fckmaleware' ) );
		Ui::toggle( 'ai_consent', $s['ai_consent'], __( 'I agree that redacted excerpts of flagged code may be sent to this provider', 'fckmaleware' ) );
		$key_help = defined( 'FCKMW_AI_API_KEY' ) && '' !== (string) FCKMW_AI_API_KEY
			? __( 'The key is set with FCKMW_AI_API_KEY in wp-config.php and cannot be changed here.', 'fckmaleware' )
			: ( '' !== $s['ai_api_key'] ? __( 'A key is stored (encrypted). Leave empty to keep it, enter - to remove it. You can also define FCKMW_AI_API_KEY in wp-config.php.', 'fckmaleware' ) : __( 'Required for Anthropic; optional for a local endpoint. Stored encrypted with your site\'s salts.', 'fckmaleware' ) );
		Ui::input( 'ai_api_key', '', __( 'API key', 'fckmaleware' ), 'password', $key_help, array( 'class' => 'regular-text', 'autocomplete' => 'new-password' ) );
		Ui::disclosure_start( __( 'Model, endpoint and limits', 'fckmaleware' ) );
		/* translators: %s: default model */
		Ui::input( 'ai_model', (string) $s['ai_model'], __( 'Model', 'fckmaleware' ), 'text', sprintf( __( 'Empty uses %s for Anthropic. Required for an OpenAI-compatible endpoint.', 'fckmaleware' ), AnthropicProvider::DEFAULT_MODEL ), array( 'class' => 'regular-text' ) );
		Ui::input( 'ai_endpoint', (string) $s['ai_endpoint'], __( 'Endpoint URL (OpenAI-compatible only)', 'fckmaleware' ), 'url', __( 'The chat completions URL, e.g. http://127.0.0.1:11434/v1/chat/completions', 'fckmaleware' ), array( 'class' => 'regular-text' ) );
		Ui::input( 'ai_max_chars', (string) $s['ai_max_chars'], __( 'Maximum excerpt length (characters)', 'fckmaleware' ), 'number', '', array( 'min' => 500, 'max' => 20000, 'class' => 'small-text' ) );
		Ui::input( 'ai_daily_limit', (string) $s['ai_daily_limit'], __( 'Maximum reviews per day', 'fckmaleware' ), 'number', '', array( 'min' => 1, 'max' => 1000, 'class' => 'small-text' ) );
		Ui::disclosure_end();
		Ui::card_end();

		Ui::card_start( $groups['advanced'], '', '', 'advanced' );
		Ui::input( 'log_retention_days', (string) $s['log_retention_days'], __( 'Keep activity log entries for (days)', 'fckmaleware' ), 'number', __( 'At most 20,000 entries are kept regardless.', 'fckmaleware' ), array( 'min' => 30, 'max' => 365, 'class' => 'small-text' ) );
		Ui::toggle( 'keep_data_on_uninstall', $s['keep_data_on_uninstall'], __( 'Keep data when the plugin is deleted', 'fckmaleware' ), __( 'Off: deleting the plugin removes findings, logs, settings, baselines, downloaded signatures and every quarantined file. On: only scheduled tasks are removed, so a reinstall continues where you left off.', 'fckmaleware' ) );
		/* translators: %s: directory */
		echo '<p class="description">' . esc_html( sprintf( __( 'Private data folder: %s', 'fckmaleware' ), (string) ( Paths::relative( Paths::data_dir() ) ?? Paths::data_dir() ) ) ) . ' · <a href="' . esc_url( Ui::url( 'diagnostics' ) ) . '">' . esc_html__( 'Diagnostics', 'fckmaleware' ) . '</a></p>';
		Ui::card_end();

		Ui::submit( __( 'Save settings', 'fckmaleware' ) );
		echo '</form>';

		Ui::card_start( __( 'Import, export and reset', 'fckmaleware' ) );
		echo '<p class="description">' . esc_html__( 'Exports never contain API keys. Imported files are validated value by value, exactly like this form.', 'fckmaleware' ) . '</p><div class="fckmw-actions">';
		Ui::form( 'settings_export', array(), 'fckmw-inline' );
		echo '<button class="button"><span class="dashicons dashicons-download" aria-hidden="true"></span>' . esc_html__( 'Export settings (JSON)', 'fckmaleware' ) . '</button></form>';
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( Ui::post_url() ) . '" class="fckmw-inline">';
		wp_nonce_field( 'fckmw_settings_import' );
		echo '<input type="hidden" name="action" value="fckmw"><input type="hidden" name="fckmw_command" value="settings_import"><input type="hidden" name="return" value="settings">';
		echo '<label class="screen-reader-text" for="fckmw-import">' . esc_html__( 'Settings file', 'fckmaleware' ) . '</label><input type="file" id="fckmw-import" name="fckmw_import" accept="application/json,.json" required> <button class="button">' . esc_html__( 'Import', 'fckmaleware' ) . '</button></form>';
		Ui::action_button( 'settings_reset', __( 'Reset to defaults', 'fckmaleware' ), array( 'return' => 'settings' ), 'button button-link-delete', __( 'Restore every setting to its default value? Stored API keys are kept. Hardening rules, findings and the quarantine are not affected.', 'fckmaleware' ) );
		echo '</div>';
		Ui::card_end();

		echo '</div></div>';
		Ui::footer();
	}
}
