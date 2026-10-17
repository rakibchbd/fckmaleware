<?php
/**
 * Removes secrets and personal data from code excerpts before they leave the
 * site for an external AI provider.
 *
 * Free of WordPress calls so it can be unit tested.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Ai;

final class Redactor {

	/** @var array<string, string> pattern => replacement */
	private const RULES = array(
		// wp-config.php style credentials, keys and salts.
		'~(define\s*\(\s*([\'"])(?:DB_(?:NAME|USER|PASSWORD|HOST)|[A-Z_]*(?:KEY|SALT|SECRET|TOKEN|PASS(?:WORD)?)[A-Z_]*)\2\s*,\s*)([\'"])(?:\\\\.|(?!\3).)*\3~' => '$1$3[REDACTED]$3',
		// Assignments to variables or array keys that look like secrets.
		'~((?:\$|[\'"])[A-Za-z0-9_]*(?:pass(?:word|wd)?|secret|api_?key|token|auth)[A-Za-z0-9_]*[\'"]?\s*(?:=>|=)\s*)([\'"])(?:\\\\.|(?!\2).){4,}\2~i' => '$1$2[REDACTED]$2',
		// Private keys.
		'~-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----~s' => '[REDACTED PRIVATE KEY]',
		// Well-known credential formats.
		'~\b(?:sk|pk|rk)[-_](?:live|test|ant|proj)?[-_]?[A-Za-z0-9_-]{16,}~' => '[REDACTED KEY]',
		'~\bAKIA[0-9A-Z]{16}\b~' => '[REDACTED AWS KEY]',
		'~\bgh[pousr]_[A-Za-z0-9]{30,}\b~' => '[REDACTED GITHUB TOKEN]',
		'~\bxox[abprs]-[A-Za-z0-9-]{10,}\b~' => '[REDACTED SLACK TOKEN]',
		'~\bAIza[0-9A-Za-z_-]{35}\b~' => '[REDACTED GOOGLE KEY]',
		'~\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}~' => '[REDACTED JWT]',
		// Credentials inside URLs.
		'~(https?://)[^/\s:@\'"]+:[^/\s@\'"]+@~i' => '$1[REDACTED]@',
		// Email addresses.
		'~\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b~' => '[REDACTED EMAIL]',
	);

	public static function redact( string $text ): string {
		foreach ( self::RULES as $pattern => $replacement ) {
			$result = preg_replace( $pattern, $replacement, $text );
			if ( null !== $result ) {
				$text = $result;
			}
		}
		return $text;
	}

	/** Replace the site's own paths, domain and table prefix with placeholders. */
	public static function anonymize( string $text, array $replacements ): string {
		foreach ( $replacements as $needle => $placeholder ) {
			if ( '' !== (string) $needle ) {
				$text = str_ireplace( (string) $needle, (string) $placeholder, $text );
			}
		}
		return $text;
	}
}
