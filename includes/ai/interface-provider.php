<?php
/**
 * An external AI provider that reviews one sanitized finding.
 *
 * Providers return a structured verdict and usage information. They never
 * act on the site: the result is advisory and stored next to the finding.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Ai;

interface Provider {

	public function id(): string;

	/**
	 * @param string $system System instructions.
	 * @param string $prompt The sanitized case (untrusted code inside clearly marked delimiters).
	 * @param array  $schema JSON schema the answer must follow.
	 * @return array{result: array, model: string, input_tokens: int, output_tokens: int, cost_usd: float|null}|\WP_Error
	 */
	public function review( string $system, string $prompt, array $schema );
}
