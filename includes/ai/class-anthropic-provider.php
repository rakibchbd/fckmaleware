<?php
/**
 * Claude (Anthropic Messages API) provider.
 *
 * Uses the WordPress HTTP API rather than the PHP SDK: the plugin has to run
 * on shared hosting without Composer, and bundled HTTP libraries conflict
 * between WordPress plugins. The request follows the documented raw HTTP
 * shape of POST /v1/messages.
 *
 * - Structured output: output_config.format with a JSON schema, so the reply
 *   is parseable JSON.
 * - effort "low": a short classification does not need deep reasoning.
 * - Server-side refusal fallbacks ("default"): malware analysis can trip a
 *   safety classifier; the API then re-routes the request to a suitable model
 *   instead of stopping. A refusal that still happens is reported, not parsed.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Ai;

final class AnthropicProvider implements Provider {

	public const DEFAULT_MODEL = 'claude-opus-5-5';
	private const ENDPOINT     = 'https://api.anthropic.com/v1/messages';

	/** USD per million tokens [input, output], for cost visibility only. */
	private const PRICES = array(
		'claude-opus-5-5'   => array( 4.00, 20.00 ),
		'claude-sonnet-5-5' => array( 2.00, 10.00 ),
		'claude-haiku-5-5'  => array( 0.10, 0.50 ),
		'claude-fable-5-1'  => array( 10.00, 50.00 ),
	);

	/** @var string */
	private $api_key;

	/** @var string */
	private $model;

	public function __construct( string $api_key, string $model = '' ) {
		$this->api_key = $api_key;
		$this->model   = '' !== $model ? $model : self::DEFAULT_MODEL;
	}

	public function id(): string {
		return 'anthropic';
	}

	public function review( string $system, string $prompt, array $schema ) {
		if ( '' === $this->api_key ) {
			return new \WP_Error( 'fckmw_ai_key', __( 'No Anthropic API key is configured.', 'fckmaleware' ) );
		}
		$body = array(
			'model'         => $this->model,
			'max_tokens'    => 2000,
			'system'        => $system,
			'messages'      => array( array( 'role' => 'user', 'content' => $prompt ) ),
			'output_config' => array(
				'effort' => 'low',
				'format' => array( 'type' => 'json_schema', 'schema' => $schema ),
			),
			'fallbacks'     => 'default',
		);
		$response = wp_remote_post(
			self::ENDPOINT,
			array(
				'timeout' => 60,
				'headers' => array(
					'content-type'      => 'application/json',
					'x-api-key'         => $this->api_key,
					'anthropic-version' => '2023-06-01',
					'anthropic-beta'    => 'server-side-fallback-2026-07-01',
				),
				'body'    => (string) wp_json_encode( $body ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code ) {
			$type    = (string) ( $data['error']['type'] ?? 'http_error' );
			$message = (string) ( $data['error']['message'] ?? 'HTTP ' . $code );
			$hint    = in_array( $code, array( 429, 500, 502, 503, 504, 529 ), true ) ? __( ' (temporary; try again later)', 'fckmaleware' ) : '';
			/* translators: 1: error type, 2: message, 3: retry hint */
			return new \WP_Error( 'fckmw_ai_http', sprintf( __( 'Claude API error %1$s: %2$s%3$s', 'fckmaleware' ), $type, $message, $hint ) );
		}

		$stop = (string) ( $data['stop_reason'] ?? '' );
		if ( 'refusal' === $stop ) {
			$category = (string) ( $data['stop_details']['category'] ?? '' );
			return new \WP_Error( 'fckmw_ai_refusal', sprintf( /* translators: %s: category */ __( 'The model declined to review this sample (%s). The local verdict stands.', 'fckmaleware' ), '' !== $category ? $category : 'refusal' ) );
		}
		if ( 'max_tokens' === $stop ) {
			return new \WP_Error( 'fckmw_ai_truncated', __( 'The answer was cut off before it was complete.', 'fckmaleware' ) );
		}

		$text = '';
		foreach ( (array) ( $data['content'] ?? array() ) as $block ) {
			if ( 'text' === ( $block['type'] ?? '' ) ) {
				$text .= (string) $block['text'];
			}
		}
		$result = json_decode( $text, true );
		if ( ! is_array( $result ) ) {
			return new \WP_Error( 'fckmw_ai_format', __( 'The model did not return valid JSON.', 'fckmaleware' ) );
		}

		$model  = (string) ( $data['model'] ?? $this->model );
		$input  = (int) ( $data['usage']['input_tokens'] ?? 0 );
		$output = (int) ( $data['usage']['output_tokens'] ?? 0 );
		$price  = self::PRICES[ $model ] ?? null;
		return array(
			'result'        => $result,
			'model'         => $model,
			'input_tokens'  => $input,
			'output_tokens' => $output,
			'cost_usd'      => null === $price ? null : round( ( $input * $price[0] + $output * $price[1] ) / 1000000, 6 ),
		);
	}
}
