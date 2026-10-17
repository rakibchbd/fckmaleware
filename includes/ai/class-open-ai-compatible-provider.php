<?php
/**
 * Provider for any OpenAI-compatible chat-completions endpoint, including
 * free local model servers (Ollama: http://localhost:11434/v1, LM Studio,
 * llama.cpp server). This is what keeps external review possible without a
 * paid API.
 *
 * The endpoint is configured by a network administrator, so local addresses
 * are allowed here (unlike webhooks).
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Ai;

final class OpenAiCompatibleProvider implements Provider {

	/** @var string Base URL ending in /v1 (or equivalent). */
	private $endpoint;

	/** @var string */
	private $api_key;

	/** @var string */
	private $model;

	public function __construct( string $endpoint, string $api_key, string $model ) {
		$this->endpoint = untrailingslashit( $endpoint );
		$this->api_key  = $api_key;
		$this->model    = $model;
	}

	public function id(): string {
		return 'openai_compatible';
	}

	public function review( string $system, string $prompt, array $schema ) {
		if ( '' === $this->endpoint || '' === $this->model ) {
			return new \WP_Error( 'fckmw_ai_config', __( 'Set the endpoint URL and model name for the OpenAI-compatible provider.', 'fckmaleware' ) );
		}
		$headers = array( 'Content-Type' => 'application/json' );
		if ( '' !== $this->api_key ) {
			$headers['Authorization'] = 'Bearer ' . $this->api_key;
		}
		$response = wp_remote_post(
			$this->endpoint . '/chat/completions',
			array(
				'timeout' => 120,
				'headers' => $headers,
				'body'    => (string) wp_json_encode(
					array(
						'model'           => $this->model,
						'temperature'     => 0,
						'response_format' => array( 'type' => 'json_object' ),
						'messages'        => array(
							array( 'role' => 'system', 'content' => $system . "\n\nAnswer with one JSON object matching this JSON schema:\n" . wp_json_encode( $schema ) ),
							array( 'role' => 'user', 'content' => $prompt ),
						),
					)
				),
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( 200 !== $code ) {
			return new \WP_Error( 'fckmw_ai_http', sprintf( /* translators: 1: status, 2: message */ __( 'AI endpoint error %1$d: %2$s', 'fckmaleware' ), $code, (string) ( $data['error']['message'] ?? '' ) ) );
		}
		$text   = (string) ( $data['choices'][0]['message']['content'] ?? '' );
		$result = json_decode( $text, true );
		if ( ! is_array( $result ) && preg_match( '/\{.*\}/s', $text, $m ) ) {
			$result = json_decode( $m[0], true ); // Some local models wrap JSON in prose.
		}
		if ( ! is_array( $result ) ) {
			return new \WP_Error( 'fckmw_ai_format', __( 'The model did not return valid JSON.', 'fckmaleware' ) );
		}
		return array(
			'result'        => $result,
			'model'         => (string) ( $data['model'] ?? $this->model ),
			'input_tokens'  => (int) ( $data['usage']['prompt_tokens'] ?? 0 ),
			'output_tokens' => (int) ( $data['usage']['completion_tokens'] ?? 0 ),
			'cost_usd'      => null,
		);
	}
}
