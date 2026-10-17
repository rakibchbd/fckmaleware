<?php
/**
 * Built-in signature engine.
 *
 * Deliberately free of WordPress calls so it can be unit tested on its own.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Signatures {

	public const SEVERITIES = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
	);

	private const EXTENSION_TYPES = array(
		'php'   => 'php',
		'php3'  => 'php',
		'php4'  => 'php',
		'php5'  => 'php',
		'php7'  => 'php',
		'php8'  => 'php',
		'phtml' => 'php',
		'phar'  => 'php',
		'inc'   => 'php',
		'suspected' => 'php',
		'js'    => 'js',
		'mjs'   => 'js',
		'html'  => 'html',
		'htm'   => 'html',
		'svg'   => 'html',
		'ico'   => 'image',
	);

	private const OPTIONAL_IMAGE_TYPES = array( 'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp' );

	/** @var string */
	private $version;

	/** @var array<int, array<string, mixed>> */
	private $signatures = array();

	/** @var string[] IDs of signatures dropped because their pattern did not compile. */
	private $invalid = array();

	public static function from_file( string $path ): self {
		$raw = is_readable( $path ) ? file_get_contents( $path ) : false;
		if ( false === $raw ) {
			throw new \RuntimeException( "Cannot read signature file: {$path}" );
		}
		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) ) {
			throw new \RuntimeException( "Signature file is not valid JSON: {$path}" );
		}
		return new self( $data );
	}

	public function __construct( array $data ) {
		$this->version = (string) ( $data['version'] ?? '0' );

		foreach ( (array) ( $data['signatures'] ?? array() ) as $sig ) {
			if ( ! is_array( $sig ) || empty( $sig['id'] ) || empty( $sig['pattern'] ) ) {
				continue;
			}
			if ( false === @preg_match( $sig['pattern'], '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$this->invalid[] = (string) $sig['id'];
				continue;
			}
			$severity           = strtolower( (string) ( $sig['severity'] ?? 'medium' ) );
			$this->signatures[] = array(
				'id'          => (string) $sig['id'],
				'name'        => (string) ( $sig['name'] ?? $sig['id'] ),
				'severity'    => isset( self::SEVERITIES[ $severity ] ) ? $severity : 'medium',
				'targets'     => array_values( array_map( 'strval', (array) ( $sig['targets'] ?? array( 'any' ) ) ) ),
				'pattern'     => (string) $sig['pattern'],
				'description' => (string) ( $sig['description'] ?? '' ),
			);
		}
	}

	public function version(): string {
		return $this->version;
	}

	/** @return array<int, array<string, mixed>> */
	public function all(): array {
		return $this->signatures;
	}

	/** @return string[] */
	public function invalid(): array {
		return $this->invalid;
	}

	/**
	 * Map a file path to the signature target type, or null if it should not be scanned.
	 */
	public static function file_type( string $path, bool $scan_images = false ): ?string {
		$base = strtolower( basename( $path ) );
		if ( '.htaccess' === $base ) {
			return 'htaccess';
		}
		if ( '.user.ini' === $base || 'php.ini' === $base ) {
			return 'ini';
		}
		$ext = strtolower( pathinfo( $base, PATHINFO_EXTENSION ) );
		if ( isset( self::EXTENSION_TYPES[ $ext ] ) ) {
			return self::EXTENSION_TYPES[ $ext ];
		}
		if ( $scan_images && in_array( $ext, self::OPTIONAL_IMAGE_TYPES, true ) ) {
			return 'image';
		}
		return null;
	}

	/**
	 * Run every applicable signature against $content.
	 *
	 * @return array<int, array{signature: array<string, mixed>, line: int, excerpt: string}>
	 */
	public function match( string $content, string $type ): array {
		$matches = array();
		foreach ( $this->signatures as $sig ) {
			if ( ! in_array( $type, $sig['targets'], true ) && ! in_array( 'any', $sig['targets'], true ) ) {
				continue;
			}
			// A false return (e.g. backtrack limit) is treated as "no match" rather than an error.
			if ( 1 !== @preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				continue;
			}
			$offset    = (int) $m[0][1];
			$matches[] = array(
				'signature' => $sig,
				'line'      => substr_count( substr( $content, 0, $offset ), "\n" ) + 1,
				'excerpt'   => self::excerpt( $content, $offset, strlen( $m[0][0] ) ),
			);
		}
		return $matches;
	}

	/**
	 * A short, printable-ASCII window around a match for display in the admin.
	 */
	public static function excerpt( string $content, int $offset, int $length, int $context = 60 ): string {
		$start   = max( 0, $offset - $context );
		$snippet = substr( $content, $start, min( $length, 200 ) + 2 * $context );
		$snippet = trim( (string) preg_replace( '/[^\x20-\x7E]+/', ' ', $snippet ) );
		if ( $start > 0 ) {
			$snippet = '...' . $snippet;
		}
		if ( $offset + $length + $context < strlen( $content ) ) {
			$snippet .= '...';
		}
		return $snippet;
	}

	public static function severity_rank( string $severity ): int {
		return self::SEVERITIES[ $severity ] ?? 0;
	}
}
