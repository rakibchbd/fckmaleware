<?php
/**
 * Signature database: loading, validation and matching.
 *
 * Deliberately free of WordPress calls so it can be unit tested and reused by
 * the maintainer build tools. Signature content is data only: patterns are
 * fed to preg_match()/strpos() and nothing is ever evaluated as PHP.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class Signatures {

	public const SCHEMA = 2;

	public const SEVERITIES = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
	);

	public const TARGETS    = array( 'php', 'js', 'html', 'htaccess', 'ini', 'image', 'db', 'any' );
	public const TECHNIQUES = array( 'regex', 'bytes', 'hash' );

	/** Confidence at or above which a match is reported as "malicious" rather than "suspicious". */
	public const MALICIOUS_CONFIDENCE = 70;

	private const MAX_PATTERN_LENGTH = 4096;
	private const MAX_SIGNATURES     = 20000;
	private const MAX_HASHES         = 500000;

	private const EXTENSION_TYPES = array(
		'php'       => 'php',
		'php3'      => 'php',
		'php4'      => 'php',
		'php5'      => 'php',
		'php7'      => 'php',
		'php8'      => 'php',
		'phtml'     => 'php',
		'phar'      => 'php',
		'pht'       => 'php',
		'inc'       => 'php',
		'suspected' => 'php',
		'js'        => 'js',
		'mjs'       => 'js',
		'html'      => 'html',
		'htm'       => 'html',
		'svg'       => 'html',
		'ico'       => 'image',
	);

	private const OPTIONAL_IMAGE_TYPES = array( 'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp' );

	/** @var string */
	private $version;

	/** @var array<int, array<string, mixed>> Regex and byte signatures. */
	private $signatures = array();

	/** @var array<string, string> sha256 => signature id */
	private $hashes = array();

	/** @var array<string, array<string, mixed>> Hash signatures by id (metadata only). */
	private $hash_signatures = array();

	/** @var array<string, string> Signature id => reason it was rejected at load time. */
	private $invalid = array();

	/** @var array<string, int> Signature id => number of PCRE runtime failures during this request. */
	private $runtime_errors = array();

	public static function from_file( string $path ): self {
		$raw = is_readable( $path ) ? file_get_contents( $path ) : false; // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( false === $raw ) {
			throw new \RuntimeException( "Cannot read signature file: {$path}" ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- escaped where displayed.
		}
		$data = json_decode( $raw, true );
		if ( ! is_array( $data ) ) {
			throw new \RuntimeException( "Signature file is not valid JSON: {$path}" ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped -- escaped where displayed.
		}
		return new self( $data );
	}

	public function __construct( array $data ) {
		$this->version = (string) ( $data['version'] ?? '0' );

		foreach ( array_slice( (array) ( $data['signatures'] ?? array() ), 0, self::MAX_SIGNATURES ) as $raw ) {
			if ( ! is_array( $raw ) ) {
				continue;
			}
			$sig   = self::normalize( $raw );
			$error = self::check( $sig );
			if ( null !== $error ) {
				$this->invalid[ '' !== $sig['id'] ? $sig['id'] : '#' . count( $this->invalid ) ] = $error;
				continue;
			}
			if ( 'hash' === $sig['technique'] ) {
				$this->hash_signatures[ $sig['id'] ] = $sig;
				foreach ( $sig['sha256'] as $hash ) {
					if ( count( $this->hashes ) < self::MAX_HASHES ) {
						$this->hashes[ $hash ] = $sig['id'];
					}
				}
				continue;
			}
			$this->signatures[] = $sig;
		}
	}

	/** Fill defaults and coerce types; 0.x (schema 1) entries become regex signatures. */
	public static function normalize( array $raw ): array {
		$severity   = strtolower( (string) ( $raw['severity'] ?? 'medium' ) );
		$technique  = (string) ( $raw['technique'] ?? ( isset( $raw['sha256'] ) ? 'hash' : ( isset( $raw['bytes'] ) ? 'bytes' : 'regex' ) ) );
		$confidence = isset( $raw['confidence'] ) ? (int) $raw['confidence'] : ( 'critical' === $severity ? 90 : 75 );

		return array(
			'id'              => (string) ( $raw['id'] ?? '' ),
			'name'            => (string) ( $raw['name'] ?? ( $raw['id'] ?? '' ) ),
			'family'          => (string) ( $raw['family'] ?? '' ),
			'category'        => (string) ( $raw['category'] ?? '' ),
			'technique'       => $technique,
			'severity'        => isset( self::SEVERITIES[ $severity ] ) ? $severity : 'medium',
			'confidence'      => max( 0, min( 100, $confidence ) ),
			'targets'         => array_values( array_map( 'strval', (array) ( $raw['targets'] ?? array( 'any' ) ) ) ),
			'pattern'         => (string) ( $raw['pattern'] ?? '' ),
			'bytes'           => strtolower( (string) ( $raw['bytes'] ?? '' ) ),
			'nocase'          => ! empty( $raw['nocase'] ),
			'sha256'          => array_values( array_map( 'strtolower', array_map( 'strval', (array) ( $raw['sha256'] ?? array() ) ) ) ),
			'description'     => (string) ( $raw['description'] ?? '' ),
			'source'          => (string) ( $raw['source'] ?? '' ),
			'license'         => (string) ( $raw['license'] ?? '' ),
			'created'         => (string) ( $raw['created'] ?? '' ),
			'updated'         => (string) ( $raw['updated'] ?? '' ),
			'revision'        => (int) ( $raw['revision'] ?? 1 ),
			'false_positives' => array_values( (array) ( $raw['false_positives'] ?? array() ) ),
			'remediation'     => (string) ( $raw['remediation'] ?? 'review' ),
			'prefilter'       => array_values( array_slice( array_filter( array_map( 'strval', (array) ( $raw['prefilter'] ?? array() ) ), 'strlen' ), 0, 64 ) ),
		);
	}

	/**
	 * Literals of which at least one must occur (case-insensitive) for the
	 * pattern to be able to match. Derived only when every top-level branch
	 * of the pattern is a plain escaped literal or a series of
	 * "(?=[\s\S]*?literal)" lookaheads (optionally with word-boundary
	 * lookarounds), so the prefilter is a necessary condition and can never
	 * hide a match. Returns [] when that cannot be proven.
	 *
	 * @return string[] Lower-cased literals.
	 */
	public static function derive_prefilter( string $pattern ): array {
		if ( ! preg_match( '/^~(.*)~([a-zA-Z]*)$/s', $pattern, $m ) || false !== strpos( $m[2], 'x' ) ) {
			return array();
		}
		$body = (string) preg_replace( '/\(\?<!\[[A-Za-z0-9_-]*\]\)|\(\?!\[[A-Za-z0-9_-]*\]\)/', '', $m[1] );
		$body = (string) preg_replace( '/^\\\\A/', '', $body );
		$out  = array();
		foreach ( self::top_branches( self::unwrap_group( $body ) ) as $branch ) {
			$branch = self::unwrap_group( $branch );
			$parts  = array();
			if ( 0 === strpos( $branch, '(?=[\s\S]*?' ) ) {
				while ( '' !== $branch ) {
					if ( 0 !== strpos( $branch, '(?=[\s\S]*?' ) ) {
						return array();
					}
					$end = self::group_end( $branch );
					if ( null === $end ) {
						return array();
					}
					$parts[] = substr( $branch, strlen( '(?=[\s\S]*?' ), $end - strlen( '(?=[\s\S]*?' ) );
					$branch  = (string) substr( $branch, $end + 1 );
				}
			} else {
				$parts[] = $branch;
			}
			$literal = null;
			foreach ( $parts as $part ) {
				$plain = self::plain_literal( $part );
				if ( null === $plain || strlen( $plain ) < 4 ) {
					continue;
				}
				// The longest literal of the branch is the most selective.
				if ( null === $literal || strlen( $plain ) > strlen( $literal ) ) {
					$literal = $plain;
				}
			}
			if ( null === $literal ) {
				return array();
			}
			$out[] = strtolower( $literal );
		}
		return array_values( array_unique( $out ) );
	}

	/** Unescaped text of a regex fragment, or null if it holds any regex syntax. */
	private static function plain_literal( string $fragment ): ?string {
		$out = '';
		for ( $i = 0, $n = strlen( $fragment ); $i < $n; $i++ ) {
			$c = $fragment[ $i ];
			if ( '\\' === $c ) {
				$next = $fragment[ $i + 1 ] ?? '';
				if ( '' === $next || ctype_alnum( $next ) ) {
					return null; // \s, \d, \x41, \b, ... are not literals.
				}
				$out .= $next;
				$i++;
				continue;
			}
			if ( false !== strpos( '.^$|?*+()[]{}', $c ) ) {
				return null;
			}
			$out .= $c;
		}
		return $out;
	}

	/** Index of the parenthesis that closes the group opening at 0, or null. */
	private static function group_end( string $s ): ?int {
		$depth = 0;
		$class = false;
		for ( $i = 0, $n = strlen( $s ); $i < $n; $i++ ) {
			$c = $s[ $i ];
			if ( '\\' === $c ) {
				$i++;
				continue;
			}
			if ( $class ) {
				$class = ']' !== $c;
				continue;
			}
			if ( '[' === $c ) {
				$class = true;
			} elseif ( '(' === $c ) {
				$depth++;
			} elseif ( ')' === $c && 0 === --$depth ) {
				return $i;
			}
		}
		return null;
	}

	/** Strip "(?:" ... ")" while it wraps the whole fragment. */
	private static function unwrap_group( string $s ): string {
		while ( 0 === strpos( $s, '(?:' ) && self::group_end( $s ) === strlen( $s ) - 1 ) {
			$s = substr( $s, 3, -1 );
		}
		return $s;
	}

	/** @return string[] Top-level "|" branches. */
	private static function top_branches( string $s ): array {
		$parts = array();
		$cur   = '';
		$depth = 0;
		$class = false;
		for ( $i = 0, $n = strlen( $s ); $i < $n; $i++ ) {
			$c = $s[ $i ];
			if ( '\\' === $c ) {
				$cur .= $c . ( $s[ $i + 1 ] ?? '' );
				$i++;
				continue;
			}
			if ( $class ) {
				$class = ']' !== $c;
			} elseif ( '[' === $c ) {
				$class = true;
			} elseif ( '(' === $c ) {
				$depth++;
			} elseif ( ')' === $c ) {
				$depth--;
			} elseif ( '|' === $c && 0 === $depth ) {
				$parts[] = $cur;
				$cur     = '';
				continue;
			}
			$cur .= $c;
		}
		$parts[] = $cur;
		return $parts;
	}

	/** @return string|null Reason the signature is unusable, or null when it is valid. */
	public static function check( array $sig ): ?string {
		if ( ! preg_match( '/^[A-Z0-9][A-Z0-9._:-]{2,95}$/', $sig['id'] ) ) {
			return 'invalid id';
		}
		if ( ! in_array( $sig['technique'], self::TECHNIQUES, true ) ) {
			return 'unknown technique';
		}
		if ( array_diff( $sig['targets'], self::TARGETS ) || ! $sig['targets'] ) {
			return 'unknown target';
		}
		switch ( $sig['technique'] ) {
			case 'regex':
				return self::check_regex( $sig['pattern'] );
			case 'bytes':
				if ( '' === $sig['bytes'] || strlen( $sig['bytes'] ) % 2 || ! ctype_xdigit( $sig['bytes'] ) || strlen( $sig['bytes'] ) > 2 * self::MAX_PATTERN_LENGTH ) {
					return 'invalid byte pattern';
				}
				return null;
			case 'hash':
				foreach ( $sig['sha256'] as $hash ) {
					if ( ! preg_match( '/^[a-f0-9]{64}$/', $hash ) ) {
						return 'invalid sha256';
					}
				}
				return $sig['sha256'] ? null : 'no hashes';
		}
		return 'invalid';
	}

	/**
	 * Patterns must use the ~ delimiter with a restricted flag set, compile,
	 * and stay within a length limit. The /e modifier can never be used.
	 */
	public static function check_regex( string $pattern ): ?string {
		if ( '' === $pattern || strlen( $pattern ) > self::MAX_PATTERN_LENGTH ) {
			return 'pattern empty or too long';
		}
		if ( ! preg_match( '/^~.*~([imsxuUD]*)$/s', $pattern ) ) {
			return 'pattern must use ~ delimiters and only the imsxuUD flags';
		}
		if ( false === @preg_match( $pattern, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return 'pattern does not compile';
		}
		return null;
	}

	/**
	 * Run a regex against adversarial inputs and reject it if it is slow or hits
	 * PCRE limits (catastrophic backtracking). Used by the build tool and before
	 * installing downloaded signature updates.
	 *
	 * @return string|null Reason, or null when the pattern behaves.
	 */
	public static function check_regex_performance( string $pattern, float $max_seconds = 0.05 ): ?string {
		static $probes = null;
		if ( null === $probes ) {
			$probes = array(
				str_repeat( 'a', 50000 ),
				str_repeat( ' ', 50000 ),
				str_repeat( '\\x41', 12000 ),
				str_repeat( 'chr(65).', 6000 ),
				str_repeat( 'QUJD', 12000 ),
				str_repeat( '<a href="x">y</a>', 3000 ),
				str_repeat( "eval(\n", 8000 ),
				str_repeat( '$_GET[', 8000 ),
				str_repeat( '"\'', 20000 ),
			);
			// Catastrophic backtracking shows when a long run is followed by a mismatch.
			foreach ( $probes as $probe ) {
				$probes[] = substr( $probe, 0, 20000 ) . "\x00!";
			}
		}
		foreach ( $probes as $probe ) {
			$start  = microtime( true );
			$result = @preg_match( $pattern, $probe ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $result ) {
				return 'PCRE error on stress input (' . preg_last_error() . ')';
			}
			if ( microtime( true ) - $start > $max_seconds ) {
				return 'too slow on stress input';
			}
		}
		return null;
	}

	/**
	 * Validate a whole database document. Used by the build tool and before a
	 * downloaded update replaces the active database.
	 *
	 * @return string[] Errors; empty when the document is acceptable.
	 */
	public static function validate( array $data, bool $performance = true ): array {
		$errors = array();
		if ( (int) ( $data['schema'] ?? 1 ) > self::SCHEMA ) {
			$errors[] = 'unsupported schema ' . (int) $data['schema'];
		}
		if ( ! preg_match( '/^\d{4}\.\d{2}\.\d{2}(?:\.\d+)?$/', (string) ( $data['version'] ?? '' ) ) ) {
			$errors[] = 'version must look like YYYY.MM.DD[.N]';
		}
		$list = $data['signatures'] ?? null;
		if ( ! is_array( $list ) || ! $list ) {
			$errors[] = 'no signatures';
			return $errors;
		}
		if ( count( $list ) > self::MAX_SIGNATURES ) {
			$errors[] = 'too many signatures';
		}
		$seen = array();
		foreach ( $list as $i => $raw ) {
			if ( ! is_array( $raw ) ) {
				$errors[] = "entry {$i} is not an object";
				continue;
			}
			$sig = self::normalize( $raw );
			$id  = '' !== $sig['id'] ? $sig['id'] : "#{$i}";
			if ( isset( $seen[ $sig['id'] ] ) ) {
				$errors[] = "{$id}: duplicate id";
			}
			$seen[ $sig['id'] ] = true;
			$error              = self::check( $sig );
			if ( null === $error && $performance && 'regex' === $sig['technique'] ) {
				$error = self::check_regex_performance( $sig['pattern'] );
			}
			if ( null !== $error ) {
				$errors[] = "{$id}: {$error}";
			}
			foreach ( array( 'name', 'family', 'category', 'description', 'source', 'license', 'created' ) as $field ) {
				if ( '' === $sig[ $field ] ) {
					$errors[] = "{$id}: missing {$field}";
				}
			}
		}
		return $errors;
	}

	public function version(): string {
		return $this->version;
	}

	/** @return array<int, array<string, mixed>> Regex and byte signatures. */
	public function all(): array {
		return $this->signatures;
	}

	/** @return array<string, array<string, mixed>> */
	public function hash_signatures(): array {
		return $this->hash_signatures;
	}

	public function hash_count(): int {
		return count( $this->hashes );
	}

	public function count(): int {
		return count( $this->signatures ) + count( $this->hash_signatures );
	}

	/** @return array<string, string> */
	public function invalid(): array {
		return $this->invalid;
	}

	/** @return array<string, int> */
	public function runtime_errors(): array {
		return $this->runtime_errors;
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

	/** @return array<string, mixed>|null Signature whose hash list contains this file hash. */
	public function match_hash( string $sha256 ): ?array {
		$id = $this->hashes[ strtolower( $sha256 ) ] ?? null;
		return null === $id ? null : $this->hash_signatures[ $id ];
	}

	/**
	 * Run every applicable regex/byte signature against $content.
	 *
	 * @return array<int, array{signature: array<string, mixed>, line: int, excerpt: string}>
	 */
	public function match( string $content, string $type ): array {
		$matches = array();
		$lower   = null;
		foreach ( $this->signatures as $sig ) {
			if ( ! in_array( $type, $sig['targets'], true ) && ! in_array( 'any', $sig['targets'], true ) ) {
				continue;
			}
			if ( $sig['prefilter'] ) {
				// Cheap necessary condition before the (much slower) regex.
				$lower = $lower ?? strtolower( $content );
				$found = false;
				foreach ( $sig['prefilter'] as $literal ) {
					if ( false !== strpos( $lower, $literal ) ) {
						$found = true;
						break;
					}
				}
				if ( ! $found ) {
					continue;
				}
			}

			if ( 'bytes' === $sig['technique'] ) {
				$needle = (string) hex2bin( $sig['bytes'] );
				$offset = $sig['nocase'] ? stripos( $content, $needle ) : strpos( $content, $needle );
				if ( false === $offset ) {
					continue;
				}
				$length = strlen( $needle );
			} else {
				$result = @preg_match( $sig['pattern'], $content, $m, PREG_OFFSET_CAPTURE ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( false === $result ) {
					// Backtrack/JIT limit: record it so the miss is visible, never silent.
					$this->runtime_errors[ $sig['id'] ] = ( $this->runtime_errors[ $sig['id'] ] ?? 0 ) + 1;
					continue;
				}
				if ( 1 !== $result ) {
					continue;
				}
				$offset = (int) $m[0][1];
				$length = strlen( $m[0][0] );
			}

			$matches[] = array(
				'signature' => $sig,
				'line'      => substr_count( $content, "\n", 0, $offset ) + 1,
				'excerpt'   => self::excerpt( $content, $offset, $length ),
			);
		}
		return $matches;
	}

	/** Verdict for a confidence value. */
	public static function verdict( int $confidence ): string {
		return $confidence >= self::MALICIOUS_CONFIDENCE ? 'malicious' : 'suspicious';
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

	/** Shannon entropy in bits per byte. */
	public static function entropy( string $data ): float {
		$length = strlen( $data );
		if ( 0 === $length ) {
			return 0.0;
		}
		$entropy = 0.0;
		foreach ( count_chars( $data, 1 ) as $count ) {
			$p        = $count / $length;
			$entropy -= $p * log( $p, 2 );
		}
		return $entropy;
	}
}
