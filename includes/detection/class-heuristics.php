<?php
/**
 * Weighted heuristic analysis of PHP source (local "AI-free" intelligence).
 *
 * The source is tokenized with token_get_all(), which only lexes it; nothing
 * is ever executed or included. Indicators are collected per statement with
 * light data-flow tracking (variables assigned from request input, decoders,
 * remote fetches or assembled function names) and combined into a score.
 *
 * A single legitimate function never makes a file suspicious: the reporting
 * rule needs several independent indicators, or one indicator that only
 * occurs in malicious code (e.g. request input passed to eval()).
 *
 * Free of WordPress calls so it can be unit tested on its own.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Signatures;

final class Heuristics {

	public const VERSION = '1';

	/** Indicators at or below this weight are "weak" and capped together at WEAK_CAP points. */
	private const WEAK_WEIGHT = 20;
	private const WEAK_CAP    = 25;

	/** Files larger than this are left to the signature layer (tokenizing is memory-hungry). */
	public const MAX_BYTES = 1048576;

	private const CODE_SINKS   = array( 'eval', 'assert', 'create_function' );
	private const SHELL_SINKS  = array( 'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec' );
	private const DECODERS     = array( 'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13', 'convert_uudecode', 'hex2bin' );
	private const WRITE_SINKS  = array( 'file_put_contents', 'fwrite', 'fputs', 'move_uploaded_file' );
	private const REMOTE       = array( 'curl_exec', 'fsockopen', 'wp_remote_get', 'wp_remote_post', 'wp_remote_request', 'wp_remote_retrieve_body', 'stream_get_contents' );
	/** Functions whose first argument is the callback to invoke. */
	private const CALLBACKS    = array( 'call_user_func', 'call_user_func_array', 'array_map', 'register_shutdown_function', 'register_tick_function', 'forward_static_call', 'forward_static_call_array' );
	private const RECON        = array( 'php_uname', 'posix_getpwuid', 'posix_getgrgid', 'disk_free_space', 'disk_total_space', 'getmyuid', 'get_current_user', 'posix_geteuid', 'getmypid' );
	private const SHELL_HABITS = array( 'set_time_limit', 'ignore_user_abort', 'error_reporting' );
	private const SANITIZERS   = array( 'sanitize_key', 'sanitize_text_field', 'sanitize_file_name', 'sanitize_title', 'sanitize_email', 'sanitize_user', 'absint', 'intval', 'floatval', 'boolval', 'basename', 'esc_attr', 'esc_html', 'esc_url', 'esc_url_raw', 'esc_sql', 'filter_var', 'filter_input', 'preg_replace', 'preg_match', 'in_array', 'array_key_exists', 'is_numeric', 'ctype_alnum', 'ctype_digit', 'wp_verify_nonce', 'check_admin_referer', 'check_ajax_referer', 'current_user_can', 'validate_file', 'md5', 'sha1', 'hash', 'wp_hash', 'json_encode', 'wp_json_encode', 'htmlspecialchars', 'strip_tags', 'wp_kses', 'wp_kses_post', 'isset', 'empty' );
	private const INPUTS       = array( '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES' );

	/** Calls that hand request input through unchanged (so the result is still attacker-controlled). */
	private const PASSTHROUGH  = array( 'wp_unslash', 'stripslashes', 'stripcslashes', 'trim', 'ltrim', 'rtrim', 'urldecode', 'rawurldecode', 'strtolower', 'strtoupper', 'html_entity_decode', 'strval', 'base64_decode', 'str_rot13', 'gzinflate', 'gzuncompress', 'strrev', 'hex2bin', 'array_values', 'current', 'reset', 'end', 'array_shift', 'array_pop' );

	/** Names that only appear assembled from fragments when someone is hiding them. */
	private const DANGEROUS_NAMES = array( 'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'create_function', 'shell_exec', 'passthru', 'assert', 'eval', 'system', 'proc_open', 'popen', 'file_put_contents', 'move_uploaded_file', 'call_user_func' );

	/** indicator id => [weight, description] */
	public const INDICATORS = array(
		'code_exec_input'         => array( 90, 'Request input reaches eval/assert/create_function' ),
		'shell_exec_input'        => array( 85, 'Request input reaches a shell command function' ),
		'input_function_call'     => array( 90, 'Calls a function whose name comes from request input' ),
		'remote_code_exec'        => array( 90, 'Remotely fetched content reaches eval/assert' ),
		'eval_decoded'            => array( 75, 'Decoded data is executed with eval/assert' ),
		'assembled_function_call' => array( 75, 'Calls a dangerous function whose name was assembled from fragments' ),
		'include_non_php'         => array( 55, 'Includes a file with an image/text extension as PHP' ),
		'include_input'           => array( 50, 'Include path built from unsanitized request input' ),
		'preg_e'                  => array( 60, 'preg_replace() with the /e (eval) modifier' ),
		'write_input'             => array( 45, 'Writes unsanitized request input to a file' ),
		'escaped_dangerous_name'  => array( 45, 'Escape sequences hide a dangerous function name' ),
		'assembled_function_name' => array( 40, 'Dangerous function name assembled from string fragments' ),
		'reversed_name'           => array( 40, 'Dangerous function name stored reversed' ),
		'globals_call'            => array( 40, 'Calls a function through $GLOBALS' ),
		'decoder_of_blob'         => array( 35, 'Decodes a long embedded encoded string' ),
		'goto_obfuscation'        => array( 35, 'Control flow scrambled with many goto statements' ),
		'injected_header'         => array( 35, 'Code packed into the first line before the file\'s real content' ),
		'packed_line'             => array( 30, 'Very long single line containing executable code' ),
		'chr_chain'               => array( 30, 'String built from a long chain of chr() calls' ),
		'hex_escapes'             => array( 20, 'Many \\x escape sequences in string literals' ),
		'high_entropy_blob'       => array( 20, 'Long high-entropy string literal (likely encrypted or packed data)' ),
		'recon_functions'         => array( 20, 'Several server reconnaissance functions (typical of file-manager shells)' ),
		'shell_sink'              => array( 15, 'Uses functions that run shell commands' ),
		'shell_habits'            => array( 15, 'Disables error reporting and time limits (typical of shells and droppers)' ),
		'variable_variables'      => array( 10, 'Heavy use of variable variables ($$name)' ),
	);

	/**
	 * @return array{score: int, indicators: array<string, array{weight: int, line: int, description: string}>, skipped?: string}
	 */
	public static function analyze( string $code ): array {
		if ( strlen( $code ) > self::MAX_BYTES ) {
			return array( 'score' => 0, 'indicators' => array(), 'skipped' => 'file larger than heuristic limit' );
		}
		if ( false === stripos( $code, '<?' ) ) {
			return array( 'score' => 0, 'indicators' => array() );
		}

		$tokens = self::significant_tokens( $code );
		$found  = array();
		$hit    = static function ( string $id, int $line ) use ( &$found ): void {
			if ( ! isset( $found[ $id ] ) ) {
				$found[ $id ] = $line;
			}
		};

		$taint_input   = array();
		$taint_decoded = array();
		$taint_remote  = array();
		$assembled     = array();
		$recon         = array();
		$habits        = array();
		$hex_escapes   = 0;
		$gotos         = 0;
		$var_vars      = 0;

		$stmt    = self::new_statement();
		$count   = count( $tokens );
		$indexes = array(); // Stack of "is this [ ] an index into a non-input array?" flags.

		for ( $i = 0; $i < $count; $i++ ) {
			list( $id, $text, $line ) = $tokens[ $i ];
			$next = $tokens[ $i + 1 ][1] ?? '';
			$prev = $tokens[ $i - 1 ] ?? array( null, '', 0 );

			if ( 0 === $stmt['line'] ) {
				$stmt['line'] = $line;
			}

			if ( null === $id && '[' === $text ) {
				$base      = $prev[1];
				$indexes[] = T_VARIABLE === $prev[0] && ! in_array( $base, self::INPUTS, true ) && '$GLOBALS' !== $base && ! isset( $taint_input[ $base ] );
			} elseif ( null === $id && ']' === $text ) {
				array_pop( $indexes );
			}
			$in_lookup = in_array( true, $indexes, true );

			if ( ( null === $id && ( ';' === $text || '{' === $text || '}' === $text ) ) || T_OPEN_TAG === $id || T_OPEN_TAG_WITH_ECHO === $id || T_CLOSE_TAG === $id ) {
				$indexes = array();
				self::close_statement( $stmt, $hit, $taint_input, $taint_decoded, $taint_remote, $assembled );
				$stmt = self::new_statement();
				continue;
			}

			// Assignment target at the start of a statement: "$var =".
			if ( T_VARIABLE === $id && null === $stmt['target'] && 0 === $stmt['tokens'] && '=' === $next ) {
				$stmt['target'] = $text;
			}
			$stmt['tokens']++;

			switch ( $id ) {
				case T_EVAL:
					$stmt['code_sink'] = true;
					break;
				case T_INCLUDE:
				case T_INCLUDE_ONCE:
				case T_REQUIRE:
				case T_REQUIRE_ONCE:
					$stmt['include'] = true;
					break;
				case T_GOTO:
					$gotos++;
					break;
				case T_FUNCTION:
					// New function scope: taint does not cross function boundaries.
					$taint_input   = array();
					$taint_decoded = array();
					$taint_remote  = array();
					$assembled     = array();
					break;
				case T_INT_CAST:
					$stmt['sanitized'] = true;
					break;
				case T_VARIABLE:
					if ( in_array( $text, self::INPUTS, true ) || ( '$_SERVER' === $text && self::server_header( $tokens, $i ) ) ) {
						// $registry[ $_GET['x'] ] looks a value up by input; the value itself is not input.
						if ( ! $in_lookup ) {
							$stmt['input'] = true;
						}
						if ( '[' === $next && self::bracket_then_call( $tokens, $i + 1 ) ) {
							$hit( 'input_function_call', $line );
						}
					} elseif ( '$GLOBALS' === $text && '[' === $next && self::bracket_then_call( $tokens, $i + 1 ) ) {
						$hit( 'globals_call', $line );
					}
					if ( isset( $taint_input[ $text ] ) && ! $in_lookup ) {
						$stmt['input'] = true;
					}
					if ( isset( $taint_decoded[ $text ] ) ) {
						$stmt['decoded'] = true;
					}
					if ( isset( $taint_remote[ $text ] ) ) {
						$stmt['remote'] = true;
					}
					if ( '(' === $next && ! self::is_method_or_declaration( $prev ) && T_FN !== $prev[0] && '$' !== $prev[1] ) {
						if ( isset( $taint_input[ $text ] ) ) {
							$hit( 'input_function_call', $line );
						} elseif ( isset( $assembled[ $text ] ) ) {
							$hit( 'assembled_function_call', $line );
						}
					}
					if ( '$' === $prev[1] ) {
						$var_vars++;
					}
					break;
				case T_CONSTANT_ENCAPSED_STRING:
				case T_ENCAPSED_AND_WHITESPACE:
					$raw   = $text;
					$value = self::literal_value( $text, $id );
					$stmt['literals'][] = $value;
					$hex_escapes       += substr_count( $raw, '\\x' );
					self::inspect_literal( $raw, $value, $line, $hit, $stmt );
					break;
			}

			if ( '`' === $text && null === $id ) {
				$stmt['shell_sink'] = true;
			}

			if ( null === $id && '.' === $text ) {
				$stmt['concat']++;
			}

			$name = self::function_name( $id, $text );
			if ( null !== $name && '(' === $next && ! self::is_method_or_declaration( $prev ) ) {
				$stmt['calls'][] = $name;
				if ( ! in_array( $name, self::PASSTHROUGH, true ) && ! in_array( $name, array( 'isset', 'empty' ), true ) ) {
					$stmt['transformed'] = true;
					if ( ! in_array( $name, self::DECODERS, true ) && 'chr' !== $name ) {
						$stmt['transformed_other'] = true;
					}
				}
				if ( in_array( $name, self::CODE_SINKS, true ) ) {
					$stmt['code_sink'] = true;
				} elseif ( in_array( $name, self::SHELL_SINKS, true ) ) {
					$stmt['shell_sink'] = true;
				} elseif ( in_array( $name, self::DECODERS, true ) ) {
					$stmt['decoder'] = true;
					$arg             = $tokens[ $i + 2 ] ?? array( null, '', 0 );
					if ( T_CONSTANT_ENCAPSED_STRING === $arg[0] && strlen( $arg[1] ) > 200 ) {
						$hit( 'decoder_of_blob', $line );
					}
				} elseif ( in_array( $name, self::WRITE_SINKS, true ) ) {
					$stmt['write'] = true;
				} elseif ( in_array( $name, self::REMOTE, true ) || ( 'file_get_contents' === $name && self::remote_argument( $tokens, $i ) ) ) {
					$stmt['remote'] = true;
				} elseif ( in_array( $name, self::CALLBACKS, true ) ) {
					$stmt['callback'] = true;
					if ( self::first_argument_tainted( $tokens, $i, $taint_input ) ) {
						$hit( 'input_function_call', $line );
					}
				} elseif ( 'preg_replace' === $name && self::preg_eval_modifier( $tokens, $i ) ) {
					$hit( 'preg_e', $line );
				} elseif ( 'chr' === $name ) {
					$stmt['chr']++;
				} elseif ( 'strrev' === $name ) {
					$stmt['strrev'] = true;
				} elseif ( in_array( $name, self::RECON, true ) ) {
					$recon[ $name ] = true;
				} elseif ( in_array( $name, self::SHELL_HABITS, true ) ) {
					$habits[ $name ] = true;
				}
				if ( in_array( $name, self::SANITIZERS, true ) ) {
					$stmt['sanitized'] = true;
				}
				if ( in_array( $name, self::SHELL_SINKS, true ) ) {
					$hit( 'shell_sink', $line );
				}
			}
		}
		self::close_statement( $stmt, $hit, $taint_input, $taint_decoded, $taint_remote, $assembled );

		if ( $hex_escapes >= 40 ) {
			$hit( 'hex_escapes', 1 );
		}
		if ( $gotos >= 25 ) {
			$hit( 'goto_obfuscation', 1 );
		}
		if ( count( $recon ) >= 3 ) {
			$hit( 'recon_functions', 1 );
		}
		if ( count( $habits ) >= 2 ) {
			$hit( 'shell_habits', 1 );
		}
		if ( $var_vars >= 10 ) {
			$hit( 'variable_variables', 1 );
		}
		self::inspect_layout( $code, $hit );

		$indicators = array();
		$score      = 0;
		$weak       = 0;
		foreach ( $found as $id => $line ) {
			list( $weight, $description ) = self::INDICATORS[ $id ];
			$indicators[ $id ]            = array( 'weight' => $weight, 'line' => $line, 'description' => $description );
			if ( $weight <= self::WEAK_WEIGHT ) {
				$weak += $weight;
			} else {
				$score += $weight;
			}
		}
		// Weak indicators are common in legitimate code; together they add at most WEAK_CAP.
		$score += min( self::WEAK_CAP, $weak );
		uasort(
			$indicators,
			static function ( $a, $b ) {
				return $b['weight'] <=> $a['weight'];
			}
		);

		return array( 'score' => $score, 'indicators' => $indicators );
	}

	/**
	 * Apply the reporting rule.
	 *
	 * @return array{report: bool, confidence: int, severity: string, verdict: string}
	 */
	public static function classify( array $analysis, int $threshold ): array {
		$score  = (int) $analysis['score'];
		$count  = count( $analysis['indicators'] );
		$max    = $count ? max( array_column( $analysis['indicators'], 'weight' ) ) : 0;
		$report = $score >= $threshold && $max >= 40 && ( $count >= 2 || $max >= 80 );

		$confidence = (int) min( 98, $score );
		return array(
			'report'     => $report,
			'confidence' => $confidence,
			'severity'   => $score >= 120 ? 'critical' : ( $score >= 85 ? 'high' : 'medium' ),
			'verdict'    => $confidence >= 85 ? 'malicious' : 'suspicious',
		);
	}

	// --- Internals ------------------------------------------------------------

	private static function new_statement(): array {
		return array(
			'line'       => 0,
			'tokens'     => 0,
			'target'     => null,
			'calls'      => array(),
			'literals'   => array(),
			'input'      => false,
			'decoded'    => false,
			'remote'     => false,
			'decoder'    => false,
			'code_sink'  => false,
			'shell_sink' => false,
			'write'      => false,
			'include'    => false,
			'callback'   => false,
			'sanitized'  => false,
			'transformed' => false,
			'transformed_other' => false,
			'strrev'     => false,
			'chr'        => 0,
			'concat'     => 0,
		);
	}

	private static function close_statement( array $s, callable $hit, array &$taint_input, array &$taint_decoded, array &$taint_remote, array &$assembled ): void {
		if ( 0 === $s['tokens'] ) {
			return;
		}
		$line  = $s['line'];
		$input = $s['input'] && ! $s['sanitized'];

		if ( $s['code_sink'] && $input ) {
			$hit( 'code_exec_input', $line );
		}
		if ( $s['shell_sink'] && $input ) {
			$hit( 'shell_exec_input', $line );
		}
		if ( $s['code_sink'] && $s['remote'] ) {
			$hit( 'remote_code_exec', $line );
		}
		if ( $s['code_sink'] && ( $s['decoder'] || $s['decoded'] ) ) {
			$hit( 'eval_decoded', $line );
		}
		if ( $s['include'] && $input ) {
			$hit( 'include_input', $line );
		}
		if ( $s['include'] && self::includes_non_php( $s['literals'] ) ) {
			$hit( 'include_non_php', $line );
		}
		if ( $s['write'] && $input && ! in_array( 'move_uploaded_file', $s['calls'], true ) ) {
			$hit( 'write_input', $line );
		}
		if ( $s['chr'] >= 10 ) {
			$hit( 'chr_chain', $line );
		}

		$name = self::assembled_name( $s );
		if ( null !== $name ) {
			$hit( 'assembled_function_name', $line );
			if ( $s['callback'] ) {
				$hit( 'assembled_function_call', $line );
			}
		}

		// Propagate taint through simple "$var = ..." assignments.
		if ( null !== $s['target'] ) {
			$var = $s['target'];
			unset( $taint_input[ $var ], $taint_decoded[ $var ], $taint_remote[ $var ], $assembled[ $var ] );
			// Input stays tainted only through pass-through calls; any other function may validate it.
			if ( $input && ! $s['transformed'] ) {
				$taint_input[ $var ] = true;
			}
			if ( $s['decoder'] || $s['decoded'] ) {
				$taint_decoded[ $var ] = true;
			}
			if ( $s['remote'] ) {
				$taint_remote[ $var ] = true;
			}
			// A variable holding a name built with chr(), strrev() or a decoder is a hidden callee.
			if ( null !== $name || $s['chr'] >= 5 || $s['strrev'] || ( $s['decoder'] && ! $input && ! $s['transformed_other'] ) ) {
				$assembled[ $var ] = true;
			}
		}
	}

	/** Dangerous name produced by concatenating 2+ literals (none of which contains it alone), or by strrev(). */
	private static function assembled_name( array $s ): ?string {
		if ( count( $s['literals'] ) < 2 && ! $s['strrev'] ) {
			return null;
		}
		$joined = strtolower( implode( '', $s['literals'] ) );
		if ( $s['strrev'] ) {
			$joined .= '|' . strrev( $joined );
		}
		foreach ( self::DANGEROUS_NAMES as $danger ) {
			if ( strlen( $danger ) < 6 && 'assert' !== $danger ) {
				continue; // "eval"/"exec"-length names are too common inside ordinary words.
			}
			if ( false === strpos( $joined, $danger ) ) {
				continue;
			}
			$whole = false;
			foreach ( $s['literals'] as $literal ) {
				if ( false !== stripos( $literal, $danger ) ) {
					$whole = true;
					break;
				}
			}
			if ( ! $whole && ( $s['concat'] >= 1 || $s['strrev'] ) ) {
				return $danger;
			}
		}
		return null;
	}

	private static function inspect_literal( string $raw, string $value, int $line, callable $hit, array &$stmt ): void {
		$lower = strtolower( $value );

		foreach ( array( 'edoced_46esab', 'etalfnizg', 'sserpmocnuzg', 'cexe_llehs', 'urhtssap', 'noitcnuf_etaerc' ) as $reversed ) {
			if ( false !== strpos( $lower, $reversed ) ) {
				$hit( 'reversed_name', $line );
			}
		}

		// "\x62\x61\x73\x65..." that decodes to a dangerous name.
		if ( substr_count( $raw, '\\x' ) >= 4 || preg_match( '/\\\\[0-7]{3}/', $raw ) ) {
			foreach ( self::DANGEROUS_NAMES as $danger ) {
				if ( strlen( $danger ) >= 6 && false !== strpos( $lower, $danger ) && false === stripos( $raw, $danger ) ) {
					$hit( 'escaped_dangerous_name', $line );
					break;
				}
			}
		}

		$length = strlen( $value );
		if ( $length >= 1000 && 0 !== strpos( $value, 'data:' ) && Signatures::entropy( substr( $value, 0, 20000 ) ) >= 5.0 ) {
			$hit( 'high_entropy_blob', $line );
		}
	}

	/** Look for code packed onto the first line, or very long lines that contain sinks or decoders. */
	private static function inspect_layout( string $code, callable $hit ): void {
		$first_break = strpos( $code, "\n" );
		$first_line  = false === $first_break ? $code : substr( $code, 0, $first_break );
		if ( false !== $first_break && strlen( $first_line ) > 300 && preg_match( '/<\?php.{200,}\?>\s*<\?php/is', substr( $code, 0, 20000 ) ) ) {
			$hit( 'injected_header', 1 );
		}

		$offset = 0;
		$length = strlen( $code );
		$line   = 1;
		while ( $offset < $length ) {
			$end = strpos( $code, "\n", $offset );
			$end = false === $end ? $length : $end;
			if ( $end - $offset > 5000 ) {
				$text = substr( $code, $offset, $end - $offset );
				if ( preg_match( '/\b(?:eval|assert|base64_decode|gzinflate|str_rot13|create_function)\s*\(/i', $text ) ) {
					$hit( 'packed_line', $line );
					return;
				}
			}
			$offset = $end + 1;
			$line++;
		}
	}

	/** @return array<int, array{0: int|null, 1: string, 2: int}> Tokens without whitespace and comments. */
	private static function significant_tokens( string $code ): array {
		$out  = array();
		$line = 1;
		foreach ( token_get_all( $code ) as $token ) {
			if ( is_array( $token ) ) {
				$line = $token[2];
				if ( in_array( $token[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
					continue;
				}
				$out[] = array( $token[0], $token[1], $line );
			} else {
				$out[] = array( null, $token, $line );
			}
		}
		return $out;
	}

	/** Lower-cased function name for a T_STRING / namespaced name token, or null. */
	private static function function_name( ?int $id, string $text ): ?string {
		if ( T_STRING === $id ) {
			return strtolower( $text );
		}
		if ( defined( 'T_NAME_FULLY_QUALIFIED' ) && T_NAME_FULLY_QUALIFIED === $id ) { // phpcs:ignore PHPCompatibility.Constants.NewConstants -- guarded (PHP 8.0+).
			return strtolower( ltrim( $text, '\\' ) );
		}
		return null;
	}

	private static function is_method_or_declaration( array $prev ): bool {
		$ids = array( T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_CONST );
		if ( defined( 'T_NULLSAFE_OBJECT_OPERATOR' ) ) {
			$ids[] = T_NULLSAFE_OBJECT_OPERATOR; // phpcs:ignore PHPCompatibility.Constants.NewConstants -- guarded (PHP 8.0+).
		}
		return in_array( $prev[0], $ids, true );
	}

	/** True when tokens from $open ("[") close the bracket and are immediately followed by "(". */
	private static function bracket_then_call( array $tokens, int $open ): bool {
		$depth = 0;
		$limit = min( count( $tokens ), $open + 40 );
		for ( $j = $open; $j < $limit; $j++ ) {
			$text = $tokens[ $j ][1];
			if ( null === $tokens[ $j ][0] && '[' === $text ) {
				$depth++;
			} elseif ( null === $tokens[ $j ][0] && ']' === $text ) {
				$depth--;
				if ( 0 === $depth ) {
					$after = $tokens[ $j + 1 ][1] ?? '';
					if ( '[' === $after ) {
						continue; // $_GET['a']['b'](...)
					}
					return '(' === $after;
				}
			}
		}
		return false;
	}

	/**
	 * True when the callback argument of the call at $i *is* request input or an
	 * input-tainted variable (optionally wrapped in pass-through calls), e.g.
	 * call_user_func( $_GET['f'] ). A fixed prefix or array( $this, ... ) does
	 * not count: those restrict what can be called.
	 */
	private static function first_argument_tainted( array $tokens, int $i, array $taint_input ): bool {
		$j     = $i + 2; // Skip the name and "(".
		$count = count( $tokens );
		while ( $j < $count && T_STRING === $tokens[ $j ][0] && in_array( strtolower( $tokens[ $j ][1] ), self::PASSTHROUGH, true ) && '(' === ( $tokens[ $j + 1 ][1] ?? '' ) ) {
			$j += 2;
		}
		if ( $j >= $count || T_VARIABLE !== $tokens[ $j ][0] ) {
			return false;
		}
		$var = $tokens[ $j ][1];
		if ( ! in_array( $var, self::INPUTS, true ) && ! isset( $taint_input[ $var ] ) ) {
			return false;
		}
		// The argument must end right after the variable (and its [index]), not continue with ". 'suffix'".
		for ( $k = $j + 1, $depth = 0; $k < $count; $k++ ) {
			$text = $tokens[ $k ][1];
			if ( null !== $tokens[ $k ][0] ) {
				if ( 0 === $depth ) {
					return false;
				}
				continue;
			}
			if ( '[' === $text ) {
				$depth++;
			} elseif ( ']' === $text ) {
				$depth--;
			} elseif ( 0 === $depth ) {
				return in_array( $text, array( ',', ')' ), true );
			}
		}
		return false;
	}

	/** $_SERVER['HTTP_*'] request headers are attacker-controlled; the rest of $_SERVER is not. */
	private static function server_header( array $tokens, int $i ): bool {
		return '[' === ( $tokens[ $i + 1 ][1] ?? '' )
			&& T_CONSTANT_ENCAPSED_STRING === ( $tokens[ $i + 2 ][0] ?? null )
			&& 0 === stripos( trim( $tokens[ $i + 2 ][1], '\'"' ), 'HTTP_' );
	}

	private static function remote_argument( array $tokens, int $i ): bool {
		$arg = $tokens[ $i + 2 ] ?? array( null, '', 0 );
		return T_CONSTANT_ENCAPSED_STRING === $arg[0] && 1 === preg_match( '#^[\'"]\s*(?:https?|ftp)://#i', $arg[1] );
	}

	/** preg_replace('/.../e', ...) — first argument literal with an "e" modifier. */
	private static function preg_eval_modifier( array $tokens, int $i ): bool {
		$arg = $tokens[ $i + 2 ] ?? array( null, '', 0 );
		if ( T_CONSTANT_ENCAPSED_STRING !== $arg[0] ) {
			return false;
		}
		$pattern = substr( $arg[1], 1, -1 );
		if ( strlen( $pattern ) < 3 ) {
			return false;
		}
		$delimiter = $pattern[0];
		$closing   = array( '(' => ')', '{' => '}', '[' => ']', '<' => '>' )[ $delimiter ] ?? $delimiter;
		$end       = strrpos( $pattern, $closing );
		return false !== $end && $end > 0 && false !== strpos( substr( $pattern, $end + 1 ), 'e' );
	}

	private static function includes_non_php( array $literals ): bool {
		foreach ( $literals as $literal ) {
			if ( preg_match( '/\.(?:ico|png|jpe?g|gif|bmp|txt|log|dat)\s*$/i', $literal ) ) {
				return true;
			}
		}
		return false;
	}

	private static function literal_value( string $text, int $id ): string {
		if ( T_CONSTANT_ENCAPSED_STRING !== $id ) {
			return $text;
		}
		$quote = $text[0];
		$inner = substr( $text, 1, -1 );
		// Decode escapes for analysis only; the result is never executed.
		return '"' === $quote ? stripcslashes( $inner ) : str_replace( array( "\\'", '\\\\' ), array( "'", '\\' ), $inner );
	}
}
