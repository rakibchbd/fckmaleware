<?php
/**
 * Collect threat intelligence and turn it into candidate signatures.
 *
 * Usage:
 *   php tools/intel/collect.php --source=<urlhaus|signature-base|malwarebazaar|community|all>
 *       --clean=<dir>[,<dir>...]   Clean corpus (WordPress core, popular plugins/themes).
 *                                   Candidates matching anything here are rejected.
 *
 * Output: intel/candidates/<date>-<source>.json (pending / rejected with reasons).
 * Nothing is added to the shipped database until tools/intel/approve.php runs.
 * This tool downloads indicators and rules only, never malware samples.
 */

require __DIR__ . '/lib.php';

$options = getopt( '', array( 'source:', 'clean:' ) );
$source  = (string) ( $options['source'] ?? '' );
$clean   = array_filter( array_map( 'realpath', explode( ',', (string) ( $options['clean'] ?? '' ) ) ) );
if ( '' === $source || ! $clean ) {
	fwrite( STDERR, "Usage: php tools/intel/collect.php --source=<urlhaus|signature-base|malwarebazaar|community|all> --clean=<dir>[,<dir>...]\n" );
	exit( 2 );
}

$root     = dirname( __DIR__, 2 );
$pipeline = new IntelPipeline( $root, $clean );
$sources  = 'all' === $source ? array( 'urlhaus', 'signature-base', 'malwarebazaar', 'community' ) : array( $source );

foreach ( $sources as $name ) {
	echo "== {$name}\n";
	switch ( $name ) {
		case 'urlhaus':
			$signatures = collect_urlhaus();
			break;
		case 'signature-base':
			$signatures = collect_signature_base();
			break;
		case 'malwarebazaar':
			$signatures = collect_malwarebazaar();
			break;
		case 'community':
			$signatures = collect_community( $root );
			break;
		default:
			fwrite( STDERR, "Unknown source {$name}\n" );
			exit( 2 );
	}
	if ( null === $signatures ) {
		echo "  skipped\n";
		continue;
	}
	echo '  collected ' . count( $signatures ) . " signatures; testing against the clean corpus...\n";
	$result = $pipeline->process( $name, $signatures );
	printf( "  %d pending review, %d rejected -> %s\n", $result['pending'], $result['rejected'], substr( $result['file'], strlen( $root ) + 1 ) );
}

// --- URLhaus ------------------------------------------------------------------

/** Web-injection campaign hosts → host signatures (one per campaign tag). */
function collect_urlhaus(): ?array {
	$raw = IntelPipeline::http_get( 'https://urlhaus.abuse.ch/downloads/json_recent/' );
	if ( null === $raw ) {
		return null;
	}
	$data = json_decode( $raw, true );
	if ( ! is_array( $data ) ) {
		return null;
	}
	// Campaigns that inject scripts into websites (the only URLhaus entries relevant to WordPress content).
	$campaigns = array( 'clearfake', 'socgholish', 'fakeupdates', 'fakeupdate', 'balada', 'keitaro', 'wordpress' );
	// Shared platforms: a host-level signature would flag legitimate sites.
	$shared = '~(?:^|\.)(?:github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|jsdelivr\.net|unpkg\.com|cloudflare\.com|google\.com|googleapis\.com|dropbox\.com|dropboxusercontent\.com|discord\.com|discordapp\.com|onedrive\.live\.com|1drv\.ms|mediafire\.com|pastebin\.com|transfer\.sh|bit\.ly|amazonaws\.com|azureedge\.net|jsonsilo\.com|wordpress\.org|wordpress\.com|wp\.com)$~i';

	$hosts = array();
	foreach ( $data as $rows ) {
		foreach ( (array) $rows as $row ) {
			$tags = array_map( 'strtolower', (array) ( $row['tags'] ?? array() ) );
			$hit  = array_values( array_intersect( $tags, $campaigns ) );
			if ( ! $hit || ( 'wordpress' === $hit[0] && ! in_array( 'js', $tags, true ) && 1 === count( $hit ) ) ) {
				continue;
			}
			$host = strtolower( (string) parse_url( (string) $row['url'], PHP_URL_HOST ) );
			if ( '' === $host || filter_var( $host, FILTER_VALIDATE_IP ) || preg_match( $shared, $host ) || ! preg_match( '/^[a-z0-9.-]+\.[a-z]{2,}$/', $host ) ) {
				continue;
			}
			$hosts[ $hit[0] ][ $host ] = true;
		}
	}

	$out = array();
	foreach ( $hosts as $campaign => $list ) {
		$list = array_keys( $list );
		sort( $list );
		foreach ( array_chunk( $list, 150 ) as $i => $chunk ) {
			$alternation = implode( '|', array_map( static function ( $h ) {
				return preg_quote( $h, '~' );
			}, $chunk ) );
			$out[] = array(
				'id'          => sprintf( 'FMW-UH-%s-%s-%d', strtoupper( $campaign ), gmdate( 'Ymd' ), $i + 1 ),
				'name'        => sprintf( 'Script host from the %s campaign', ucfirst( $campaign ) ),
				'family'      => 'JS.Injection.' . ucfirst( $campaign ),
				'category'    => 'js-injection',
				'technique'   => 'regex',
				'severity'    => 'high',
				'confidence'  => 80,
				'targets'     => array( 'js', 'html', 'php', 'db' ),
				'pattern'     => '~(?<![a-z0-9.-])(?:' . $alternation . ')(?![a-z0-9-])~i',
				'description' => sprintf( 'References a host reported by URLhaus for the %s web-injection campaign (%d hosts).', $campaign, count( $chunk ) ),
				'remediation' => 'clean',
			) + IntelPipeline::meta( 'URLhaus by abuse.ch (https://urlhaus.abuse.ch/)', 'CC0-1.0' );
		}
	}
	return $out;
}

// --- MalwareBazaar ------------------------------------------------------------

/** Hashes of PHP web shells and WordPress malware → hash signatures. */
function collect_malwarebazaar(): ?array {
	$key = (string) getenv( 'ABUSECH_AUTH_KEY' );
	if ( '' === $key ) {
		fwrite( STDERR, "  MalwareBazaar needs a free abuse.ch Auth-Key in ABUSECH_AUTH_KEY.\n" );
		return null;
	}
	$out = array();
	foreach ( array( 'webshell', 'php', 'wordpress' ) as $tag ) {
		$raw  = IntelPipeline::http_get( 'https://mb-api.abuse.ch/api/v1/', array( 'query' => 'get_taginfo', 'tag' => $tag, 'limit' => 500 ), array( 'Auth-Key: ' . $key ) );
		$data = null === $raw ? null : json_decode( $raw, true );
		if ( ! is_array( $data ) || 'ok' !== ( $data['query_status'] ?? '' ) ) {
			fwrite( STDERR, "  tag {$tag}: " . ( $data['query_status'] ?? 'no response' ) . "\n" );
			continue;
		}
		$hashes = array();
		foreach ( (array) $data['data'] as $sample ) {
			if ( in_array( strtolower( (string) ( $sample['file_type'] ?? '' ) ), array( 'php', 'js', 'html', 'htm', 'txt', 'unknown' ), true ) && preg_match( '/^[a-f0-9]{64}$/', (string) $sample['sha256_hash'] ) ) {
				$hashes[] = strtolower( $sample['sha256_hash'] );
			}
		}
		if ( $hashes ) {
			$out[] = array(
				'id'          => sprintf( 'FMW-MB-%s-%s', strtoupper( $tag ), gmdate( 'Ymd' ) ),
				'name'        => sprintf( 'Known malware sample (MalwareBazaar tag "%s")', $tag ),
				'family'      => 'Known.' . ucfirst( $tag ),
				'category'    => 'known-sample',
				'technique'   => 'hash',
				'severity'    => 'critical',
				'confidence'  => 95,
				'targets'     => array( 'any' ),
				'sha256'      => array_values( array_unique( $hashes ) ),
				'description' => sprintf( 'SHA-256 of %d samples tagged "%s" on MalwareBazaar.', count( $hashes ), $tag ),
				'remediation' => 'quarantine',
			) + IntelPipeline::meta( 'MalwareBazaar by abuse.ch (https://bazaar.abuse.ch/)', 'CC0-1.0' );
		}
	}
	return $out;
}

// --- signature-base (YARA) ----------------------------------------------------

function collect_signature_base(): ?array {
	$raw = IntelPipeline::http_get( 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar' );
	if ( null === $raw ) {
		return null;
	}
	$out     = array();
	$skipped = array();
	foreach ( YaraSubset::parse( $raw ) as $rule ) {
		$sig = YaraSubset::convert( $rule );
		if ( is_string( $sig ) ) {
			$skipped[ $sig ] = ( $skipped[ $sig ] ?? 0 ) + 1;
			continue;
		}
		$out[] = $sig;
	}
	foreach ( $skipped as $why => $count ) {
		echo "  skipped {$count} rules: {$why}\n";
	}
	return $out;
}

/**
 * Converts the subset of YARA that maps faithfully onto a single PCRE:
 * plain text strings (ascii / nocase / fullword) with "any|all|N of them".
 */
final class YaraSubset {

	public static function parse( string $source ): array {
		$source = preg_replace( '~/\*.*?\*/~s', '', $source );
		preg_match_all( '~^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z0-9_]+)[^{]*\{(.*?)^\}~ms', (string) $source, $m, PREG_SET_ORDER );
		$rules = array();
		foreach ( $m as $match ) {
			$body = $match[2];
			$rule = array( 'name' => $match[1], 'meta' => array(), 'strings' => array(), 'condition' => '' );
			if ( preg_match( '~meta:(.*?)(?:strings:|condition:)~s', $body, $meta ) ) {
				preg_match_all( '~^\s*(\w+)\s*=\s*"((?:[^"\\\\]|\\\\.)*)"~m', $meta[1], $pairs, PREG_SET_ORDER );
				foreach ( $pairs as $pair ) {
					$rule['meta'][ $pair[1] ] = $pair[2];
				}
				preg_match_all( '~^\s*(\w+)\s*=\s*(\d+)\s*$~m', $meta[1], $nums, PREG_SET_ORDER );
				foreach ( $nums as $pair ) {
					$rule['meta'][ $pair[1] ] = (int) $pair[2];
				}
			}
			if ( preg_match( '~strings:(.*?)condition:~s', $body, $strings ) ) {
				foreach ( preg_split( '~\R~', $strings[1] ) as $line ) {
					$line = trim( preg_replace( '~\s//.*$~', '', $line ) );
					if ( preg_match( '~^\$(\w*)\s*=\s*"((?:[^"\\\\]|\\\\.)*)"\s*(.*)$~', $line, $s ) ) {
						$rule['strings'][] = array( 'kind' => 'text', 'value' => self::unescape( $s[2] ), 'mods' => preg_split( '~\s+~', strtolower( trim( $s[3] ) ), -1, PREG_SPLIT_NO_EMPTY ) );
					} elseif ( preg_match( '~^\$\w*\s*=~', $line ) ) {
						$rule['strings'][] = array( 'kind' => 'unsupported' );
					}
				}
			}
			if ( preg_match( '~condition:(.*)$~s', $body, $cond ) ) {
				$rule['condition'] = strtolower( trim( preg_replace( '~\s+~', ' ', preg_replace( '~//[^\n]*~', '', $cond[1] ) ) ) );
			}
			$rules[] = $rule;
		}
		return $rules;
	}

	private static function unescape( string $s ): string {
		return (string) preg_replace_callback(
			'~\\\\(x[0-9a-fA-F]{2}|.)~',
			static function ( $m ) {
				if ( 'x' === $m[1][0] && 3 === strlen( $m[1] ) ) {
					return chr( (int) hexdec( substr( $m[1], 1 ) ) );
				}
				return array( 'n' => "\n", 't' => "\t", 'r' => "\r" )[ $m[1] ] ?? $m[1];
			},
			$s
		);
	}

	/** @return array|string Signature, or the reason the rule cannot be converted. */
	public static function convert( array $rule ) {
		$name = $rule['name'];
		$desc = (string) ( $rule['meta']['description'] ?? '' );
		$php  = (bool) preg_match( '~php|wordpress|wp_~i', $name . ' ' . $desc );
		foreach ( $rule['strings'] as $s ) {
			if ( 'text' === $s['kind'] && preg_match( '~<\?php|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|eval\(|base64_decode|\$GLOBALS~', $s['value'] ) ) {
				$php = true;
			}
		}
		if ( ! $php ) {
			return 'not a PHP rule';
		}

		$condition = trim( preg_replace( '~(?:filesize\s*[<>]=?\s*\d+\s*(?:kb|mb)?\s+and\s+|\s+and\s+filesize\s*[<>]=?\s*\d+\s*(?:kb|mb)?)~', '', $rule['condition'] ) );
		$condition = trim( $condition, '() ' );
		if ( ! preg_match( '~^(all|any|\d+) of them$~', $condition, $c ) ) {
			return 'condition not supported (' . substr( $condition, 0, 40 ) . ')';
		}

		$fragments   = array();
		$unsupported = 0;
		foreach ( $rule['strings'] as $s ) {
			if ( 'text' !== $s['kind'] || array_intersect( $s['mods'], array( 'wide', 'base64', 'base64wide', 'xor' ) ) && ! in_array( 'ascii', $s['mods'], true ) ) {
				$unsupported++;
				continue;
			}
			if ( strlen( $s['value'] ) < 6 ) {
				$unsupported++;
				continue;
			}
			$fragment = preg_quote( $s['value'], '~' );
			if ( in_array( 'nocase', $s['mods'], true ) ) {
				$fragment = '(?i:' . $fragment . ')';
			}
			if ( in_array( 'fullword', $s['mods'], true ) ) {
				$fragment = '(?<![A-Za-z0-9_])' . $fragment . '(?![A-Za-z0-9_])';
			}
			$fragments[] = $fragment;
		}
		$total = count( $fragments ) + $unsupported;
		if ( ! $fragments ) {
			return 'no convertible strings';
		}
		$need = 'all' === $c[1] ? $total : ( 'any' === $c[1] ? 1 : (int) $c[1] );
		if ( $unsupported && 1 !== $need ) {
			return 'condition depends on unsupported strings';
		}

		if ( 1 === $need ) {
			$pattern = '~(?:' . implode( '|', $fragments ) . ')~';
		} elseif ( $need === count( $fragments ) && $need <= 8 ) {
			$pattern = '~\A' . implode( '', array_map( static function ( $f ) {
				return '(?=[\s\S]*?' . $f . ')';
			}, $fragments ) ) . '~';
		} else {
			$combos = self::combinations( count( $fragments ), $need );
			if ( count( $combos ) > 20 ) {
				return 'too many string combinations';
			}
			$alternatives = array();
			foreach ( $combos as $combo ) {
				$alternatives[] = implode( '', array_map( static function ( $i ) use ( $fragments ) {
					return '(?=[\s\S]*?' . $fragments[ $i ] . ')';
				}, $combo ) );
			}
			$pattern = '~\A(?:' . implode( '|', $alternatives ) . ')~';
		}
		if ( strlen( $pattern ) > 4096 ) {
			return 'pattern too long';
		}

		$score  = (int) ( $rule['meta']['score'] ?? 70 );
		$author = (string) ( $rule['meta']['author'] ?? 'Florian Roth' );
		$ref    = (string) ( $rule['meta']['reference'] ?? '' );
		return array(
			'id'          => 'FMW-SB-' . strtoupper( substr( preg_replace( '~[^A-Za-z0-9]+~', '-', $name ), 0, 80 ) ),
			'name'        => str_replace( '_', ' ', $name ),
			'family'      => 'WebShell.' . preg_replace( '~^(?:webshell|WEBSHELL)_?~', '', $name ),
			'category'    => 'webshell',
			'technique'   => 'regex',
			'severity'    => $score >= 75 ? 'critical' : 'high',
			'confidence'  => max( 60, min( 90, $score ) ),
			'targets'     => array( 'php' ),
			'pattern'     => $pattern,
			'description' => trim( $desc . ' (YARA rule ' . $name . ' by ' . $author . ( '' !== $ref ? '; reference ' . $ref : '' ) . '; converted: ' . $c[0] . ')' ),
			'remediation' => 'quarantine',
		) + IntelPipeline::meta( 'Neo23x0/signature-base, rule ' . $name . ' by ' . $author . ' (https://github.com/Neo23x0/signature-base)', 'DRL-1.1' );
	}

	/** @return int[][] All $k-element index combinations of 0..$n-1. */
	private static function combinations( int $n, int $k ): array {
		if ( 0 === $k ) {
			return array( array() );
		}
		$out = array();
		for ( $i = 0; $i <= $n - $k; $i++ ) {
			foreach ( self::combinations( $n - $i - 1, $k - 1 ) as $rest ) {
				$out[] = array_merge( array( $i ), array_map( static function ( $r ) use ( $i ) {
					return $r + $i + 1;
				}, $rest ) );
			}
			if ( count( $out ) > 21 ) {
				break;
			}
		}
		return $out;
	}
}

// --- Community ----------------------------------------------------------------

function collect_community( string $root ): ?array {
	$out = array();
	foreach ( glob( $root . '/intel/community/*.json' ) ?: array() as $file ) {
		$batch = json_decode( (string) file_get_contents( $file ), true );
		foreach ( (array) ( $batch['signatures'] ?? array() ) as $sig ) {
			$sig['source']  = $sig['source'] ?? 'Community submission (' . basename( $file ) . ')';
			$sig['license'] = $sig['license'] ?? 'GPL-3.0-or-later';
			$out[]          = $sig;
		}
	}
	return $out;
}
