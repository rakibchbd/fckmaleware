<?php
/**
 * Shared pipeline stages for threat-intelligence candidates (maintainer side).
 *
 *   collect → validate → normalize → deduplicate → classify → test
 *   → (human) approve → build → sign → publish → sites update
 *
 * Candidates are written to intel/candidates/<date>-<source>.json with a
 * status of "pending" or "rejected" (with the reason). Nothing here touches
 * the shipped database; tools/intel/approve.php does that on explicit request.
 */

$root = dirname( __DIR__, 2 );
require_once $root . '/includes/class-signatures.php';

use Fckmaleware\Signatures;

final class IntelPipeline {

	/** @var string */
	public $root;

	/** @var string[] Clean corpus directories (must produce zero matches). */
	private $clean;

	/** @var array<string, bool> Existing patterns / hashes / ids for deduplication. */
	private $existing = array( 'id' => array(), 'pattern' => array(), 'hash' => array() );

	public function __construct( string $root, array $clean_dirs ) {
		$this->root  = $root;
		$this->clean = $clean_dirs;

		$current = json_decode( (string) file_get_contents( $root . '/signatures/signatures.json' ), true );
		foreach ( (array) $current['signatures'] as $sig ) {
			$this->existing['id'][ $sig['id'] ] = true;
			if ( '' !== (string) ( $sig['pattern'] ?? '' ) ) {
				$this->existing['pattern'][ $sig['pattern'] ] = true;
			}
			foreach ( (array) ( $sig['sha256'] ?? array() ) as $hash ) {
				$this->existing['hash'][ strtolower( $hash ) ] = true;
			}
		}
	}

	/**
	 * Run every stage after collection and write the candidate file.
	 *
	 * @param array[] $signatures Raw signatures from a collector.
	 * @return array{file: string, pending: int, rejected: int}
	 */
	public function process( string $source, array $signatures ): array {
		$candidates = array();
		$seen       = array();
		$valid      = array();
		foreach ( $signatures as $raw ) {
			$sig          = Signatures::normalize( $raw );
			$reason       = $this->reject_reason( $sig, $seen );
			$candidates[] = array(
				'status'    => null === $reason ? 'pending' : 'rejected',
				'reason'    => $reason,
				'tests'     => null,
				'signature' => $sig,
			);
			if ( null === $reason ) {
				$valid[ $sig['id'] ] = count( $candidates ) - 1;
			}
		}

		// One pass over the corpus for all valid candidates together.
		$results = $this->test_many(
			array_map(
				static function ( $index ) use ( $candidates ) {
					return $candidates[ $index ]['signature'];
				},
				array_values( $valid )
			)
		);
		foreach ( $valid as $id => $index ) {
			$candidates[ $index ]['tests'] = $results[ $id ];
			if ( $results[ $id ]['clean_hits'] ) {
				$candidates[ $index ]['status'] = 'rejected';
				$candidates[ $index ]['reason'] = 'matches clean corpus: ' . implode( ', ', array_slice( $results[ $id ]['clean_hits'], 0, 3 ) );
			}
		}

		$file = $this->root . '/intel/candidates/' . gmdate( 'Y-m-d' ) . '-' . $source . '.json';
		file_put_contents(
			$file,
			json_encode(
				array(
					'source'     => $source,
					'collected'  => gmdate( 'c' ),
					'corpus'     => array_map( 'basename', $this->clean ),
					'candidates' => $candidates,
				),
				JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
			) . "\n"
		);
		$pending = count( array_filter( $candidates, static function ( $c ) {
			return 'pending' === $c['status'];
		} ) );
		return array( 'file' => $file, 'pending' => $pending, 'rejected' => count( $candidates ) - $pending );
	}

	/** Validate and deduplicate. */
	private function reject_reason( array $sig, array &$seen ): ?string {
		$error = Signatures::check( $sig );
		if ( null !== $error ) {
			return 'invalid: ' . $error;
		}
		if ( 'regex' === $sig['technique'] ) {
			$perf = Signatures::check_regex_performance( $sig['pattern'] );
			if ( null !== $perf ) {
				return 'unsafe regex: ' . $perf;
			}
		}
		foreach ( array( 'name', 'family', 'category', 'description', 'source', 'license', 'created' ) as $field ) {
			if ( '' === $sig[ $field ] ) {
				return "missing {$field}";
			}
		}
		if ( isset( $this->existing['id'][ $sig['id'] ] ) || isset( $seen[ 'id:' . $sig['id'] ] ) ) {
			return 'duplicate id';
		}
		$key = 'regex' === $sig['technique'] ? 'pattern:' . $sig['pattern'] : ( 'bytes' === $sig['technique'] ? 'bytes:' . $sig['bytes'] : '' );
		if ( '' !== $key && ( isset( $seen[ $key ] ) || ( 'regex' === $sig['technique'] && isset( $this->existing['pattern'][ $sig['pattern'] ] ) ) ) ) {
			return 'duplicate pattern';
		}
		if ( 'hash' === $sig['technique'] ) {
			foreach ( $sig['sha256'] as $hash ) {
				if ( isset( $this->existing['hash'][ $hash ] ) || isset( $seen[ 'hash:' . $hash ] ) ) {
					return 'duplicate hash';
				}
			}
			foreach ( $sig['sha256'] as $hash ) {
				$seen[ 'hash:' . $hash ] = true;
			}
		}
		$seen[ 'id:' . $sig['id'] ] = true;
		if ( '' !== $key ) {
			$seen[ $key ] = true;
		}
		return null;
	}

	/** Test a single candidate (kept for tools that check one signature). */
	public function test( array $sig ): array {
		return $this->test_many( array( $sig ) )[ $sig['id'] ];
	}

	/**
	 * Run candidates against the clean corpus (must be zero hits) and the
	 * malware fixtures (informational), reading every file once.
	 *
	 * @return array<string, array{clean_hits: string[], fixture_hits: int}>
	 */
	public function test_many( array $sigs ): array {
		$out = array();
		foreach ( $sigs as $sig ) {
			$out[ $sig['id'] ] = array( 'clean_hits' => array(), 'fixture_hits' => 0 );
		}
		if ( ! $sigs ) {
			return $out;
		}
		$db       = new Signatures( array( 'version' => '0000.00.00', 'signatures' => $sigs ) );
		$has_hash = $db->hash_count() > 0;
		foreach ( $this->clean as $dir ) {
			foreach ( self::files( $dir ) as $path => $type ) {
				$content = (string) file_get_contents( $path );
				$hits    = array();
				foreach ( $db->match( $content, $type ) as $match ) {
					$hits[] = $match['signature']['id'];
				}
				if ( $has_hash ) {
					$hash = $db->match_hash( hash( 'sha256', $content ) );
					if ( $hash ) {
						$hits[] = $hash['id'];
					}
				}
				foreach ( $hits as $id ) {
					if ( count( $out[ $id ]['clean_hits'] ) < 5 ) {
						$out[ $id ]['clean_hits'][] = substr( $path, strlen( $dir ) + 1 );
					}
				}
			}
		}
		foreach ( glob( $this->root . '/tests/fixtures/malware/*.fixture' ) ?: array() as $fixture ) {
			preg_match( '/\.([a-z]+)\.fixture$/', $fixture, $m );
			$type = array( 'htaccess' => 'htaccess', 'ini' => 'ini' )[ $m[1] ] ?? ( Signatures::file_type( 'x.' . $m[1] ) ?? 'php' );
			foreach ( $db->match( (string) file_get_contents( $fixture ), $type ) as $match ) {
				$out[ $match['signature']['id'] ]['fixture_hits']++;
			}
		}
		return $out;
	}

	/** @return \Generator<string, string> path => signature type */
	private static function files( string $dir ): \Generator {
		static $cache = array();
		if ( ! isset( $cache[ $dir ] ) ) {
			$cache[ $dir ] = array();
			$it            = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $it as $file ) {
				if ( $file->isFile() && ! $file->isLink() && $file->getSize() <= 4 * 1048576 ) {
					$type = Signatures::file_type( $file->getPathname(), true );
					if ( null !== $type ) {
						$cache[ $dir ][ $file->getPathname() ] = $type;
					}
				}
			}
		}
		foreach ( $cache[ $dir ] as $path => $type ) {
			yield $path => $type;
		}
	}

	/** Common metadata for collector output. */
	public static function meta( string $source, string $license ): array {
		return array(
			'source'          => $source,
			'license'         => $license,
			'created'         => gmdate( 'Y-m-d' ),
			'updated'         => gmdate( 'Y-m-d' ),
			'revision'        => 1,
			'false_positives' => array(),
		);
	}

	/** HTTP request via libcurl (honours HTTPS_PROXY / SSL_CERT_FILE like other CLI tools). */
	public static function http_get( string $url, ?array $post = null, array $headers = array() ): ?string {
		$ch = curl_init( $url );
		curl_setopt_array(
			$ch,
			array(
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_FOLLOWLOCATION => true,
				CURLOPT_MAXREDIRS      => 3,
				CURLOPT_TIMEOUT        => 120,
				CURLOPT_USERAGENT      => 'fckmaleware-intel/1.0',
				CURLOPT_HTTPHEADER     => $headers,
			)
		);
		if ( null !== $post ) {
			curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $post ) );
		}
		foreach ( array( 'SSL_CERT_FILE', 'CURL_CA_BUNDLE' ) as $env ) {
			if ( getenv( $env ) ) {
				curl_setopt( $ch, CURLOPT_CAINFO, getenv( $env ) );
				break;
			}
		}
		$body = curl_exec( $ch );
		$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
		curl_close( $ch );
		if ( false === $body || $code >= 400 ) {
			fwrite( STDERR, "  {$url}: HTTP {$code}\n" );
			return null;
		}
		return (string) $body;
	}
}
