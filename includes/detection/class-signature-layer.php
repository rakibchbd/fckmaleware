<?php
/**
 * Layer A: signature detection (SHA-256 hashes, exact byte patterns, regex).
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Signatures;

final class SignatureLayer implements Layer {

	/** @var Signatures */
	private $signatures;

	public function __construct( Signatures $signatures ) {
		$this->signatures = $signatures;
	}

	public function id(): string {
		return 'signature';
	}

	public function inspect( FileContext $file ): array {
		if ( null === $file->type ) {
			return array();
		}
		$detections = array();

		if ( $this->signatures->hash_count() ) {
			$sig = $this->signatures->match_hash( $file->sha256() );
			if ( null !== $sig ) {
				$detections[] = self::detection( $sig, 0, '', __( 'File hash matches a known malware sample.', 'fckmaleware' ) );
			}
		}

		foreach ( $this->signatures->match( $file->content(), $file->type ) as $match ) {
			$detections[] = self::detection( $match['signature'], $match['line'], $match['excerpt'], $match['signature']['description'] );
		}
		return $detections;
	}

	public static function detection( array $sig, int $line, string $excerpt, string $evidence ): array {
		return array(
			'source'         => 'signature',
			'technique'      => $sig['technique'],
			'signature_id'   => $sig['id'],
			'signature_name' => $sig['name'],
			'family'         => $sig['family'],
			'severity'       => $sig['severity'],
			'confidence'     => $sig['confidence'],
			'verdict'        => Signatures::verdict( (int) $sig['confidence'] ),
			'line'           => $line,
			'excerpt'        => $excerpt,
			'evidence'       => $evidence,
			'remediation'    => $sig['remediation'],
		);
	}
}
