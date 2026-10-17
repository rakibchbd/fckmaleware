<?php
/**
 * Runs the detection layers over a file in a fixed order:
 *
 *   integrity → location → signature → heuristic
 *
 * Files verified against official checksums, and FCK Malware's own files,
 * only go through the integrity layer.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Signatures;

final class Engine {

	public const VERSION = '1.0.0';

	/** @var IntegrityLayer|null */
	private $integrity;

	/** @var Layer[] Layers that run on unverified files. */
	private $layers;

	/** @var string */
	private $fingerprint;

	/** @var Signatures */
	private $signatures;

	/**
	 * @param Layer[] $layers
	 */
	public function __construct( Signatures $signatures, ?IntegrityLayer $integrity, array $layers, string $settings_fingerprint = '' ) {
		$this->signatures  = $signatures;
		$this->integrity   = $integrity;
		$this->layers      = $layers;
		$this->fingerprint = substr( sha1( self::VERSION . '|' . $signatures->version() . '|' . Heuristics::VERSION . '|' . $settings_fingerprint ), 0, 16 );
	}

	/** Changes whenever detection logic, signatures or relevant settings change; used by the file cache. */
	public function fingerprint(): string {
		return $this->fingerprint;
	}

	public function signatures(): Signatures {
		return $this->signatures;
	}

	public function integrity(): ?IntegrityLayer {
		return $this->integrity;
	}

	/** @return array<int, array<string, mixed>> */
	public function inspect( FileContext $file ): array {
		$detections = array();
		if ( null !== $this->integrity ) {
			$detections = $this->integrity->inspect( $file );
		}
		if ( $file->verified || $file->own ) {
			return $detections;
		}
		foreach ( $this->layers as $layer ) {
			foreach ( $layer->inspect( $file ) as $detection ) {
				$detections[] = $detection;
			}
		}
		return $detections;
	}
}
