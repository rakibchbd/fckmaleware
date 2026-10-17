<?php
/**
 * Location rules: executable files where WordPress never puts them.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

final class LocationLayer implements Layer {

	/** @var string Uploads directory relative to the root, with trailing slash. */
	private $uploads;

	public function __construct( string $uploads_relative ) {
		$this->uploads = $uploads_relative;
	}

	public function id(): string {
		return 'location';
	}

	public function inspect( FileContext $file ): array {
		if ( 'php' !== $file->type ) {
			return array();
		}
		$out = array();

		if ( '' !== $this->uploads && 0 === strpos( $file->relative, $this->uploads ) ) {
			$out[] = array(
				'source'         => 'location',
				'signature_id'   => 'FMW-LOC-001',
				'signature_name' => __( 'PHP file in uploads directory', 'fckmaleware' ),
				'family'         => 'Location.UploadsPhp',
				'severity'       => 'medium',
				'confidence'     => 55,
				'verdict'        => 'suspicious',
				'evidence'       => __( 'WordPress stores media in uploads; executable PHP there is usually a dropped backdoor. A few plugins keep PHP data files in uploads, so check what created it.', 'fckmaleware' ),
				'remediation'    => 'review',
			);
		}

		if ( '.' === basename( $file->relative )[0] ) {
			$out[] = array(
				'source'         => 'location',
				'signature_id'   => 'FMW-LOC-002',
				'signature_name' => __( 'Hidden PHP file', 'fckmaleware' ),
				'family'         => 'Location.HiddenPhp',
				'severity'       => 'medium',
				'confidence'     => 55,
				'verdict'        => 'suspicious',
				'evidence'       => __( 'A PHP file whose name starts with a dot is hidden from directory listings, a common way to conceal backdoors.', 'fckmaleware' ),
				'remediation'    => 'review',
			);
		}
		return $out;
	}
}
