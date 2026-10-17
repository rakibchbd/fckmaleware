<?php
/**
 * Layer B: weighted heuristic analysis of PHP files.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Signatures;

final class HeuristicLayer implements Layer {

	/** @var int */
	private $threshold;

	public function __construct( int $threshold = 60 ) {
		$this->threshold = $threshold;
	}

	public function id(): string {
		return 'heuristic';
	}

	public function inspect( FileContext $file ): array {
		if ( 'php' !== $file->type || $file->size > Heuristics::MAX_BYTES ) {
			return array();
		}
		$content  = $file->content();
		$analysis = Heuristics::analyze( $content );
		$class    = Heuristics::classify( $analysis, $this->threshold );
		if ( ! $class['report'] ) {
			return array();
		}

		$top      = reset( $analysis['indicators'] );
		$evidence = array();
		foreach ( $analysis['indicators'] as $indicator ) {
			$evidence[] = sprintf( '%s (line %d, +%d)', $indicator['description'], $indicator['line'], $indicator['weight'] );
		}

		return array(
			array(
				'source'         => 'heuristic',
				'signature_id'   => 'FMW-HEUR-PHP',
				'signature_name' => sprintf( /* translators: %d: score */ __( 'Suspicious PHP behaviour (score %d)', 'fckmaleware' ), $analysis['score'] ),
				'family'         => 'Heuristic.PHP',
				'severity'       => $class['severity'],
				'confidence'     => $class['confidence'],
				'verdict'        => $class['verdict'],
				'line'           => (int) $top['line'],
				'excerpt'        => self::line_excerpt( $content, (int) $top['line'] ),
				'evidence'       => implode( "\n", $evidence ),
				'remediation'    => 'review',
			),
		);
	}

	private static function line_excerpt( string $content, int $line ): string {
		$lines = explode( "\n", $content, $line + 1 );
		return Signatures::excerpt( (string) ( $lines[ $line - 1 ] ?? '' ), 0, 240, 0 );
	}
}
