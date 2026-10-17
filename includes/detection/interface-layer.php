<?php
/**
 * A detection layer inspects one file and returns detections.
 *
 * Detections are arrays with the keys Findings::upsert() accepts:
 * source, signature_id, signature_name, family, severity, verdict,
 * confidence, line, excerpt, evidence, remediation.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

interface Layer {

	/** Short identifier stored as the finding source, e.g. "signature". */
	public function id(): string;

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public function inspect( FileContext $file ): array;
}
