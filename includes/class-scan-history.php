<?php
/**
 * Record of finished, cancelled and failed scans (file and database) for the
 * scan history table, the overview and reports. Bounded to the newest entries.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware;

final class ScanHistory {

	public const OPTION = 'fckmw_scan_history';
	private const MAX   = 100;

	/** @return array<int, array> Newest first. */
	public static function all(): array {
		$items = Store::get( self::OPTION, array() );
		return is_array( $items ) ? array_values( $items ) : array();
	}

	public static function add( array $entry ): void {
		$items = self::all();
		array_unshift( $items, $entry );
		Store::set( self::OPTION, array_slice( $items, 0, self::MAX ) );
	}

	/** Newest entry of a kind/mode (null for any), optionally only completed ones. */
	public static function latest( ?string $mode = null, bool $complete_only = true ): ?array {
		foreach ( self::all() as $item ) {
			if ( ( null === $mode || $mode === ( $item['mode'] ?? '' ) ) && ( ! $complete_only || 'complete' === ( $item['status'] ?? '' ) ) ) {
				return $item;
			}
		}
		return null;
	}

	/** Human-readable scan type. */
	public static function label( string $mode ): string {
		$labels = array(
			'quick'    => __( 'Quick scan', 'fckmaleware' ),
			'standard' => __( 'Full scan', 'fckmaleware' ),
			'deep'     => __( 'Deep scan', 'fckmaleware' ),
			'core'     => __( 'Core integrity', 'fckmaleware' ),
			'recent'   => __( 'Recent changes', 'fckmaleware' ),
			'custom'   => __( 'Custom directory', 'fckmaleware' ),
			'plugins'  => __( 'Plugins & themes', 'fckmaleware' ),
			'uploads'  => __( 'Uploads scan', 'fckmaleware' ),
			'database' => __( 'Database scan', 'fckmaleware' ),
		);
		return $labels[ $mode ] ?? ucfirst( $mode );
	}
}
