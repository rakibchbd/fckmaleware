<?php
/**
 * Base class for admin pages.
 *
 * @package Fckmaleware\Admin
 */

namespace Fckmaleware\Admin\Pages;

use Fckmaleware\Plugin;

abstract class Page {

	/** @var Plugin */
	protected $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	abstract public function render( string $title ): void;

	/** @return mixed */
	protected static function query( string $key, $default = '' ) {
		return isset( $_GET[ $key ] ) ? wp_unslash( $_GET[ $key ] ) : $default; // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- read-only navigation; callers sanitize.
	}
}
