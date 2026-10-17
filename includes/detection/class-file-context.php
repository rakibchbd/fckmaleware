<?php
/**
 * One file under inspection. Content and hashes are loaded lazily so layers
 * that only need metadata (or a hash) do not force a full read.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

final class FileContext {

	/** @var string Path relative to the WordPress root, "/" separated. */
	public $relative;

	/** @var string */
	public $absolute;

	/** @var string|null Signature target type (php, js, html, htaccess, ini, image). */
	public $type;

	/** @var int */
	public $size;

	/** @var int */
	public $mtime;

	/** @var bool Set by the integrity layer when the file matches an official checksum. */
	public $verified = false;

	/** @var bool File belongs to FCK Malware itself (integrity-checked only). */
	public $own = false;

	/** @var string|null */
	private $content;

	/** @var string|null */
	private $sha256;

	/** @var string|null */
	private $md5;

	public function __construct( string $relative, string $absolute, ?string $type, int $size, int $mtime ) {
		$this->relative = $relative;
		$this->absolute = $absolute;
		$this->type     = $type;
		$this->size     = $size;
		$this->mtime    = $mtime;
	}

	/** Build from a file on disk (used outside the scanner, e.g. upload checks). */
	public static function from_path( string $relative, string $absolute, ?string $type ): self {
		return new self( $relative, $absolute, $type, (int) @filesize( $absolute ), (int) @filemtime( $absolute ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/** Content for in-memory analysis (e.g. database values or test input). */
	public static function from_string( string $relative, string $content, ?string $type ): self {
		$context          = new self( $relative, '', $type, strlen( $content ), 0 );
		$context->content = $content;
		return $context;
	}

	public function content(): string {
		if ( null === $this->content ) {
			$read          = '' === $this->absolute ? false : @file_get_contents( $this->absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			$this->content = false === $read ? '' : $read;
		}
		return $this->content;
	}

	public function sha256(): string {
		if ( null === $this->sha256 ) {
			$this->sha256 = null !== $this->content || '' === $this->absolute
				? hash( 'sha256', $this->content() )
				: (string) @hash_file( 'sha256', $this->absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		return $this->sha256;
	}

	public function md5(): string {
		if ( null === $this->md5 ) {
			$this->md5 = null !== $this->content || '' === $this->absolute
				? md5( $this->content() )
				: (string) @md5_file( $this->absolute ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		return $this->md5;
	}

	/** Drop the loaded content to free memory once all layers have run. */
	public function release(): void {
		$this->content = null;
	}
}
