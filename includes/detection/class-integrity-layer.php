<?php
/**
 * Layer C: WordPress integrity.
 *
 * - Core files against official WordPress.org checksums.
 * - wordpress.org plugins against their published checksums.
 * - Everything else (themes, premium plugins, mu-plugins, drop-ins and
 *   important configuration files) against a local baseline.
 * - FCK Malware's own files against the manifest shipped in the package.
 *
 * Files that match an official checksum are marked verified, and the
 * signature and heuristic layers skip them.
 *
 * @package Fckmaleware
 */

namespace Fckmaleware\Detection;

use Fckmaleware\Paths;

final class IntegrityLayer implements Layer {

	private const CONFIG_FILES = array( 'wp-config.php', '.htaccess', '.user.ini', 'php.ini' );

	/** @var Checksums */
	private $checksums;

	/** @var Baseline */
	private $baseline;

	/** @var bool */
	private $core_enabled;

	/** @var bool */
	private $plugins_enabled;

	/** @var string FCK Malware's directory relative to the root, with trailing slash. */
	private $own_dir;

	/**
	 * Components being baselined during the current scan (component@version => true).
	 * Persisted in the scan state by the scanner between steps.
	 *
	 * @var array<string, bool>|null Null when this inspection may not record baselines (single-file checks).
	 */
	private $recording;

	public function __construct( Checksums $checksums, Baseline $baseline, bool $core, bool $plugins, ?array $recording = null ) {
		$this->checksums       = $checksums;
		$this->baseline        = $baseline;
		$this->core_enabled    = $core;
		$this->plugins_enabled = $plugins;
		$this->recording       = $recording;
		$own                   = Paths::relative( (string) realpath( FCKMW_DIR ) );
		$this->own_dir         = null === $own ? '' : trailingslashit( $own );
	}

	public function id(): string {
		return 'integrity';
	}

	/** @return array<string, bool>|null */
	public function recording(): ?array {
		return $this->recording;
	}

	public function is_own( string $relative ): bool {
		return '' !== $this->own_dir && 0 === strpos( $relative, $this->own_dir );
	}

	public function inspect( FileContext $file ): array {
		$rel = $file->relative;

		if ( $this->is_own( $rel ) ) {
			$file->own = true;
			return $this->inspect_own( $file );
		}

		if ( 0 !== strpos( $rel, 'wp-content/' ) && ! in_array( $rel, self::CONFIG_FILES, true ) ) {
			return $this->core_enabled ? $this->inspect_core( $file ) : array();
		}

		$component = $this->component( $rel );
		if ( null === $component ) {
			return array();
		}
		list( $name, $version, $inner ) = $component;

		if ( $this->plugins_enabled && 0 === strpos( $name, 'plugin:' ) && '' !== $version ) {
			$official = $this->checksums->plugin( substr( $name, 7 ), $version );
			if ( null !== $official ) {
				return $this->inspect_official_plugin( $file, $official, $inner );
			}
		}
		return $this->inspect_baseline( $file, $name, $version );
	}

	/** @return string[] Core PHP files listed in the official checksums but missing on disk. */
	public function missing_core_files(): array {
		if ( ! $this->core_enabled ) {
			return array();
		}
		$root    = Paths::root();
		$missing = array();
		foreach ( array_keys( $this->checksums->core() ) as $rel ) {
			if ( 0 === strpos( $rel, 'wp-content/' ) || '.php' !== substr( $rel, -4 ) || 'wp-config-sample.php' === $rel ) {
				continue;
			}
			if ( ! file_exists( $root . $rel ) ) {
				$missing[] = $rel;
			}
		}
		return $missing;
	}

	// --- Core -----------------------------------------------------------------

	private function inspect_core( FileContext $file ): array {
		$core = $this->checksums->core();
		if ( ! $core ) {
			return array();
		}
		$rel = $file->relative;
		if ( isset( $core[ $rel ] ) ) {
			if ( hash_equals( $core[ $rel ], $file->md5() ) ) {
				$file->verified = true;
				return array();
			}
			return array(
				self::detection( 'FMW-INT-001', __( 'Modified WordPress core file', 'fckmaleware' ), 'Integrity.Core.Modified', 'high', 70, __( 'The file differs from the official WordPress.org checksum for this version and locale.', 'fckmaleware' ), 'repair' ),
			);
		}
		if ( 'php' === $file->type && Paths::is_core( $rel ) ) {
			return array(
				self::detection( 'FMW-INT-002', __( 'Unknown PHP file in WordPress core directory', 'fckmaleware' ), 'Integrity.Core.Unknown', 'high', 70, __( 'This PHP file is not part of WordPress but sits in a core directory, where nothing else should be added.', 'fckmaleware' ), 'quarantine' ),
			);
		}
		return array();
	}

	// --- wordpress.org plugins -----------------------------------------------

	private function inspect_official_plugin( FileContext $file, array $official, string $inner ): array {
		if ( isset( $official[ $inner ] ) ) {
			if ( in_array( $file->sha256(), $official[ $inner ], true ) ) {
				$file->verified = true;
				return array();
			}
			return array(
				self::detection( 'FMW-INT-010', __( 'Modified plugin file', 'fckmaleware' ), 'Integrity.Plugin.Modified', 'high', 65, __( 'The file differs from the checksum published on wordpress.org for this plugin version.', 'fckmaleware' ), 'repair' ),
			);
		}
		if ( 'php' === $file->type ) {
			return array(
				self::detection( 'FMW-INT-011', __( 'Unexpected PHP file in plugin', 'fckmaleware' ), 'Integrity.Plugin.Unexpected', 'medium', 55, __( 'This PHP file is not part of the plugin release published on wordpress.org. Some plugins write their own configuration files; others are injected.', 'fckmaleware' ), 'review' ),
			);
		}
		return array();
	}

	// --- Local baselines ------------------------------------------------------

	private function inspect_baseline( FileContext $file, string $component, string $version ): array {
		$key = $component . '@' . $version;

		if ( null !== $this->recording && ( isset( $this->recording[ $key ] ) || ! $this->baseline->has( $component, $version ) ) ) {
			if ( ! isset( $this->recording[ $key ] ) ) {
				// First sight of this component version: replace any older baseline.
				$this->baseline->forget( $component );
				$this->recording[ $key ] = true;
			}
			$this->baseline->set( $file->relative, $component, $version, $file->sha256() );
			$this->baseline->mark_known( $component, $version );
			return array();
		}
		if ( ! $this->baseline->has( $component, $version ) ) {
			return array(); // No baseline yet and not allowed to record one here.
		}

		$row = $this->baseline->get( $file->relative );
		if ( null === $row ) {
			if ( 'php' !== $file->type ) {
				return array();
			}
			return array(
				self::detection( 'FMW-INT-021', __( 'New PHP file since baseline', 'fckmaleware' ), 'Integrity.Baseline.NewFile', 'medium', 50, sprintf( /* translators: %s: component */ __( 'This PHP file appeared in %s after its baseline was recorded, while the version stayed the same.', 'fckmaleware' ), $component ), 'review' ),
			);
		}
		if ( hash_equals( (string) $row['sha256'], $file->sha256() ) ) {
			return array();
		}
		$when = gmdate( 'Y-m-d', (int) $row['recorded_at'] );
		if ( 'config' === $component ) {
			return array(
				self::detection( 'FMW-INT-022', __( 'Configuration file changed', 'fckmaleware' ), 'Integrity.Config.Changed', 'medium', 45, sprintf( /* translators: %s: date */ __( 'The file changed since its baseline was recorded on %s. Review the change; accept it if you made it.', 'fckmaleware' ), $when ), 'review' ),
			);
		}
		return array(
			self::detection( 'FMW-INT-020', __( 'File changed since baseline', 'fckmaleware' ), 'Integrity.Baseline.Changed', 'medium', 50, sprintf( /* translators: 1: component, 2: date */ __( 'This file in %1$s changed after its baseline was recorded on %2$s, while the version stayed the same.', 'fckmaleware' ), $component, $when ), 'review' ),
		);
	}

	/**
	 * @return array{0: string, 1: string, 2: string}|null [component, version, path inside component]
	 */
	public function component( string $rel ): ?array {
		if ( in_array( $rel, self::CONFIG_FILES, true ) ) {
			return array( 'config', '', $rel );
		}
		$parts = explode( '/', $rel );
		if ( 'wp-content' !== $parts[0] || count( $parts ) < 2 ) {
			return null;
		}
		if ( 2 === count( $parts ) ) {
			return array( 'dropins', '', $parts[1] );
		}
		switch ( $parts[1] ) {
			case 'plugins':
				if ( 3 === count( $parts ) ) {
					$slug = $parts[2];
					return array( 'plugin:' . $slug, $this->checksums->installed_plugins()[ $slug ] ?? '', $slug );
				}
				$slug = $parts[2];
				return array( 'plugin:' . $slug, $this->checksums->installed_plugins()[ $slug ] ?? '', implode( '/', array_slice( $parts, 3 ) ) );
			case 'themes':
				if ( count( $parts ) < 4 ) {
					return null;
				}
				return array( 'theme:' . $parts[2], $this->checksums->theme_version( $parts[2] ), implode( '/', array_slice( $parts, 3 ) ) );
			case 'mu-plugins':
				return array( 'mu-plugins', '', implode( '/', array_slice( $parts, 2 ) ) );
		}
		return null;
	}

	// --- FCK Malware itself ---------------------------------------------------

	private function inspect_own( FileContext $file ): array {
		$manifest = $this->checksums->own();
		if ( null === $manifest ) {
			return array(); // Development checkout without a release manifest.
		}
		$inner = substr( $file->relative, strlen( $this->own_dir ) );
		if ( isset( $manifest[ $inner ] ) ) {
			if ( hash_equals( (string) $manifest[ $inner ], $file->sha256() ) ) {
				$file->verified = true;
				return array();
			}
			return array(
				self::detection( 'FMW-INT-030', __( 'FCK Malware file modified', 'fckmaleware' ), 'Integrity.Self.Modified', 'critical', 90, __( 'A file of this security plugin no longer matches its release checksum. Attackers modify security plugins to blind them. Reinstall FCK Malware.', 'fckmaleware' ), 'repair' ),
			);
		}
		if ( 'php' === $file->type ) {
			return array(
				self::detection( 'FMW-INT-031', __( 'Unexpected file in FCK Malware directory', 'fckmaleware' ), 'Integrity.Self.Unexpected', 'high', 75, __( 'This PHP file is not part of the FCK Malware release.', 'fckmaleware' ), 'quarantine' ),
			);
		}
		return array();
	}

	private static function detection( string $id, string $name, string $family, string $severity, int $confidence, string $evidence, string $remediation ): array {
		return array(
			'source'         => 'integrity',
			'signature_id'   => $id,
			'signature_name' => $name,
			'family'         => $family,
			'severity'       => $severity,
			'confidence'     => $confidence,
			'verdict'        => $confidence >= 70 ? 'malicious' : 'suspicious',
			'evidence'       => $evidence,
			'remediation'    => $remediation,
		);
	}
}
