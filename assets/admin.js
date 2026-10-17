/* global jQuery, fckmw */
( function ( $ ) {
	'use strict';

	const $start = $( '#fckmw-scan-start' );
	const $cancel = $( '#fckmw-scan-cancel' );
	const $progress = $( '.fckmw-progress' );
	const $bar = $( '.fckmw-bar' );
	const $status = $( '.fckmw-status' );

	function call( action ) {
		return $.post( fckmw.ajaxUrl, { action: action, _ajax_nonce: fckmw.nonce } );
	}

	function format( template, values ) {
		return template.replace( /%(\d)\$d/g, function ( _, n ) {
			return values[ Number( n ) - 1 ];
		} );
	}

	function render( state ) {
		const total = state.total || 0;
		const pct = total ? Math.round( ( state.position / total ) * 100 ) : 0;
		$progress.prop( 'hidden', false );
		$bar.css( 'width', pct + '%' );
		$status.text( format( fckmw.i18n.scanning, [ state.position, total, state.found ] ) );
	}

	function fail( message ) {
		$status.text( fckmw.i18n.error + ' ' + message );
		$start.prop( 'disabled', false );
		$cancel.prop( 'hidden', true );
	}

	function loop() {
		$start.prop( 'disabled', true );
		$cancel.prop( 'hidden', false );
		call( 'fckmw_scan_step' )
			.done( function ( res ) {
				if ( ! res.success ) {
					return fail( res.data && res.data.message );
				}
				render( res.data );
				if ( res.data.status === 'running' ) {
					setTimeout( loop, 150 );
				} else {
					$status.text( fckmw.i18n.done );
					window.location.reload();
				}
			} )
			.fail( function ( xhr ) {
				fail( xhr.status + ' ' + xhr.statusText );
			} );
	}

	$start.on( 'click', function () {
		$start.prop( 'disabled', true );
		$status.text( fckmw.i18n.starting );
		call( 'fckmw_scan_start' )
			.done( function ( res ) {
				if ( ! res.success ) {
					return fail( res.data && res.data.message );
				}
				render( res.data );
				loop();
			} )
			.fail( function ( xhr ) {
				fail( xhr.status + ' ' + xhr.statusText );
			} );
	} );

	$cancel.on( 'click', function () {
		call( 'fckmw_scan_cancel' ).always( function () {
			window.location.reload();
		} );
	} );

	$( document ).on( 'submit', 'form', function ( e ) {
		const $btn = $( this ).find( 'button' );
		if ( $btn.hasClass( 'fckmw-confirm' ) && ! window.confirm( fckmw.i18n.confirmQ ) ) {
			e.preventDefault();
		}
		if ( $btn.hasClass( 'fckmw-confirm-delete' ) && ! window.confirm( fckmw.i18n.confirmDel ) ) {
			e.preventDefault();
		}
	} );

	// Resume the progress display if a scan is already running (e.g. after a reload).
	if ( $start.length && fckmw.state && fckmw.state.status === 'running' ) {
		render( fckmw.state );
		loop();
	}
} )( jQuery );
