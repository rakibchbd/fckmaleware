/* global fckmw */
( function () {
	'use strict';

	function format( template, values ) {
		return template.replace( /%(\d)\$d/g, function ( _, n ) {
			return String( values[ Number( n ) - 1 ] );
		} );
	}

	function post( action, data ) {
		const body = new URLSearchParams( Object.assign( { action: action, _ajax_nonce: fckmw.nonce }, data || {} ) );
		return fetch( fckmw.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( response ) {
				return response.json().catch( function () {
					throw new Error( fckmw.i18n.network );
				} );
			} )
			.then( function ( json ) {
				if ( ! json || ! json.success ) {
					throw new Error( ( json && json.data && json.data.message ) || fckmw.i18n.network );
				}
				return json.data;
			} );
	}

	// Confirmation for destructive or impactful buttons.
	document.addEventListener( 'click', function ( event ) {
		const button = event.target.closest( '[data-confirm]' );
		if ( button && ! window.confirm( button.getAttribute( 'data-confirm' ) ) ) {
			event.preventDefault();
		}
	} );

	// Select-all checkbox in the findings table.
	document.querySelectorAll( '.fckmw-check-all' ).forEach( function ( all ) {
		all.addEventListener( 'change', function () {
			document.querySelectorAll( 'input[name="ids[]"]' ).forEach( function ( box ) {
				box.checked = all.checked;
			} );
		} );
	} );

	document.querySelectorAll( '.fckmw-print' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			window.print();
		} );
	} );

	// --- File scan ------------------------------------------------------------

	const form = document.getElementById( 'fckmw-scan-form' );
	const progress = document.getElementById( 'fckmw-scan-progress' );

	if ( form && progress ) {
		const bar = progress.querySelector( '.fckmw-bar' );
		const text = progress.querySelector( '.fckmw-live-text' );
		const cancel = document.getElementById( 'fckmw-scan-cancel' );
		let stopped = false;

		const showOptions = function () {
			const mode = form.querySelector( 'input[name="mode"]:checked' ).value;
			form.querySelectorAll( '.fckmw-mode-option' ).forEach( function ( option ) {
				option.hidden = option.getAttribute( 'data-mode' ) !== mode;
			} );
		};
		form.addEventListener( 'change', showOptions );
		showOptions();

		const render = function ( state ) {
			if ( 'listing' === state.phase ) {
				bar.classList.add( 'fckmw-bar-indeterminate' );
				bar.style.width = '';
				text.textContent = fckmw.i18n.starting + ' (' + state.total + ')';
				return;
			}
			const total = state.total || 0;
			bar.classList.remove( 'fckmw-bar-indeterminate' );
			bar.style.width = ( total ? Math.round( ( 100 * state.position ) / total ) : 0 ) + '%';
			text.textContent = format( fckmw.i18n.scanning, [ state.position, total, state.found ] );
		};

		const fail = function ( error ) {
			text.textContent = fckmw.i18n.error + ' ' + error.message;
			cancel.hidden = true;
			form.hidden = false;
		};

		const step = function () {
			if ( stopped ) {
				return;
			}
			post( 'fckmw_scan_step' )
				.then( function ( state ) {
					if ( 'running' === state.status ) {
						render( state );
						step();
					} else if ( 'complete' === state.status ) {
						bar.style.width = '100%';
						text.textContent = fckmw.i18n.done;
						window.location.reload();
					} else {
						text.textContent = fckmw.i18n.cancelled;
						form.hidden = false;
					}
				} )
				.catch( fail );
		};

		form.addEventListener( 'submit', function ( event ) {
			event.preventDefault();
			const data = new FormData( form );
			stopped = false;
			form.hidden = true;
			progress.hidden = false;
			cancel.hidden = false;
			text.textContent = fckmw.i18n.starting;
			post( 'fckmw_scan_start', { mode: data.get( 'mode' ), scope: data.get( 'scope' ) || '', days: data.get( 'days' ) || '7' } )
				.then( function ( state ) {
					render( state );
					step();
				} )
				.catch( fail );
		} );

		cancel.addEventListener( 'click', function () {
			stopped = true;
			post( 'fckmw_scan_cancel' )
				.then( function () {
					window.location.reload();
				} )
				.catch( fail );
		} );

		// Resume driving a scan that is already running (e.g. after a reload).
		if ( 'running' === fckmw.scan ) {
			step();
		}
	}

	// --- Database scan ----------------------------------------------------------

	const dbButton = document.getElementById( 'fckmw-db-start' );
	const dbProgress = document.getElementById( 'fckmw-db-progress' );

	if ( dbButton && dbProgress ) {
		const dbText = dbProgress.querySelector( '.fckmw-live-text' );

		const dbFail = function ( error ) {
			dbText.textContent = fckmw.i18n.error + ' ' + error.message;
			dbButton.hidden = false;
		};

		const dbStep = function () {
			post( 'fckmw_db_step' )
				.then( function ( state ) {
					dbText.textContent = format( fckmw.i18n.dbScanning, [ state.rows, state.found ] );
					if ( 'running' === state.status ) {
						dbStep();
					} else {
						dbText.textContent = fckmw.i18n.done;
						window.location.reload();
					}
				} )
				.catch( dbFail );
		};

		dbButton.addEventListener( 'click', function () {
			dbButton.hidden = true;
			dbProgress.hidden = false;
			dbText.textContent = fckmw.i18n.starting;
			post( 'fckmw_db_start' ).then( dbStep ).catch( dbFail );
		} );

		if ( 'running' === fckmw.dbScan ) {
			dbStep();
		}
	}
}() );
