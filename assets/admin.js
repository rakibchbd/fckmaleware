/* global fckmw */
( function () {
	'use strict';

	const i18n = fckmw.i18n;

	function format( template, values ) {
		return template.replace( /%(\d)\$d/g, function ( _, n ) {
			return String( values[ Number( n ) - 1 ] );
		} );
	}

	function post( action, data, nonce ) {
		const body = new URLSearchParams();
		body.append( 'action', action );
		body.append( '_ajax_nonce', nonce || fckmw.nonce );
		Object.keys( data || {} ).forEach( function ( key ) {
			const value = data[ key ];
			if ( Array.isArray( value ) ) {
				value.forEach( function ( item ) {
					body.append( key + '[]', item );
				} );
			} else if ( value && 'object' === typeof value ) {
				Object.keys( value ).forEach( function ( inner ) {
					body.append( key + '[' + inner + ']', value[ inner ] );
				} );
			} else {
				body.append( key, value );
			}
		} );
		return fetch( fckmw.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( response ) {
				return response.json().catch( function () {
					throw new Error( i18n.network );
				} );
			} )
			.then( function ( json ) {
				if ( ! json || ! json.success ) {
					throw new Error( ( json && json.data && json.data.message ) || i18n.network );
				}
				return json.data;
			} );
	}

	function el( tag, attrs, text ) {
		const node = document.createElement( tag );
		Object.keys( attrs || {} ).forEach( function ( key ) {
			node.setAttribute( key, attrs[ key ] );
		} );
		if ( undefined !== text ) {
			node.textContent = text;
		}
		return node;
	}

	function duration( seconds ) {
		seconds = Math.max( 0, Math.round( seconds ) );
		const m = Math.floor( seconds / 60 );
		const s = seconds % 60;
		return m ? m + 'm ' + s + 's' : s + 's';
	}

	// --- Confirmation dialog -------------------------------------------------
	// One accessible <dialog> replaces window.confirm(). Esc and Cancel close it
	// and focus returns to the button that opened it.

	const dialog = el( 'dialog', { class: 'fckmw-dialog', 'aria-labelledby': 'fckmw-dialog-title' } );
	dialog.innerHTML = '<form method="dialog"><div class="fckmw-dialog-body"><h2 class="fckmw-dialog-title" id="fckmw-dialog-title"></h2><p class="fckmw-dialog-message"></p><div class="fckmw-dialog-extra"></div></div><div class="fckmw-dialog-foot"><button value="cancel" class="button fckmw-dialog-cancel"></button><button value="ok" class="button button-primary fckmw-dialog-confirm"></button></div></form>';
	document.body.appendChild( dialog );
	dialog.querySelector( '.fckmw-dialog-cancel' ).textContent = i18n.cancel;

	function ask( options ) {
		return new Promise( function ( resolve ) {
			const opener = document.activeElement;
			dialog.classList.toggle( 'fckmw-dialog-danger', !! options.danger );
			dialog.querySelector( '.fckmw-dialog-title' ).textContent = options.title || i18n.areYouSure;
			dialog.querySelector( '.fckmw-dialog-message' ).textContent = options.message || '';
			const extra = dialog.querySelector( '.fckmw-dialog-extra' );
			extra.innerHTML = '';
			if ( options.extra ) {
				extra.appendChild( options.extra );
			}
			const confirm = dialog.querySelector( '.fckmw-dialog-confirm' );
			confirm.textContent = options.confirm || i18n.confirm;
			confirm.hidden = !! options.noConfirm;
			dialog.querySelector( '.fckmw-dialog-cancel' ).textContent = options.noConfirm ? i18n.close : i18n.cancel;
			dialog.returnValue = '';
			const done = function () {
				dialog.removeEventListener( 'close', done );
				if ( opener && opener.focus ) {
					opener.focus();
				}
				resolve( 'ok' === dialog.returnValue );
			};
			dialog.addEventListener( 'close', done );
			if ( 'function' === typeof dialog.showModal ) {
				dialog.showModal();
				( options.noConfirm ? dialog.querySelector( '.fckmw-dialog-cancel' ) : confirm ).focus();
			} else {
				// Very old browsers: fall back to the native prompt.
				dialog.removeEventListener( 'close', done );
				resolve( window.confirm( ( options.title ? options.title + '\n\n' : '' ) + ( options.message || '' ) ) );
			}
		} );
	}

	document.addEventListener( 'click', function ( event ) {
		const button = event.target.closest( '[data-confirm]' );
		if ( ! button || button.dataset.confirmed ) {
			return;
		}
		event.preventDefault();
		ask( {
			title: button.getAttribute( 'data-confirm-label' ) || button.textContent.trim(),
			message: button.getAttribute( 'data-confirm' ),
			confirm: button.getAttribute( 'data-confirm-label' ) || button.textContent.trim(),
			danger: button.classList.contains( 'button-link-delete' ),
		} ).then( function ( ok ) {
			if ( ! ok ) {
				return;
			}
			button.dataset.confirmed = '1';
			if ( button.form && button.form.requestSubmit ) {
				button.form.requestSubmit( button );
			} else {
				button.click();
			}
			delete button.dataset.confirmed;
		} );
	} );

	document.querySelectorAll( '.fckmw-print' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			window.print();
		} );
	} );

	document.querySelectorAll( '[data-fckmw-copy]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			const source = document.getElementById( button.getAttribute( 'data-fckmw-copy' ) );
			if ( source && navigator.clipboard ) {
				navigator.clipboard.writeText( source.textContent ).then( function () {
					button.textContent = button.getAttribute( 'data-copied' ) || button.textContent;
				} );
			}
		} );
	} );

	// --- Quick scan buttons (overview) -----------------------------------------
	// Start a scan through AJAX, then open the scanner, which follows its progress.

	document.querySelectorAll( '[data-fckmw-scan]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function ( event ) {
			event.preventDefault();
			button.disabled = true;
			const mode = button.getAttribute( 'data-fckmw-scan' );
			const go = function () {
				window.location.href = button.getAttribute( 'data-href' );
			};
			if ( 'database' === mode ) {
				post( 'fckmw_db_start' ).then( go ).catch( function ( error ) {
					button.disabled = false;
					ask( { title: i18n.error, message: error.message, noConfirm: true } );
				} );
				return;
			}
			post( 'fckmw_scan_start', { mode: mode } ).then( go ).catch( function ( error ) {
				button.disabled = false;
				ask( { title: i18n.error, message: error.message, noConfirm: true } );
			} );
		} );
	} );

	// --- File scan -------------------------------------------------------------

	const form = document.getElementById( 'fckmw-scan-form' );
	const progress = document.getElementById( 'fckmw-scan-progress' );

	if ( form && progress ) {
		const bar = progress.querySelector( '.fckmw-bar' );
		const text = progress.querySelector( '.fckmw-live-text' );
		const cancel = document.getElementById( 'fckmw-scan-cancel' );
		const field = function ( name ) {
			return progress.querySelector( '[data-stat="' + name + '"]' );
		};
		let stopped = false;
		let offset = 0;

		const showOptions = function () {
			const checked = form.querySelector( 'input[name="mode"]:checked' );
			form.querySelectorAll( '.fckmw-mode-option' ).forEach( function ( option ) {
				option.hidden = ! checked || option.getAttribute( 'data-mode' ) !== checked.value;
			} );
		};
		form.addEventListener( 'change', showOptions );
		showOptions();

		const render = function ( state ) {
			if ( state.now ) {
				offset = Date.now() / 1000 - state.now;
			}
			if ( field( 'files' ) ) {
				field( 'files' ).textContent = ( state.position || 0 ) + ' / ' + ( state.total || 0 );
				field( 'skipped' ).textContent = state.skipped || 0;
				field( 'found' ).textContent = state.found || 0;
				field( 'errors' ).textContent = state.errors || 0;
				field( 'elapsed' ).textContent = state.started ? duration( Date.now() / 1000 - offset - state.started ) : '—';
			}
			if ( 'listing' === state.phase ) {
				bar.classList.add( 'fckmw-bar-indeterminate' );
				bar.style.width = '';
				text.textContent = i18n.starting + ' (' + state.total + ')';
				return;
			}
			const total = state.total || 0;
			bar.classList.remove( 'fckmw-bar-indeterminate' );
			bar.style.width = ( total ? Math.round( ( 100 * state.position ) / total ) : 0 ) + '%';
			text.textContent = format( i18n.scanning, [ state.position, total, state.found ] );
		};

		const fail = function ( error ) {
			text.textContent = i18n.error + ' ' + error.message;
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
						text.textContent = i18n.done;
						window.location.reload();
					} else {
						text.textContent = i18n.cancelled;
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
			text.textContent = i18n.starting;
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
		const dbCancel = document.getElementById( 'fckmw-db-cancel' );
		let dbStopped = false;

		const dbFail = function ( error ) {
			dbText.textContent = i18n.error + ' ' + error.message;
			dbButton.hidden = false;
		};

		const dbStep = function () {
			if ( dbStopped ) {
				return;
			}
			post( 'fckmw_db_step' )
				.then( function ( state ) {
					dbText.textContent = format( i18n.dbScanning, [ state.rows, state.found ] );
					if ( 'running' === state.status ) {
						dbStep();
					} else {
						dbText.textContent = i18n.done;
						window.location.reload();
					}
				} )
				.catch( dbFail );
		};

		dbButton.addEventListener( 'click', function () {
			dbStopped = false;
			dbButton.hidden = true;
			dbProgress.hidden = false;
			dbText.textContent = i18n.starting;
			post( 'fckmw_db_start' ).then( dbStep ).catch( dbFail );
		} );

		if ( dbCancel ) {
			dbCancel.addEventListener( 'click', function () {
				dbStopped = true;
				post( 'fckmw_db_cancel' ).then( function () {
					window.location.reload();
				} ).catch( dbFail );
			} );
		}

		if ( 'running' === fckmw.dbScan ) {
			dbStep();
		}
	}

	// --- Findings selection -------------------------------------------------------

	const table = document.querySelector( '.fckmw-findings' );
	const boxes = function () {
		return Array.prototype.slice.call( document.querySelectorAll( 'input[name="ids[]"]' ) );
	};
	const selectAllBanner = document.getElementById( 'fckmw-selectall' );
	const bulkForm = document.getElementById( 'fckmw-bulk-form' );
	let allMatching = false;

	const updateSelection = function () {
		const selected = boxes().filter( function ( box ) {
			return box.checked;
		} ).length;
		const count = document.getElementById( 'fckmw-bulk-count' );
		if ( count ) {
			count.textContent = allMatching ? count.getAttribute( 'data-all' ) : count.getAttribute( 'data-template' ).replace( '%d', selected );
		}
		if ( selectAllBanner ) {
			const all = boxes().length > 0 && selected === boxes().length;
			selectAllBanner.hidden = ! all;
			if ( ! all ) {
				allMatching = false;
			}
			selectAllBanner.querySelector( '.fckmw-selectall-page' ).hidden = allMatching;
			selectAllBanner.querySelector( '.fckmw-selectall-all' ).hidden = ! allMatching;
		}
	};

	document.querySelectorAll( '.fckmw-check-all' ).forEach( function ( all ) {
		all.addEventListener( 'change', function () {
			boxes().forEach( function ( box ) {
				box.checked = all.checked;
			} );
			updateSelection();
		} );
	} );
	if ( table ) {
		table.addEventListener( 'change', function ( event ) {
			if ( 'ids[]' === event.target.name ) {
				updateSelection();
			}
		} );
	}
	if ( selectAllBanner ) {
		selectAllBanner.querySelector( '[data-select-all]' ).addEventListener( 'click', function () {
			allMatching = true;
			updateSelection();
		} );
		selectAllBanner.querySelector( '[data-select-page]' ).addEventListener( 'click', function () {
			allMatching = false;
			updateSelection();
		} );
	}

	// --- Bulk jobs ------------------------------------------------------------------

	const jobPanel = document.getElementById( 'fckmw-job' );

	const renderJob = function ( job ) {
		if ( ! jobPanel ) {
			return;
		}
		jobPanel.hidden = false;
		const processed = job.processed || 0;
		const total = Math.max( job.total || 0, processed );
		jobPanel.querySelector( '.fckmw-job-title' ).textContent = job.label || '';
		const bar = jobPanel.querySelector( '.fckmw-bar' );
		bar.style.width = ( 'running' !== job.status || ! total ? 100 : Math.round( ( 100 * processed ) / total ) ) + '%';
		jobPanel.querySelector( '.fckmw-live-text' ).textContent = format( i18n.bulkProgress, [ processed, total, job.succeeded || 0, job.failed || 0, job.skipped || 0 ] ) + ( 'running' === job.status ? '' : ' — ' + ( 'cancelled' === job.status ? i18n.cancelled : i18n.bulkDone ) );
		const list = jobPanel.querySelector( '.fckmw-job-failures' );
		list.innerHTML = '';
		( job.failures || [] ).forEach( function ( failure ) {
			list.appendChild( el( 'li', {}, failure.file + ': ' + failure.message ) );
		} );
		Object.keys( job.reasons || {} ).forEach( function ( reason ) {
			list.appendChild( el( 'li', {}, reason + ' (' + job.reasons[ reason ] + ')' ) );
		} );
		jobPanel.querySelector( '[data-job-cancel]' ).hidden = 'running' !== job.status;
		jobPanel.querySelector( '[data-job-retry]' ).hidden = 'running' === job.status || ! job.recoverable;
		jobPanel.querySelector( '[data-job-reload]' ).hidden = 'running' === job.status;
	};

	const driveJob = function () {
		post( 'fckmw_bulk_step', {}, fckmw.bulkNonce )
			.then( function ( job ) {
				renderJob( job );
				if ( 'running' === job.status ) {
					driveJob();
				}
			} )
			.catch( function ( error ) {
				if ( jobPanel ) {
					jobPanel.querySelector( '.fckmw-live-text' ).textContent = i18n.error + ' ' + error.message;
				}
			} );
	};

	const previewList = function ( preview ) {
		const wrap = el( 'div' );
		const reasons = Object.keys( preview.reasons || {} );
		if ( preview.sample && preview.sample.length ) {
			const sample = el( 'ul' );
			preview.sample.forEach( function ( file ) {
				sample.appendChild( el( 'li', {}, file ) );
			} );
			wrap.appendChild( sample );
		}
		if ( reasons.length ) {
			const skipped = el( 'ul' );
			reasons.forEach( function ( reason ) {
				skipped.appendChild( el( 'li', {}, reason + ' (' + preview.reasons[ reason ] + ')' ) );
			} );
			wrap.appendChild( skipped );
		}
		return wrap;
	};

	const runBulk = function ( selection, labels ) {
		if ( jobPanel ) {
			jobPanel.hidden = false;
			jobPanel.querySelector( '.fckmw-live-text' ).textContent = i18n.previewing;
		}
		post( 'fckmw_bulk_preview', selection, fckmw.bulkNonce )
			.then( function ( preview ) {
				if ( jobPanel ) {
					jobPanel.hidden = true;
				}
				const message = labels.message
					.replace( '%1$d', preview.eligible )
					.replace( '%2$d', preview.total )
					.replace( '%3$d', preview.skipped );
				return ask( {
					title: labels.title,
					message: message,
					extra: previewList( preview ),
					confirm: preview.eligible ? labels.confirm : '',
					noConfirm: ! preview.eligible,
					danger: 'quarantine' === selection.op,
				} );
			} )
			.then( function ( ok ) {
				if ( ! ok ) {
					return null;
				}
				return post( 'fckmw_bulk_start', selection, fckmw.bulkNonce ).then( function ( job ) {
					renderJob( job );
					driveJob();
				} );
			} )
			.catch( function ( error ) {
				ask( { title: i18n.error, message: error.message, noConfirm: true } );
			} );
	};

	if ( bulkForm ) {
		bulkForm.addEventListener( 'submit', function ( event ) {
			event.preventDefault();
			const op = bulkForm.querySelector( '[name="op"]' ).value;
			const ids = boxes().filter( function ( box ) {
				return box.checked;
			} ).map( function ( box ) {
				return box.value;
			} );
			if ( ! op || ( ! allMatching && ! ids.length ) ) {
				ask( { title: i18n.areYouSure, message: i18n.selectFirst, noConfirm: true } );
				return;
			}
			const attrs = document.getElementById( 'fckmw-bulk-attrs' );
			const filters = JSON.parse( ( attrs && attrs.getAttribute( 'data-filters' ) ) || '{}' );
			const option = bulkForm.querySelector( '[name="op"] option:checked' );
			runBulk(
				allMatching ? { op: op, mode: 'filters', filters: filters } : { op: op, mode: 'ids', ids: ids },
				{ title: option.textContent, message: ( attrs && attrs.getAttribute( 'data-preview' ) ) || '', confirm: option.textContent }
			);
		} );
	}

	document.querySelectorAll( '[data-fckmw-bulk-eligible]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function ( event ) {
			event.preventDefault();
			if ( ! jobPanel ) {
				window.location.href = button.getAttribute( 'data-href' );
				return;
			}
			const menu = button.closest( 'details.fckmw-menu' );
			if ( menu ) {
				menu.open = false;
			}
			const title = ( button.querySelector( 'strong' ) || button ).textContent.trim();
			runBulk( { op: 'quarantine', mode: 'eligible', scope: button.getAttribute( 'data-scope' ) || 'eligible' }, { title: title, message: button.getAttribute( 'data-preview' ), confirm: title } );
		} );
	} );

	if ( jobPanel ) {
		jobPanel.querySelector( '[data-job-cancel]' ).addEventListener( 'click', function () {
			post( 'fckmw_bulk_cancel', {}, fckmw.bulkNonce ).then( renderJob );
		} );
		jobPanel.querySelector( '[data-job-retry]' ).addEventListener( 'click', function () {
			post( 'fckmw_bulk_retry', {}, fckmw.bulkNonce ).then( function ( job ) {
				renderJob( job );
				driveJob();
			} ).catch( function ( error ) {
				ask( { title: i18n.error, message: error.message, noConfirm: true } );
			} );
		} );
		jobPanel.querySelector( '[data-job-reload]' ).addEventListener( 'click', function () {
			window.location.reload();
		} );
		if ( 'running' === fckmw.bulkJob ) {
			driveJob();
		}
	}

	// Quarantine menu: close on Escape or a click outside.
	document.addEventListener( 'click', function ( event ) {
		document.querySelectorAll( 'details.fckmw-menu[open]' ).forEach( function ( menu ) {
			if ( ! menu.contains( event.target ) ) {
				menu.open = false;
			}
		} );
	} );
	document.addEventListener( 'keydown', function ( event ) {
		if ( 'Escape' === event.key ) {
			document.querySelectorAll( 'details.fckmw-menu[open]' ).forEach( function ( menu ) {
				menu.open = false;
				menu.querySelector( 'summary' ).focus();
			} );
		}
	} );

	// Select-all for other checkbox tables (quarantine).
	document.querySelectorAll( '[data-check-all]' ).forEach( function ( all ) {
		all.addEventListener( 'change', function () {
			document.querySelectorAll( 'input[name="' + all.getAttribute( 'data-check-all' ) + '"]' ).forEach( function ( box ) {
				box.checked = all.checked;
			} );
		} );
	} );
}() );
