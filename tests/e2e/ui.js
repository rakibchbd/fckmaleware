/**
 * End-to-end test of the admin UI with Playwright, against a disposable test site.
 *
 *   FCKMW_SITE=http://127.0.0.1:8099 FCKMW_USER=admin FCKMW_PASS=admin \
 *   FCKMW_SAMPLES=wp-content/e2e-samples node tests/e2e/ui.js /tmp/shots
 *
 * FCKMW_SAMPLES must be a real (not symlinked) directory inside the site holding
 * copies of tests/fixtures/malware and tests/fixtures/clean without the
 * .fixture suffix. The test quarantines and restores files from it, and bulk
 * quarantines the rest; copy the samples again before re-running.
 */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const site = process.env.FCKMW_SITE || 'http://127.0.0.1:8099';
const admin = site + '/wp-admin/admin.php?page=';
const samples = process.env.FCKMW_SAMPLES || 'wp-content/e2e-samples';
const shots = process.argv[2] || require('os').tmpdir();
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
  page.on('dialog', d => { errors.push('native dialog used: ' + d.message()); d.accept(); });
  const ok = (cond, msg) => { console.log((cond ? 'PASS ' : 'FAIL ') + msg); if (!cond) process.exitCode = 1; };
  const confirmDialog = async () => {
    await page.locator('dialog.fckmw-dialog[open]').waitFor();
    await page.locator('dialog.fckmw-dialog[open] .fckmw-dialog-confirm').click();
  };
  const notice = async () => (await page.locator('.fckmw-flash').first().innerText()).trim();

  await page.goto(site + '/wp-login.php');
  await page.fill('#user_login', process.env.FCKMW_USER || 'admin'); await page.fill('#user_pass', process.env.FCKMW_PASS || 'admin');
  await page.click('#wp-submit'); await page.waitForLoadState();

  // Automatic removal is on by default; the manual-review flows below need it off.
  const setAutoRemove = async (on) => {
    await page.goto(admin + 'fckmaleware-protection');
    await page.locator('#fckmw-auto_remove_verified').setChecked(on, { force: true });
    await page.click('button[type=submit]:has-text("Save protection settings")');
    await page.waitForLoadState();
    return page.isChecked('#fckmw-auto_remove_verified');
  };
  ok(await page.goto(admin + 'fckmaleware-protection').then(() => page.isChecked('#fckmw-auto_remove_verified')), 'verified malware removal is on by default');
  ok(!(await setAutoRemove(false)), 'automatic removal can be switched off');

  // Navigation: one menu, five sections, legacy links redirect.
  await page.goto(admin + 'fckmaleware');
  ok(await page.locator('.fckmw-ring').count() === 1, 'overview shows the security score');
  ok(await page.locator('.fckmw-metric').count() === 5, 'overview shows score and four metrics');
  const submenu = await page.locator('#adminmenu .toplevel_page_fckmaleware .wp-submenu a').allInnerTexts();
  ok(submenu.length === 5, 'admin menu has five sections: ' + submenu.join(', '));
  ok(await page.locator('#adminmenu a[href*="page=fckmaleware"]').locator('xpath=ancestor::li[contains(@class,"menu-top")]').count() === 1, 'one top-level FCK menu');
  await page.screenshot({ path: shots + '/overview.png', fullPage: true });
  await page.goto(admin + 'fckmaleware-findings&status=resolved');
  ok(/page=fckmaleware-scan&tab=findings&status=resolved/.test(page.url()), 'legacy findings link redirects to the new tab');

  // Scanner: custom scan through AJAX to completion.
  await page.goto(admin + 'fckmaleware-scan');
  await page.check('input[name=mode][value=custom]');
  ok(await page.locator('.fckmw-mode-option[data-mode=custom]').isVisible(), 'custom mode shows the directory field');
  await page.fill('input[name=scope]', samples);
  await page.click('#fckmw-scan-form button[type=submit]');
  const outcome = await Promise.race([
    page.waitForEvent('load', { timeout: 180000 }).then(() => 'reloaded'),
    page.waitForFunction(() => /Error:/.test(document.querySelector('#fckmw-scan-progress .fckmw-live-text')?.textContent || ''), null, { timeout: 180000 }).then(() => 'error'),
  ]);
  if (outcome === 'error') { console.log('FAIL scan error: ' + await page.locator('#fckmw-scan-progress .fckmw-live-text').innerText()); process.exit(1); }
  await page.waitForLoadState();
  ok(/Custom directory/.test(await page.locator('#history').innerText()), 'scan listed in the scan history');
  await page.screenshot({ path: shots + '/scanner.png', fullPage: true });

  // Findings: quarantine one through the confirmation dialog, restore it.
  await page.goto(admin + 'fckmaleware-scan&tab=findings&source=signature');
  const rows = await page.locator('.fckmw-findings tbody > tr:not(.fckmw-detail-row)').count();
  ok(rows > 0, `findings listed (${rows})`);
  ok(await page.locator('.fckmw-findings .fckmw-badge:has-text("Confirmed malware"), .fckmw-findings .fckmw-badge:has-text("Likely malicious")').count() > 0, 'classification badges shown');
  await page.locator('.fckmw-detail-row summary').first().click();
  const file = (await page.locator('.fckmw-file code').first().innerText()).trim();
  await page.screenshot({ path: shots + '/findings.png', fullPage: false });
  await page.locator('.fckmw-detail-row button:has-text("Quarantine file")').first().click();
  ok(await page.locator('dialog.fckmw-dialog[open]').count() === 1, 'accessible confirmation dialog opens');
  await page.keyboard.press('Escape');
  ok(await page.locator('dialog.fckmw-dialog[open]').count() === 0, 'Escape cancels without acting');
  await page.locator('.fckmw-detail-row button:has-text("Quarantine file")').first().click();
  await confirmDialog();
  await page.waitForLoadState();
  ok(/quarantine/i.test(await notice()), 'quarantine notice: ' + await notice());
  await page.goto(admin + 'fckmaleware-scan&tab=quarantine');
  ok((await page.locator('.fckmw-table').first().innerText()).includes(file), 'quarantined file listed: ' + file);
  await page.screenshot({ path: shots + '/quarantine.png', fullPage: true });
  await page.locator(`tr:has-text("${file}") button:has-text("Restore")`).first().click();
  await confirmDialog();
  await page.waitForLoadState();
  ok(/restored/i.test(await notice()), 'restore notice');

  // Bulk: quarantine all eligible findings in the sample folder.
  await page.goto(admin + 'fckmaleware-scan&tab=findings&s=' + encodeURIComponent(samples + '/'));
  await page.locator('.fckmw-check-all').check();
  if (await page.locator('[data-select-all]').count()) { await page.locator('[data-select-all]').click(); }
  await page.selectOption('#fckmw-bulk-op', 'quarantine');
  await page.locator('#fckmw-bulk-form button:has-text("Apply")').click();
  await page.locator('dialog.fckmw-dialog[open]').waitFor();
  ok(/will be processed/.test(await page.locator('dialog.fckmw-dialog[open]').innerText()), 'bulk preview shows the affected count before acting');
  await page.screenshot({ path: shots + '/bulk-preview.png', fullPage: false });
  await confirmDialog();
  await page.waitForFunction(() => /Bulk action finished/.test(document.querySelector('#fckmw-job .fckmw-live-text')?.textContent || ''), null, { timeout: 120000 });
  const jobText = await page.locator('#fckmw-job .fckmw-live-text').innerText();
  ok(/succeeded/.test(jobText), 'bulk progress reports counts: ' + jobText);
  await page.screenshot({ path: shots + '/bulk-done.png', fullPage: false });

  // One-click quarantine menu on the overview: all confirmed malware.
  await page.goto(admin + 'fckmaleware');
  await page.locator('.fckmw-strip-actions details.fckmw-menu > summary').click();
  ok(await page.locator('.fckmw-strip-actions .fckmw-menu-item').count() === 4, 'quarantine menu offers four scopes');
  await page.screenshot({ path: shots + '/quarantine-menu.png', fullPage: false });
  await page.keyboard.press('Escape');
  ok(!(await page.locator('.fckmw-strip-actions details.fckmw-menu').getAttribute('open')), 'Escape closes the menu');
  await page.locator('.fckmw-strip-actions details.fckmw-menu > summary').click();
  const confirmed = page.locator('.fckmw-strip-actions .fckmw-menu-item[data-scope="confirmed"]');
  if (await confirmed.isEnabled()) {
    await confirmed.click();
    await page.locator('dialog.fckmw-dialog[open]').waitFor();
    ok(/matching open findings/.test(await page.locator('dialog.fckmw-dialog[open]').innerText()), 'confirmed-malware scope shows a preview first');
    if (await page.locator('dialog.fckmw-dialog[open] .fckmw-dialog-confirm').isVisible()) {
      await confirmDialog();
      await page.waitForFunction(() => /Bulk action finished/.test(document.querySelector('#fckmw-job .fckmw-live-text')?.textContent || ''), null, { timeout: 120000 });
      ok(/0 failed/.test(await page.locator('#fckmw-job .fckmw-live-text').innerText()), 'one-click quarantine of confirmed malware finished without failures');
    } else {
      await page.keyboard.press('Escape');
    }
  } else {
    ok(true, 'no confirmed malware left to quarantine');
  }

  // Settings save round-trip (toggle off then on).
  await page.goto(admin + 'fckmaleware-settings');
  await page.locator('#fckmw-scan_images').setChecked(true, { force: true });
  await page.locator('#scanning summary').click();
  await page.fill('input[name="fckmw[heuristic_threshold]"]', '65');
  await page.click('button[type=submit]:has-text("Save settings")');
  await page.waitForLoadState();
  ok(await page.inputValue('input[name="fckmw[heuristic_threshold]"]') === '65', 'threshold saved');
  ok(await page.isChecked('#fckmw-scan_images'), 'switched-on setting saved as on');
  await page.locator('label[for="fckmw-scan_images"]').click();
  await page.click('button[type=submit]:has-text("Save settings")');
  await page.waitForLoadState();
  ok(!(await page.isChecked('#fckmw-scan_images')), 'switched-off setting saved as off (keyboard/label toggle)');
  await page.locator('#scanning summary').click();
  await page.fill('input[name="fckmw[heuristic_threshold]"]', '60');
  await page.click('button[type=submit]:has-text("Save settings")'); await page.waitForLoadState();

  // Hardening apply / revert.
  await page.goto(admin + 'fckmaleware-protection&tab=hardening');
  const card = '.fckmw-rule:has-text("Disable the built-in file editor")';
  await page.locator(card + ' button:has-text("Apply")').click();
  await confirmDialog(); await page.waitForLoadState();
  ok(await page.locator(card + ' button:has-text("Revert")').count() === 1, 'hardening rule applied');
  await page.screenshot({ path: shots + '/hardening.png', fullPage: false });
  await page.locator(card + ' button:has-text("Revert")').click(); await page.waitForLoadState();
  ok(await page.locator(card + ' button:has-text("Apply")').count() === 1, 'hardening rule reverted');

  // Every remaining tab renders with the shared shell.
  for (const p of ['fckmaleware-scan&tab=schedule', 'fckmaleware-protection', 'fckmaleware-protection&tab=signatures', 'fckmaleware-protection&tab=intel', 'fckmaleware-protection&tab=ai', 'fckmaleware-integrations', 'fckmaleware-integrations&tab=connections', 'fckmaleware-settings&tab=activity', 'fckmaleware-settings&tab=reports', 'fckmaleware-settings&tab=diagnostics']) {
    await page.goto(admin + p);
    ok(await page.locator('.wrap.fckmw .fckmw-brandbar').count() === 1 && await page.locator('.fckmw-tabs .is-current').count() === 1, 'renders ' + p);
  }
  await page.goto(admin + 'fckmaleware-integrations');
  ok(await page.locator('.fckmw-card-title:has-text("cPGuard")').count() === 1, 'integration center lists cPGuard');

  // Keyboard: tabs are reachable and show a focus ring.
  await page.goto(admin + 'fckmaleware-scan');
  await page.locator('.fckmw-tabs a').first().focus();
  ok(await page.evaluate(() => getComputedStyle(document.activeElement).boxShadow !== 'none'), 'visible focus state on tabs');

  // Narrow screens: no horizontal overflow.
  await page.setViewportSize({ width: 390, height: 900 });
  for (const p of ['fckmaleware', 'fckmaleware-scan&tab=findings', 'fckmaleware-settings']) {
    await page.goto(admin + p);
    const overflow = await page.evaluate(() => document.querySelector('.wrap.fckmw').scrollWidth - document.querySelector('.wrap.fckmw').clientWidth);
    ok(overflow <= 2, 'no horizontal overflow at 390px: ' + p + ' (' + overflow + ')');
  }
  await page.goto(admin + 'fckmaleware'); await page.screenshot({ path: shots + '/overview-mobile.png', fullPage: true });

  await page.setViewportSize({ width: 1440, height: 1000 });
  ok(await setAutoRemove(true), 'automatic removal switched back on');
  ok(errors.length === 0, 'no JavaScript errors or native dialogs ' + errors.join(' | '));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
