/**
 * End-to-end test of the admin UI with Playwright, against a disposable test site.
 *
 *   FCKMW_SITE=http://127.0.0.1:8099 FCKMW_USER=admin FCKMW_PASS=admin \
 *   FCKMW_SAMPLES=wp-content/e2e-samples node tests/e2e/ui.js /tmp/shots
 *
 * FCKMW_SAMPLES must be a real (not symlinked) directory inside the site holding
 * copies of tests/fixtures/malware and tests/fixtures/clean without the
 * .fixture suffix. The test quarantines and restores one of them.
 */
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const site = process.env.FCKMW_SITE || 'http://127.0.0.1:8099';
const base = site + '/wp-admin/admin.php?page=fckmaleware';
const shots = process.argv[2] || require('os').tmpdir();
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
  page.on('dialog', d => d.accept());
  const ok = (cond, msg) => { console.log((cond ? 'PASS ' : 'FAIL ') + msg); if (!cond) process.exitCode = 1; };

  await page.goto(site + '/wp-login.php');
  await page.fill('#user_login', process.env.FCKMW_USER || 'admin'); await page.fill('#user_pass', process.env.FCKMW_PASS || 'admin');
  await page.click('#wp-submit'); await page.waitForLoadState();

  // Overview
  await page.goto(base);
  ok(await page.locator('.fckmw-score').count() === 1, 'overview shows health score');
  ok(await page.locator('.fckmw-nav a').count() === 14, 'navigation has 14 sections');
  await page.screenshot({ path: shots + '/overview.png', fullPage: true });

  // Scanner: run a custom scan of the malware fixtures dir through the UI
  await page.goto(base + '-scanner');
  await page.check('input[name=mode][value=custom]');
  ok(await page.locator('.fckmw-mode-option[data-mode=custom]').isVisible(), 'custom mode shows directory field');
  await page.fill('input[name=scope]', process.env.FCKMW_SAMPLES || 'wp-content/e2e-samples');
  await page.click('#fckmw-scan-form button[type=submit]');
  const outcome = await Promise.race([
    page.waitForEvent('load', { timeout: 120000 }).then(() => 'reloaded'),
    page.waitForFunction(() => /Error:/.test(document.querySelector('#fckmw-scan-progress .fckmw-live-text')?.textContent || ''), null, { timeout: 120000 }).then(() => 'error'),
  ]);
  if (outcome === 'error') { console.log('FAIL scan error: ' + await page.locator('#fckmw-scan-progress .fckmw-live-text').innerText()); process.exit(1); }
  await page.waitForLoadState();
  const lastScan = await page.locator('.fckmw-dl').first().innerText();
  ok(/Custom/.test(lastScan), 'scan completed and last scan shows Custom mode');
  await page.screenshot({ path: shots + '/scanner.png', fullPage: true });

  // Findings: open the first one, quarantine it, then restore from quarantine
  await page.goto(base + '-findings&source=signature');
  const rows = await page.locator('.fckmw-findings tbody > tr:not(.fckmw-detail-row)').count();
  ok(rows > 0, `findings listed (${rows})`);
  await page.locator('.fckmw-detail-row summary').first().click();
  const file = (await page.locator('.fckmw-file code').first().innerText()).trim();
  await page.screenshot({ path: shots + '/findings.png', fullPage: false });
  await page.locator('.fckmw-detail-row button:has-text("Quarantine file")').first().click();
  await page.waitForLoadState();
  ok(/quarantine/i.test(await page.locator('.notice').first().innerText()), 'quarantine notice: ' + (await page.locator('.notice').first().innerText()).trim());
  await page.goto(base + '-quarantine');
  ok((await page.locator('.fckmw-table').first().innerText()).includes(file), 'quarantined file listed: ' + file);
  await page.screenshot({ path: shots + '/quarantine.png', fullPage: true });
  await page.locator(`tr:has-text("${file}") button:has-text("Restore")`).first().click();
  await page.waitForLoadState();
  ok(/restored/i.test(await page.locator('.notice').first().innerText()), 'restore notice');

  // Settings save round-trip (toggle off then on)
  await page.goto(base + '-settings');
  await page.uncheck('input[name="fckmw[scan_images]"]');
  await page.fill('input[name="fckmw[heuristic_threshold]"]', '65');
  await page.click('input[type=submit][value="Save settings"]');
  await page.waitForLoadState();
  ok(await page.inputValue('input[name="fckmw[heuristic_threshold]"]') === '65', 'threshold saved');
  ok(!(await page.isChecked('input[name="fckmw[scan_images]"]')), 'unchecked box saved as off');
  await page.fill('input[name="fckmw[heuristic_threshold]"]', '60');
  await page.click('input[type=submit][value="Save settings"]'); await page.waitForLoadState();

  // Hardening toggle on/off
  await page.goto(base + '-hardening');
  const card = page.locator('.fckmw-rule:has-text("Disable the built-in file editor")');
  await card.locator('button:has-text("Turn on")').click(); await page.waitForLoadState();
  ok(await page.locator('.fckmw-rule:has-text("Disable the built-in file editor") button:has-text("Turn off")').count() === 1, 'hardening rule enabled');
  await page.screenshot({ path: shots + '/hardening.png', fullPage: false });
  await page.locator('.fckmw-rule:has-text("Disable the built-in file editor") button:has-text("Turn off")').click(); await page.waitForLoadState();

  // Remaining pages render
  for (const p of ['-realtime','-ai','-signatures','-intel','-schedule','-reports','-activity','-integrations']) {
    await page.goto(base + p);
    ok(await page.locator('.wrap.fckmw').count() === 1, 'renders ' + p);
  }
  await page.goto(base + '-reports'); await page.screenshot({ path: shots + '/reports.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto(base); await page.screenshot({ path: shots + '/overview-mobile.png', fullPage: true });

  ok(errors.length === 0, 'no JS errors ' + errors.join(' | '));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
