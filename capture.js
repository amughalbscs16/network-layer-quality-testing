/**
 * HAR Capture Script for Network Call Quality Audit
 * ──────────────────────────────────────────────────
 * Captures HAR (HTTP Archive) files for 30 production websites.
 * Validates each site's accessibility, marks sites as SUCCESS/BLOCKED/FAILED.
 * Target: 20+ usable sites from 30 candidates.
 *
 * Usage:
 *   node capture.js                    # Capture all sites
 *   node capture.js --site mysite      # Capture single site by ID
 *   node capture.js --test             # Test mode: first 3 sites, 1 run each
 *   node capture.js --validate         # Only check which sites are accessible (no full capture)
 *
 * Output:
 *   har-files/<site-id>/<page-label>_run<N>_<cold|warm>.har
 *   results/capture_master_log.json    # Full capture log with site statuses
 *   results/site_status.json           # Quick-reference: which sites worked
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// ─── Configuration ───────────────────────────────────────────────────────────

const SITES_FILE = path.join(__dirname, 'data', 'sites.json');
const HAR_DIR = path.join(__dirname, 'har-files');
const RESULTS_DIR = path.join(__dirname, 'results');
const RUNS_PER_PAGE = 3;
const SCROLL_VIEWPORTS = 3;
const IDLE_WAIT_MS = 5000;
const POST_SCROLL_WAIT_MS = 3000;
const VIEWPORT = { width: 1920, height: 1080 };
const BETWEEN_SITES_DELAY_MS = 3000;
const BETWEEN_RUNS_DELAY_MS = 2000;

// Minimum number of requests to consider a capture valid (CAPTCHA pages have very few)
const MIN_REQUESTS_FOR_VALID = 5;
// Hard timeout per page capture (prevents infinite SPA loading)
const PAGE_CAPTURE_TIMEOUT_MS = 90000; // 90 seconds max per page

// ─── Helpers ─────────────────────────────────────────────────────────────────

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function log(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] ${msg}`);
}

function logError(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.error(`[${ts}] ERROR: ${msg}`);
}

function logSuccess(msg) {
  const ts = new Date().toISOString().slice(11, 19);
  console.log(`[${ts}] OK: ${msg}`);
}

// ─── Core Capture Logic ─────────────────────────────────────────────────────

async function capturePageWithTimeout(browser, url, harPath) {
  let contextRef = null;
  const capturePromise = capturePage(browser, url, harPath, (ctx) => { contextRef = ctx; });
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(async () => {
      if (contextRef) {
        try { await contextRef.close(); } catch {}
      }
      reject(new Error(`Page capture timed out after ${PAGE_CAPTURE_TIMEOUT_MS/1000}s`));
    }, PAGE_CAPTURE_TIMEOUT_MS);
  });
  return Promise.race([capturePromise, timeoutPromise]);
}

async function capturePage(browser, url, harPath, onContextCreated) {
  const requestLog = [];

  const context = await browser.newContext({
    viewport: VIEWPORT,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    recordHar: {
      path: harPath,
      mode: 'full',
      content: 'omit'
    }
  });

  // Register context for timeout cleanup
  if (onContextCreated) onContextCreated(context);

  const page = await context.newPage();

  // Track requests for validation
  page.on('request', req => {
    requestLog.push({ url: req.url(), method: req.method(), resourceType: req.resourceType() });
  });

  let pageTitle = '';
  let finalUrl = '';
  let httpStatus = 0;

  try {
    // Step 1: Navigate
    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout: 60000
    });

    httpStatus = response ? response.status() : 0;
    finalUrl = page.url();

    // Step 2: Wait for network idle
    try {
      await page.waitForLoadState('networkidle', { timeout: IDLE_WAIT_MS });
    } catch {
      // OK — heavy sites may never reach networkidle
    }

    // Step 3: Get page title (helps detect CAPTCHA/block pages)
    pageTitle = await page.title();

    // Step 4: Scroll to trigger lazy loading
    for (let i = 0; i < SCROLL_VIEWPORTS; i++) {
      await page.evaluate((vh) => window.scrollBy(0, vh), VIEWPORT.height);
      await page.waitForTimeout(800);
    }

    // Step 5: Wait for lazy-loaded calls
    await page.waitForTimeout(POST_SCROLL_WAIT_MS);

    // Step 6: Scroll back
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(1000);

  } catch (err) {
    logError(`Navigation failed for ${url}: ${err.message}`);
    await context.close();
    return {
      success: false,
      error: err.message,
      requestCount: requestLog.length,
      httpStatus,
      pageTitle,
      finalUrl
    };
  }

  await context.close();

  return {
    success: true,
    requestCount: requestLog.length,
    httpStatus,
    pageTitle,
    finalUrl,
    apiRequests: requestLog.filter(r => r.resourceType === 'xhr' || r.resourceType === 'fetch').length
  };
}

// Detect if a page loaded real content or got blocked
function classifyPageResult(result) {
  const title = (result.pageTitle || '').toLowerCase();
  const blockedTitles = ['captcha', 'access denied', 'robot', 'bot detection',
    'verify you are human', 'just a moment', 'attention required', 'blocked',
    'pardon our interruption', 'are you a robot'];

  for (const blocked of blockedTitles) {
    if (title.includes(blocked)) return 'blocked';
  }

  if (result.httpStatus === 401 || result.httpStatus === 403 || result.httpStatus === 429) return 'blocked';
  if (result.httpStatus >= 500) return 'server_error';
  if (!result.success) return 'failed';
  if (result.requestCount < MIN_REQUESTS_FOR_VALID) return 'suspicious';

  return 'success';
}

// ─── Site-Level Capture ─────────────────────────────────────────────────────

async function captureSite(browser, site, runsPerPage) {
  const siteDir = path.join(HAR_DIR, site.id);
  ensureDir(siteDir);

  const siteResult = {
    site_id: site.id,
    site_name: site.name,
    category: site.category,
    architecture: site.architecture,
    bot_risk: site.bot_risk,
    status: 'pending',       // Will be set to: success | partial | blocked | failed
    captures: [],
    page_statuses: [],
    started_at: new Date().toISOString(),
    completed_at: null,
    errors: []
  };

  for (const pageInfo of site.pages) {
    let pageStatus = 'unknown';

    for (let run = 1; run <= runsPerPage; run++) {
      for (const visitType of ['cold', 'warm']) {
        const harFile = `${pageInfo.label}_run${run}_${visitType}.har`;
        const harPath = path.join(siteDir, harFile);

        log(`  [${site.id}] ${pageInfo.label} run ${run}/${runsPerPage} ${visitType.toUpperCase()}`);

        try {
          const result = await capturePageWithTimeout(browser, pageInfo.url, harPath);
          const classification = classifyPageResult(result);

          if (run === 1 && visitType === 'cold') {
            pageStatus = classification;
          }

          siteResult.captures.push({
            page: pageInfo.label,
            url: pageInfo.url,
            run,
            type: visitType,
            file: harFile,
            timestamp: new Date().toISOString(),
            classification,
            httpStatus: result.httpStatus,
            requestCount: result.requestCount,
            apiRequests: result.apiRequests || 0,
            pageTitle: result.pageTitle
          });

          if (classification === 'success') {
            logSuccess(`${result.requestCount} requests (${result.apiRequests || 0} API), status ${result.httpStatus}`);
          } else if (classification === 'blocked') {
            logError(`BLOCKED - title: "${result.pageTitle}", status: ${result.httpStatus}`);
          } else {
            log(`  Status: ${classification} (${result.requestCount} requests, HTTP ${result.httpStatus})`);
          }

        } catch (err) {
          logError(`Capture failed: ${err.message}`);
          siteResult.errors.push({
            page: pageInfo.label, run, type: visitType, error: err.message
          });
        }

        await new Promise(r => setTimeout(r, BETWEEN_RUNS_DELAY_MS));
      }
    }

    siteResult.page_statuses.push({
      page: pageInfo.label,
      url: pageInfo.url,
      status: pageStatus
    });
  }

  // Determine overall site status
  const pageStatuses = siteResult.page_statuses.map(p => p.status);
  if (pageStatuses.every(s => s === 'success')) {
    siteResult.status = 'success';
  } else if (pageStatuses.every(s => s === 'blocked')) {
    siteResult.status = 'blocked';
  } else if (pageStatuses.some(s => s === 'success')) {
    siteResult.status = 'partial';
  } else {
    siteResult.status = 'failed';
  }

  siteResult.completed_at = new Date().toISOString();

  // Save per-site log
  fs.writeFileSync(
    path.join(siteDir, 'capture_log.json'),
    JSON.stringify(siteResult, null, 2)
  );

  return siteResult;
}

// ─── Validation-Only Mode ────────────────────────────────────────────────────

async function validateSites(browser, sites) {
  log('\n  VALIDATION MODE: Testing accessibility of each site (1 page, no full capture)');
  log('─────────────────────────────────────────────────────────────────────\n');

  const results = [];
  const tempDir = path.join(HAR_DIR, '_validation_temp');
  ensureDir(tempDir);

  for (const site of sites) {
    const firstPage = site.pages[0];
    const tempHar = path.join(tempDir, `${site.id}_validate.har`);

    log(`  Testing ${site.name} (${site.id})...`);
    try {
      const result = await capturePageWithTimeout(browser, firstPage.url, tempHar);
      const classification = classifyPageResult(result);

      results.push({
        id: site.id,
        name: site.name,
        category: site.category,
        bot_risk: site.bot_risk,
        status: classification,
        httpStatus: result.httpStatus,
        requestCount: result.requestCount,
        apiRequests: result.apiRequests || 0,
        pageTitle: result.pageTitle
      });

      const icon = classification === 'success' ? 'OK' : classification === 'blocked' ? 'BLOCKED' : 'WARN';
      log(`  [${icon}] ${site.name}: ${classification} (${result.requestCount} reqs, HTTP ${result.httpStatus})`);
    } catch (err) {
      logError(`${site.name}: ${err.message}`);
      results.push({
        id: site.id, name: site.name, category: site.category,
        bot_risk: site.bot_risk, status: 'timeout',
        httpStatus: 0, requestCount: 0, apiRequests: 0, pageTitle: ''
      });
    }

    // Clean up temp HAR
    try { fs.unlinkSync(tempHar); } catch {}

    await new Promise(r => setTimeout(r, BETWEEN_SITES_DELAY_MS));
  }

  // Clean up temp dir
  try { fs.rmdirSync(tempDir); } catch {}

  // Summary
  const successful = results.filter(r => r.status === 'success');
  const blocked = results.filter(r => r.status === 'blocked');
  const timedOut = results.filter(r => r.status === 'timeout');
  const other = results.filter(r => !['success', 'blocked', 'timeout'].includes(r.status));

  log('\n═══════════════════════════════════════════════════════════════');
  log('  VALIDATION RESULTS');
  log('═══════════════════════════════════════════════════════════════');
  log(`  Accessible (success):  ${successful.length} sites`);
  successful.forEach(r => log(`    - ${r.name} (${r.requestCount} reqs, ${r.apiRequests} API)`));
  log(`  Blocked:               ${blocked.length} sites`);
  blocked.forEach(r => log(`    - ${r.name} (${r.pageTitle})`));
  log(`  Timed out:             ${timedOut.length} sites`);
  timedOut.forEach(r => log(`    - ${r.name}`));
  if (other.length > 0) {
    log(`  Other issues:          ${other.length} sites`);
    other.forEach(r => log(`    - ${r.name}: ${r.status}`));
  }
  log('═══════════════════════════════════════════════════════════════');

  // Save validation results
  const validationPath = path.join(RESULTS_DIR, 'site_validation.json');
  fs.writeFileSync(validationPath, JSON.stringify({
    validated_at: new Date().toISOString(),
    total_sites: results.length,
    accessible: successful.length,
    blocked: blocked.length,
    results
  }, null, 2));
  log(`  Results saved to: ${validationPath}`);

  return results;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const testMode = args.includes('--test');
  const validateOnly = args.includes('--validate');
  const accessibleOnly = args.includes('--accessible-only');
  const siteFilter = args.includes('--site') ? args[args.indexOf('--site') + 1] : null;

  // Load sites
  const config = JSON.parse(fs.readFileSync(SITES_FILE, 'utf-8'));
  let sites = config.sites;

  if (siteFilter) {
    sites = sites.filter(s => s.id === siteFilter);
    if (sites.length === 0) {
      console.error(`Site "${siteFilter}" not found. Available: ${config.sites.map(s => s.id).join(', ')}`);
      process.exit(1);
    }
  }

  // Filter to only accessible sites (based on prior validation)
  if (accessibleOnly) {
    const validationPath = path.join(RESULTS_DIR, 'site_validation.json');
    if (fs.existsSync(validationPath)) {
      const validation = JSON.parse(fs.readFileSync(validationPath, 'utf-8'));
      const accessibleIds = new Set(
        validation.results.filter(r => r.status === 'success').map(r => r.id)
      );
      const beforeCount = sites.length;
      sites = sites.filter(s => accessibleIds.has(s.id));
      log(`ACCESSIBLE-ONLY: Filtered ${beforeCount} -> ${sites.length} sites (using validation results)`);
    } else {
      log('WARNING: No validation results found. Run --validate first. Proceeding with all sites.');
    }
  }

  if (testMode) {
    sites = sites.slice(0, 3);
    log('TEST MODE: First 3 sites, 1 run each');
  }

  const runsPerPage = testMode ? 1 : RUNS_PER_PAGE;

  log('═══════════════════════════════════════════════════════════════');
  log('  Network Call Quality Audit - HAR Capture');
  log('═══════════════════════════════════════════════════════════════');
  log(`  Mode: ${validateOnly ? 'VALIDATE' : testMode ? 'TEST' : 'FULL CAPTURE'}`);
  log(`  Sites: ${sites.length}`);
  if (!validateOnly) {
    log(`  Pages per site: 2`);
    log(`  Runs per page: ${runsPerPage}`);
    log(`  Visit types: cold + warm`);
    log(`  Total HAR files: ~${sites.length * 2 * runsPerPage * 2}`);
  }
  log(`  Output: ${HAR_DIR}`);
  log('═══════════════════════════════════════════════════════════════');

  ensureDir(HAR_DIR);
  ensureDir(RESULTS_DIR);

  const browser = await chromium.launch({
    headless: true,
    args: [
      '--disable-blink-features=AutomationControlled',
      '--disable-dev-shm-usage',
      '--no-sandbox'
    ]
  });

  if (validateOnly) {
    await validateSites(browser, sites);
    await browser.close();
    return;
  }

  // ─── Full Capture ────────────────────────────────────────────────

  const masterLog = {
    started_at: new Date().toISOString(),
    completed_at: null,
    config: {
      total_sites: sites.length,
      runs_per_page: runsPerPage,
      viewport: VIEWPORT,
      scroll_viewports: SCROLL_VIEWPORTS,
      idle_wait_ms: IDLE_WAIT_MS
    },
    site_results: [],
    summary: {
      sites_success: 0,
      sites_partial: 0,
      sites_blocked: 0,
      sites_failed: 0,
      total_captures: 0,
      total_errors: 0
    }
  };

  for (let i = 0; i < sites.length; i++) {
    const site = sites[i];
    log(`\n══ Site ${i + 1}/${sites.length}: ${site.name} (${site.id}) ══`);
    log(`   Category: ${site.category} | Architecture: ${site.architecture} | Bot risk: ${site.bot_risk}`);

    try {
      const siteResult = await captureSite(browser, site, runsPerPage);
      masterLog.site_results.push(siteResult);

      // Update summary
      masterLog.summary[`sites_${siteResult.status}`]++;
      masterLog.summary.total_captures += siteResult.captures.length;
      masterLog.summary.total_errors += siteResult.errors.length;

      log(`   Site status: ${siteResult.status.toUpperCase()}`);
    } catch (err) {
      logError(`Site ${site.id} completely failed: ${err.message}`);
      masterLog.site_results.push({
        site_id: site.id, site_name: site.name, status: 'failed',
        error: err.message, captures: [], errors: [{ error: err.message }]
      });
      masterLog.summary.sites_failed++;
    }

    // Delay between sites
    if (i < sites.length - 1) {
      await new Promise(r => setTimeout(r, BETWEEN_SITES_DELAY_MS));
    }
  }

  await browser.close();
  masterLog.completed_at = new Date().toISOString();

  // Save master log
  const masterLogPath = path.join(RESULTS_DIR, 'capture_master_log.json');
  fs.writeFileSync(masterLogPath, JSON.stringify(masterLog, null, 2));

  // Save quick-reference site status
  const siteStatusPath = path.join(RESULTS_DIR, 'site_status.json');
  const siteStatus = masterLog.site_results.map(r => ({
    id: r.site_id,
    name: r.site_name,
    category: r.category,
    status: r.status,
    captures: r.captures ? r.captures.length : 0,
    errors: r.errors ? r.errors.length : 0
  }));
  fs.writeFileSync(siteStatusPath, JSON.stringify({
    generated_at: new Date().toISOString(),
    sites: siteStatus
  }, null, 2));

  // Print summary
  log('\n═══════════════════════════════════════════════════════════════');
  log('  CAPTURE COMPLETE');
  log('═══════════════════════════════════════════════════════════════');
  log(`  Sites successful:  ${masterLog.summary.sites_success}`);
  log(`  Sites partial:     ${masterLog.summary.sites_partial}`);
  log(`  Sites blocked:     ${masterLog.summary.sites_blocked}`);
  log(`  Sites failed:      ${masterLog.summary.sites_failed}`);
  log(`  Total HAR files:   ${masterLog.summary.total_captures}`);
  log(`  Total errors:      ${masterLog.summary.total_errors}`);
  log(`  Master log:        ${masterLogPath}`);
  log(`  Site status:       ${siteStatusPath}`);
  log('═══════════════════════════════════════════════════════════════');

  // List usable sites
  const usable = masterLog.site_results.filter(r => r.status === 'success' || r.status === 'partial');
  log(`\n  Usable for analysis: ${usable.length} sites`);
  usable.forEach(r => log(`    [${r.status.toUpperCase()}] ${r.site_name}`));

  if (usable.length < 20) {
    log(`\n  WARNING: Only ${usable.length} usable sites (target: 20+).`);
    log('  Consider re-running blocked sites with --site <id> after a delay.');
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
