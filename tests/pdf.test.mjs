import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../cloud-sync/src/index.js';
import { readPdfPayload, renderPrintPdf, PRINT_FONT_URL } from '../cloud-sync/src/pdf-render.js';

const session = { user_id: 'usr_pdf_test', email: 'owner@example.test', expires_at: '2099-01-01' };
const env = extra => ({ PDF_ALLOWED_EMAILS: session.email, DB: { prepare() { return { bind() { return this; }, async first() { return session; } }; } }, ...extra });
const request = body => new Request('https://api.test/api/pdf', { method: 'POST', headers: { authorization: 'Bearer test-session-token-1234567890', 'content-type': 'application/json' }, body: JSON.stringify(body) });
test('PDF is disabled unless explicitly enabled', async () => assert.equal((await worker.fetch(request({}), env())).status, 503));
test('PDF account allowlist precedes browser acquisition', async () => assert.equal((await worker.fetch(request({}), env({ PDF_ALLOWED_EMAILS: 'other@example.test' }))).status, 403));
test('PDF rate limit rejects before browser acquisition', async () => {
  const response = await worker.fetch(request({}), env({ PDF_ENABLED: 'true', PDF_BROWSER: {}, PDF_RATE_LIMITER: { limit: async () => ({ success: false }) } }));
  assert.equal(response.status, 429);
});
test('oversized PDF payload is rejected', async () => {
  const req = new Request('https://api.test', { method: 'POST', headers: { 'content-length': String(13 * 1024 * 1024) }, body: '{}' });
  await assert.rejects(readPdfPayload(req), /PDF_PAYLOAD_TOO_LARGE/);
});
test('renderer disables scripts and rejects arbitrary network access', async () => {
  const calls = [];
  let intercept;
  const page = {
    async setJavaScriptEnabled(value) { calls.push(['javascript', value]); },
    async setViewport() {}, async setRequestInterception() {},
    on(name, handler) { if (name === 'request') intercept = handler; },
    async emulateMediaType(value) { assert.equal(value, 'print'); },
    async setContent(html) { assert.ok(html.includes("script-src 'none'")); },
    async evaluate() {}, async $$eval() { return 1; },
    async pdf(options) { assert.equal(options.preferCSSPageSize, true); return new Uint8Array(); }
  };
  await renderPrintPdf(page, { html: '<div class="print-pagination-root"></div>', css: '' });
  assert.deepEqual(calls[0], ['javascript', false]);
  let blocked = 0, allowed = 0;
  for (const url of ['http://127.0.0.1/private', 'https://attacker.example/', 'http://169.254.169.254/']) intercept({ method: () => 'GET', url: () => url, abort: () => blocked++, continue: () => allowed++ });
  intercept({ method: () => 'GET', url: () => PRINT_FONT_URL, abort: () => blocked++, continue: () => allowed++ });
  assert.equal(blocked, 3); assert.equal(allowed, 1);
});
