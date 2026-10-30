export const PRINT_FONT_URL = 'https://aaronkino.github.io/qt/assets/pdf/NotoSansTC-Regular.ttf';
export const MAX_PDF_BYTES = 12 * 1024 * 1024;

export async function readPdfPayload(request) {
  if (Number(request.headers.get('content-length')) > MAX_PDF_BYTES) throw new Error('PDF_PAYLOAD_TOO_LARGE');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('PDF_INVALID_PAYLOAD');
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_PDF_BYTES) { await reader.cancel(); throw new Error('PDF_PAYLOAD_TOO_LARGE'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const body = JSON.parse(new TextDecoder().decode(bytes));
  if (typeof body.html !== 'string' || typeof body.css !== 'string' || !body.html.includes('print-pagination-root')) throw new Error('PDF_INVALID_PAYLOAD');
  return body;
}

export function createPrintDocument({ html, css }, fontSource = PRINT_FONT_URL) {
  // A new, cookie-free browser has no application credentials. Scripts are
  // disabled before loading this document; all outbound requests are blocked
  // except the single public print font, preventing SSRF/resource exfiltration.
  return `<!doctype html><html lang="zh-TW" class="print-pagination-active"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data: https://aaronkino.github.io; script-src 'none'; frame-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'"><style>${css.replace(/@import\s+[^;]+;/gi, '')}</style><style>@font-face{font-family:KinoPrintTC;src:url('${fontSource}') format('truetype');font-weight:400;font-display:block}.print-pagination-root,.print-pagination-root input,.print-pagination-root textarea,.print-pagination-root select{font-family:KinoPrintTC,sans-serif!important}html,body{margin:0;padding:0;background:white}*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}</style></head><body>${html}</body></html>`;
}

export async function renderPrintPdf(page, payload, fontSource = PRINT_FONT_URL) {
  await page.setJavaScriptEnabled(false);
  const width = Math.min(2560, Math.max(320, Math.round(Number(payload.viewportWidth) || 1200)));
  await page.setViewport({ width, height: 1600, deviceScaleFactor: 1 });
  await page.setRequestInterception(true);
  page.on('request', request => {
    if (request.method() === 'GET' && (request.url() === PRINT_FONT_URL || /^data:image\/(png|jpeg|webp|gif|svg\+xml)[;,]/i.test(request.url()))) void request.continue();
    else void request.abort();
  });
  await page.emulateMediaType('print');
  await page.setContent(createPrintDocument(payload, fontSource), { waitUntil: 'load', timeout: 25000 });
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.images].map(image => image.decode()));
  });
  const count = await page.$$eval('.print-page', pages => pages.length);
  if (!count || count > 20) throw new Error('PDF_PAGE_LIMIT');
  return page.pdf({ format: 'A4', printBackground: true, preferCSSPageSize: true, displayHeaderFooter: false, scale: 1, timeout: 20000 });
}
