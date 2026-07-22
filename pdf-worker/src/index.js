import puppeteer from '@cloudflare/puppeteer';
import { PDFArray, PDFDict, PDFName, PDFString, PDFDocument, rgb, TextAlignment } from 'pdf-lib';

const MAX_HTML_BYTES = 1_500_000;
const TEXT_FIELDS = new Set([
  'clientCompany', 'clientContact', 'clientTaxId', 'clientPhone',
  'vendorCompany', 'vendorContact', 'vendorTaxId', 'vendorPhone'
]);

const corsHeaders = (origin) => ({
  'Access-Control-Allow-Origin': origin,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Vary': 'Origin'
});

const reject = (message, status, origin) => new Response(message, {
  status,
  headers: { ...corsHeaders(origin), 'content-type': 'text/plain; charset=UTF-8' }
});

const addSignatureField = (pdfDoc, page, name, box) => {
  const { x, y, width, height } = box;
  const context = pdfDoc.context;
  const acroFormKey = PDFName.of('AcroForm');
  let acroForm = pdfDoc.catalog.lookupMaybe(acroFormKey, PDFDict);
  if (!acroForm) {
    acroForm = context.obj({ Fields: [] });
    pdfDoc.catalog.set(acroFormKey, acroForm);
  }
  let fields = acroForm.lookupMaybe(PDFName.of('Fields'), PDFArray);
  if (!fields) {
    fields = context.obj([]);
    acroForm.set(PDFName.of('Fields'), fields);
  }
  const field = context.obj({ FT: PDFName.of('Sig'), T: PDFString.of(name), Ff: 0 });
  const fieldRef = context.register(field);
  const widget = context.obj({
    Type: PDFName.of('Annot'),
    Subtype: PDFName.of('Widget'),
    Rect: [x, y, x + width, y + height],
    P: page.ref,
    Parent: fieldRef,
    F: 4,
    MK: { BC: [0.85, 0.89, 0.92], BG: [1, 1, 1] }
  });
  const widgetRef = context.register(widget);
  field.set(PDFName.of('Kids'), context.obj([widgetRef]));
  fields.push(fieldRef);
  let annotations = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
  if (!annotations) {
    annotations = context.obj([]);
    page.node.set(PDFName.of('Annots'), annotations);
  }
  annotations.push(widgetRef);
  acroForm.set(PDFName.of('SigFlags'), context.obj(3));
};

const toPdfBox = (box, pageHeight) => ({
  x: box.x * 0.75,
  y: pageHeight - ((box.y + box.height) * 0.75),
  width: box.width * 0.75,
  height: box.height * 0.75
});

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    if (origin !== env.ALLOWED_ORIGIN) return reject('Origin not allowed', 403, env.ALLOWED_ORIGIN);
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(env.ALLOWED_ORIGIN) });
    if (request.method !== 'POST') return reject('Method not allowed', 405, env.ALLOWED_ORIGIN);
    const requestLength = Number(request.headers.get('Content-Length') || 0);
    if (requestLength > MAX_HTML_BYTES) return reject('Document is too large', 413, env.ALLOWED_ORIGIN);

    let payload;
    try {
      payload = await request.json();
    } catch {
      return reject('Invalid JSON request', 400, env.ALLOWED_ORIGIN);
    }
    if (typeof payload?.html !== 'string' || !payload.html.includes('quick-print-sheet') || payload.html.length > MAX_HTML_BYTES) {
      return reject('Invalid quotation document', 400, env.ALLOWED_ORIGIN);
    }

    const browser = await puppeteer.launch(env.BROWSER);
    try {
      const renderPage = await browser.newPage();
      // The quotation stylesheet imports web fonts. Waiting for a completely idle
      // network can therefore keep a Browser Rendering session open indefinitely.
      // Render once the document exists, then allow a short grace period for fonts.
      await renderPage.setContent(payload.html, { waitUntil: 'domcontentloaded' });
      await renderPage.emulateMediaType('print');
      await renderPage.evaluate(async () => {
        await Promise.race([
          document.fonts.ready,
          new Promise((resolve) => setTimeout(resolve, 3000)),
        ]);
      });
      const fieldBoxes = await renderPage.evaluate(() => {
        const fields = [...document.querySelectorAll('[data-pdf-field]')];
        const result = fields.map((element) => {
          const bounds = element.getBoundingClientRect();
          const fieldName = element.getAttribute('data-pdf-field');
          const fieldType = element.getAttribute('data-pdf-field-type') || 'text';
          if (fieldType === 'text' && fieldName.startsWith('client')) element.textContent = '';
          return { name: fieldName, type: fieldType, x: bounds.x, y: bounds.y, width: bounds.width, height: bounds.height };
        });
        return result.filter(field => field.width > 0 && field.height > 0);
      });
      const printedPdf = await renderPage.pdf({ preferCSSPageSize: true, printBackground: true });
      const pdfDoc = await PDFDocument.load(printedPdf);
      const page = pdfDoc.getPage(0);
      const { height: pageHeight } = page.getSize();
      const form = pdfDoc.getForm();

      for (const field of fieldBoxes) {
        const box = toPdfBox(field, pageHeight);
        if (field.type === 'signature') {
          addSignatureField(pdfDoc, page, field.name, box);
        } else if (TEXT_FIELDS.has(field.name)) {
          const textField = form.createTextField(field.name);
          textField.addToPage(page, { ...box, borderWidth: 0, textColor: rgb(0.07, 0.22, 0.31) });
          textField.setFontSize(8);
          textField.setAlignment(TextAlignment.Center);
        }
      }
      const output = await pdfDoc.save();
      const filename = String(payload.filename || 'KINO-quotation-fillable.pdf').replace(/[^a-zA-Z0-9._-]/g, '_');
      return new Response(output, {
        headers: {
          ...corsHeaders(env.ALLOWED_ORIGIN),
          'content-type': 'application/pdf',
          'content-disposition': `attachment; filename="${filename}"`,
          'cache-control': 'no-store'
        }
      });
    } catch (error) {
      console.error('PDF generation failed', error);
      return reject('PDF generation failed', 500, env.ALLOWED_ORIGIN);
    } finally {
      await browser.close();
    }
  }
};
