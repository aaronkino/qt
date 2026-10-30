/* Serialize the browser's existing print pages; Chromium renders the PDF. */
(() => {
    'use strict';
    async function inlineImage(source, target) {
        await source.decode();
        if (source.currentSrc.startsWith('data:')) { target.src = source.currentSrc; return; }
        const response = await fetch(source.currentSrc);
        if (!response.ok) throw new Error('報價圖片載入失敗');
        const blob = await response.blob();
        target.src = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(blob);
        });
        target.removeAttribute('srcset');
    }
    async function serialize(root, quotationId) {
        const copy = root.cloneNode(true);
        copy.classList.remove('print-pagination-measuring');
        copy.style.cssText = '';
        await Promise.all([...root.querySelectorAll('img')].map((image, index) => inlineImage(image, copy.querySelectorAll('img')[index])));
        const sources = root.querySelectorAll('input,textarea,select');
        copy.querySelectorAll('input,textarea,select').forEach((field, index) => {
            const source = sources[index];
            if (field.tagName === 'TEXTAREA') field.textContent = source.value;
            else if (field.tagName === 'SELECT') [...field.options].forEach((option, i) => option.selected = source.selectedIndex === i);
            else { field.setAttribute('value', source.value); if (source.checked) field.setAttribute('checked', ''); else field.removeAttribute('checked'); }
        });
        copy.querySelectorAll('script,iframe,object,embed').forEach(node => node.remove());
        copy.querySelectorAll('*').forEach(node => {
            for (const attribute of [...node.attributes]) if (/^on/i.test(attribute.name)) node.removeAttribute(attribute.name);
        });
        const styles = [];
        for (const sheet of document.styleSheets) {
            try { styles.push([...sheet.cssRules].map(rule => rule.cssText).join('\n')); }
            catch { /* Remote icon sheets are unnecessary in the print tree. */ }
        }
        return { html: copy.outerHTML, css: styles.join('\n'), quotationId: String(quotationId || 'quotation'), viewportWidth: window.innerWidth };
    }
    window.KinoPdfExport = {
        busy: false,
        serialize,
        async download(root, quotationId, token, apiUrl) {
            if (!root || !token) throw new Error('請先使用 Google 登入以下載 PDF。');
            if (this.busy) return;
            this.busy = true;
            const buttons = [...document.querySelectorAll('[aria-label="下載報價單 PDF"]')];
            buttons.forEach(button => { button.disabled = true; button.setAttribute('aria-busy', 'true'); });
            try {
                const payload = await serialize(root, quotationId);
                const response = await fetch(`${apiUrl}/api/pdf`, {
                    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
                    body: JSON.stringify(payload), signal: AbortSignal.timeout(60000)
                });
                if (!response.ok) {
                    const error = await response.json().catch(() => ({}));
                    throw new Error(error.error || 'PDF 下載失敗，請稍後再試。');
                }
                if (!response.headers.get('content-type')?.includes('application/pdf')) throw new Error('PDF 回應格式不正確');
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = String(quotationId || 'quotation').trim().replace(/[\\/:*?"<>|\x00-\x1f]/g, '-') + '.pdf';
                document.body.appendChild(link); link.click(); link.remove();
                setTimeout(() => URL.revokeObjectURL(url), 60000);
            } finally {
                this.busy = false;
                buttons.forEach(button => { button.disabled = false; button.removeAttribute('aria-busy'); });
            }
        }
    };
})();
