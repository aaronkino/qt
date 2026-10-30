/* Local-only PDF export: raster backgrounds/marks plus Unicode PDF text. */
(() => {
    'use strict';
    const base = new URL('./', document.currentScript.src);
    let dependencies;
    const loadScript = path => new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = new URL(path, base).href;
        script.onload = resolve;
        script.onerror = () => { script.remove(); reject(new Error('PDF 元件載入失敗，請檢查網路後重試。')); };
        document.head.appendChild(script);
    });
    const load = () => dependencies ||= Promise.all([
        loadScript('pdf/jspdf.umd.min.js'),
        loadScript('pdf/html2canvas.min.js'),
        fetch(new URL('pdf/NotoSansTC-Regular.ttf', base)).then(response => {
            if (!response.ok) throw new Error('PDF 中文字型載入失敗');
            return response.arrayBuffer();
        }).then(async buffer => {
            const face = new FontFace('KinoPdfTC', buffer);
            await face.load();
            document.fonts.add(face);
            const bytes = new Uint8Array(buffer);
            let binary = '';
            for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
            return btoa(binary);
        })
    ]).catch(error => { dependencies = null; throw error; });
    const waitImage = image => new Promise((resolve, reject) => {
        let timer;
        const finish = () => {
            clearTimeout(timer);
            image.removeEventListener('load', finish);
            image.removeEventListener('error', finish);
            image.naturalWidth ? resolve() : reject(new Error('報價圖片載入失敗，請重新選擇圖片後重試。'));
        };
        if (image.complete) return finish();
        image.addEventListener('load', finish);
        image.addEventListener('error', finish);
        timer = setTimeout(() => { image.removeEventListener('load', finish); image.removeEventListener('error', finish); reject(new Error('報價圖片載入逾時，請重試。')); }, 15000);
    });
    const textLayer = page => {
        const bounds = page.getBoundingClientRect();
        const walker = document.createTreeWalker(page, NodeFilter.SHOW_TEXT);
        const runs = [];
        let node;
        while ((node = walker.nextNode())) {
            if (!node.textContent.trim()) continue;
            if (node.parentElement.closest('.quick-print-footer,.detailed-print-footer')) continue;
            const style = getComputedStyle(node.parentElement);
            if (style.visibility === 'hidden' || style.display === 'none') continue;
            // Character ranges follow the browser's actual line wrapping,
            // table alignment and selected print scale, including Chinese.
            let offset = 0;
            for (const character of node.textContent) {
                const range = document.createRange();
                range.setStart(node, offset);
                offset += character.length;
                range.setEnd(node, offset);
                const rect = range.getBoundingClientRect();
                if (!character.trim() || !rect.width || !rect.height) continue;
                let opacity = 1;
                for (let ancestor = node.parentElement; ancestor && ancestor !== page; ancestor = ancestor.parentElement) opacity *= Number(getComputedStyle(ancestor).opacity);
                runs.push({ text: character, x: rect.left - bounds.left, y: rect.top - bounds.top, height: rect.height, width: rect.width, color: style.color, bold: Number(style.fontWeight) >= 600, opacity });
            }
        }
        for (const input of page.querySelectorAll('input,textarea,select')) {
            const rect = input.getBoundingClientRect();
            const style = getComputedStyle(input);
            if (!rect.width || !rect.height) continue;
            const height = parseFloat(style.fontSize) * 1.2;
            const align = style.textAlign === 'center' ? 'center' : style.textAlign === 'right' ? 'right' : 'left';
            runs.push({ text: input.value || '', x: rect.left - bounds.left + (align === 'center' ? rect.width / 2 : align === 'right' ? rect.width : 0), y: rect.top - bounds.top + (rect.height - height) / 2, height, color: style.color, align });
        }
        for (const list of page.querySelectorAll('ol')) {
            for (const [index, item] of [...list.children].entries()) {
                if (item.classList.contains('quick-print-term-continuation')) continue;
                const rect = item.getBoundingClientRect();
                const style = getComputedStyle(item);
                const height = parseFloat(style.fontSize) * 1.2;
                runs.push({ text: String((Number(list.start) || 1) + index) + '.', x: rect.left - bounds.left - 3, y: rect.top - bounds.top, height, color: style.color, align: 'right' });
            }
        }
        const footer = page.querySelector('.quick-print-footer,.detailed-print-footer');
        if (footer) {
            const rect = footer.getBoundingClientRect();
            const style = getComputedStyle(footer);
            const height = parseFloat(style.fontSize) * 1.2;
            const spans = footer.querySelectorAll('span');
            runs.push({ text: spans[0]?.textContent || '', x: 0, y: rect.bottom - bounds.top - height, height, color: style.color });
            runs.push({ text: spans[1]?.textContent || '', x: bounds.width, y: rect.bottom - bounds.top - height, height, color: style.color, align: 'right' });
        }
        return { bounds, runs };
    };
    window.KinoPdfExport = {
        busy: false,
        async download(root, quotationId) {
            if (!root) throw new Error('找不到報價列印內容');
            if (this.busy) throw new Error('PDF 正在產生，請稍候');
            this.busy = true;
            const buttons = [...document.querySelectorAll('[aria-label="下載報價單 PDF"]')];
            buttons.forEach(button => { button.disabled = true; button.setAttribute('aria-busy', 'true'); });
            try {
                const [, , font] = await load();
                root.classList.add('print-pagination-measuring');
                root.style.cssText = 'display:block!important;position:absolute;left:0;top:0;width:194mm;visibility:visible;pointer-events:none;z-index:-1;';
                for (const element of root.querySelectorAll('*')) element.style.fontFamily = 'KinoPdfTC, sans-serif';
                await Promise.all([...root.querySelectorAll('img')].map(waitImage));
                for (const image of root.querySelectorAll('img')) {
                    if (!image.src.startsWith('data:image/svg') && !image.src.endsWith('.svg')) continue;
                    const raster = document.createElement('canvas');
                    raster.width = image.naturalWidth || 600;
                    raster.height = image.naturalHeight || 200;
                    raster.getContext('2d').drawImage(image, 0, 0, raster.width, raster.height);
                    image.src = raster.toDataURL('image/png');
                    await waitImage(image);
                }
                const pdf = new window.jspdf.jsPDF({ unit: 'mm', format: 'a4', compress: true, putOnlyUsedFonts: true });
                pdf.addFileToVFS('NotoSansTC-Regular.ttf', font);
                pdf.addFont('NotoSansTC-Regular.ttf', 'KinoTC', 'normal');
                pdf.setFont('KinoTC');
                pdf.setProperties({ title: String(quotationId || '奇諾影像報價單'), creator: 'KINO Studio' });
                const pages = [...root.querySelectorAll('.print-page')];
                if (!pages.length) throw new Error('報價分頁尚未準備完成');
                for (let index = 0; index < pages.length; index++) {
                    const page = pages[index];
                    const { bounds, runs } = textLayer(page);
                    const scale = 194 / bounds.width;
                    if (bounds.height * scale > 275.5) throw new Error('單一區塊超出頁面，請減少內容或調低比例後重試。');
                    const canvas = await window.html2canvas(page, { scale: 2, backgroundColor: '#ffffff', useCORS: true, logging: false, windowWidth: window.innerWidth, scrollX: 0, scrollY: 0,
                        onclone: cloned => {
                            for (const element of cloned.querySelectorAll('.print-pagination-root *')) element.style.setProperty('color', 'transparent', 'important');
                            for (const input of cloned.querySelectorAll('.print-pagination-root input,.print-pagination-root textarea')) input.value = '';
                        }
                    });
                    if (index) pdf.addPage();
                    pdf.addImage(canvas, 'PNG', 8, 11, 194, bounds.height * scale, undefined, 'FAST');
                    for (const run of runs) {
                        pdf.setFontSize(run.height * scale * 72 / 25.4 * .8);
                        const rgb = run.color.match(/[\d.]+/g)?.slice(0, 3).map(Number) || [24, 34, 48];
                        pdf.setTextColor(...rgb);
                        pdf.setDrawColor(...rgb);
                        pdf.setLineWidth(.04);
                        pdf.setGState(new pdf.GState({ opacity: run.opacity ?? 1, 'stroke-opacity': run.opacity ?? 1 }));
                        if (run.text) pdf.text(run.text, 8 + run.x * scale, 11 + (run.y + run.height * .8) * scale, { align: run.align || 'left', renderingMode: run.bold ? 'fillThenStroke' : 'fill' });
                    }
                    canvas.width = canvas.height = 0;
                }
                const filename = String(quotationId || '奇諾影像報價單').trim().replace(/[\\/:*?"<>|\x00-\x1f]/g, '-') + '.pdf';
                const blob = pdf.output('blob');
                // Keep the download synchronous after generation; mobile browsers
                // can open the file in their download/share sheet as usual.
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                link.remove();
                setTimeout(() => URL.revokeObjectURL(url), 60000);
                return blob;
            } finally {
                this.busy = false;
                buttons.forEach(button => { button.disabled = false; button.removeAttribute('aria-busy'); });
            }
        }
    };
})();
