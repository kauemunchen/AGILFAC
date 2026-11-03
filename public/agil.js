// AgilFac — facilidades globais: desfazer, sem internet, leitor de código de barras, atalhos e filtros lembrados.
(() => {
  const role = document.body.dataset.role || '';
  const launcherOnly = role === 'lancador' || role === 'apontamento';
  const get = k => { try { return localStorage.getItem(k); } catch (_) { return null; } };
  const set = (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} };
  const del = k => { try { localStorage.removeItem(k); } catch (_) {} };
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const isTyping = el => el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));

  // ---------- Aviso flutuante ----------
  let toastBox = document.querySelector('.agil-toasts');
  if (!toastBox) { toastBox = document.createElement('div'); toastBox.className = 'agil-toasts'; document.body.appendChild(toastBox); }
  function toast(html, { ms = 5000, cls = '' } = {}) {
    const t = document.createElement('div');
    t.className = 'agil-toast ' + cls;
    t.innerHTML = html;
    toastBox.appendChild(t);
    if (ms) setTimeout(() => t.remove(), ms);
    return t;
  }
  window.AgilToast = toast;

  // ---------- Desfazer (10 s) ----------
  const params = new URLSearchParams(location.search);
  const undoToken = params.get('undo');
  if (undoToken) {
    params.delete('undo');
    history.replaceState(null, '', location.pathname + (params.toString() ? '?' + params : '') + location.hash);
    let left = 10;
    const t = toast('<span>Registro salvo.</span><button type="button" class="agil-undo">Desfazer <b>10</b></button>', { ms: 0, cls: 'is-undo' });
    const btn = t.querySelector('button');
    const timer = setInterval(() => { left -= 1; btn.querySelector('b').textContent = left; if (left <= 0) { clearInterval(timer); t.remove(); } }, 1000);
    btn.addEventListener('click', async () => {
      clearInterval(timer);
      btn.disabled = true; btn.textContent = 'Desfazendo…';
      try {
        const r = await fetch('/desfazer', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'token=' + encodeURIComponent(undoToken) });
        const d = await r.json();
        const p = new URLSearchParams(location.search);
        p.delete('notice'); p.delete('error');
        p.set(d.ok ? 'notice' : 'error', d.message);
        location.replace(location.pathname + '?' + p.toString());
      } catch (_) { t.remove(); toast('Não foi possível desfazer. Use Estornos.', { cls: 'is-error' }); }
    });
  }

  // ---------- Sem internet: guarda lançamentos e envia quando voltar ----------
  const QKEY = 'agilfac-offline-queue';
  const readQ = () => { try { return JSON.parse(get(QKEY) || '[]'); } catch (_) { return []; } };
  const writeQ = q => set(QKEY, JSON.stringify(q));
  const OFFLINE_FORMS = ['/productions', '/productions/hourly', '/productions/hourly/quadro'];
  const badge = document.createElement('div');
  badge.className = 'agil-offline';
  badge.hidden = true;
  document.body.appendChild(badge);
  function paintBadge() {
    const q = readQ();
    const failed = q.filter(i => i.failed).length;
    if (!navigator.onLine) { badge.hidden = false; badge.className = 'agil-offline is-off'; badge.textContent = `📴 Sem internet${q.length ? ` · ${q.length} lançamento(s) aguardando envio` : ''}`; return; }
    if (q.length) { badge.hidden = false; badge.className = 'agil-offline' + (failed ? ' is-error' : ''); badge.innerHTML = failed ? `⚠️ ${failed} lançamento(s) não aceitos ao reenviar <button type="button" data-q-show>ver</button>` : `⏳ Enviando ${q.length} lançamento(s)…`; return; }
    badge.hidden = true;
  }
  window.AgilOffline = {
    queue(action, body, label) { const q = readQ(); q.push({ action, body, label, at: new Date().toISOString() }); writeQ(q); paintBadge(); }
  };
  let flushing = false;
  async function flush() {
    if (flushing || !navigator.onLine) return paintBadge();
    let q = readQ();
    if (!q.some(i => !i.failed)) return paintBadge();
    flushing = true; paintBadge();
    for (const item of q.filter(i => !i.failed)) {
      try {
        const r = await fetch(item.action, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: item.body });
        if (r.url.includes('/login')) { flushing = false; toast('Faça login de novo para enviar os lançamentos guardados.', { cls: 'is-error', ms: 8000 }); return paintBadge(); }
        let ok = r.ok && !/[?&]error=/.test(r.url);
        if ((r.headers.get('content-type') || '').includes('json')) { const d = await r.json(); ok = !!d.ok; item.message = d.message; }
        if (ok) { q = readQ().filter(x => !(x.at === item.at && x.action === item.action)); writeQ(q); }
        else { item.failed = true; item.message = item.message || decodeURIComponent((r.url.match(/error=([^&]*)/) || [])[1] || 'Recusado').replace(/\+/g, ' '); writeQ(readQ().map(x => (x.at === item.at && x.action === item.action) ? item : x)); }
      } catch (_) { break; }
    }
    flushing = false;
    const rest = readQ();
    if (!rest.length) toast('✅ Lançamentos guardados foram enviados.', { ms: 6000 });
    paintBadge();
  }
  badge.addEventListener('click', e => {
    if (!e.target.closest('[data-q-show]')) return;
    const failed = readQ().filter(i => i.failed);
    const t = toast(`<div><strong>Não aceitos:</strong><ul>${failed.map(i => `<li>${esc(i.label || i.action)} — ${esc(i.message || '')}</li>`).join('')}</ul><button type="button" data-q-clear>Descartar e lançar de novo à mão</button></div>`, { ms: 0, cls: 'is-error' });
    t.querySelector('[data-q-clear]').addEventListener('click', () => { writeQ(readQ().filter(i => !i.failed)); t.remove(); paintBadge(); });
  });
  window.addEventListener('online', flush);
  window.addEventListener('offline', paintBadge);
  document.addEventListener('submit', e => {
    const form = e.target;
    const action = new URL(form.action, location.href).pathname;
    if (navigator.onLine || form.method.toLowerCase() !== 'post' || !OFFLINE_FORMS.includes(action)) return;
    e.preventDefault();
    const body = new URLSearchParams(new FormData(form));
    if (e.submitter && e.submitter.name) body.set(e.submitter.name, e.submitter.value);
    const label = [body.get('op_number'), body.get('produced_quantity') && body.get('produced_quantity') + ' pç', body.get('hour_slot')].filter(Boolean).join(' · ') || 'Lançamento';
    window.AgilOffline.queue(action, body.toString(), label);
    toast('📴 Sem internet: lançamento guardado neste aparelho. Será enviado sozinho quando a conexão voltar.', { ms: 7000, cls: 'is-warn' });
    const qty = form.querySelector('[name=produced_quantity]');
    if (qty) { qty.value = ''; qty.focus(); }
  }, true);
  paintBadge();
  setTimeout(flush, 800);

  // ---------- Leitor de código de barras (digitação muito rápida terminando em Enter) ----------
  let buf = '', lastAt = 0, startEl = null;
  document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const now = Date.now();
    if (now - lastAt > 60) { buf = ''; startEl = document.activeElement; }
    lastAt = now;
    if (e.key === 'Enter') {
      const code = buf.trim();
      buf = '';
      if (code.length < 5 || !/^[0-9A-Za-z\-\.]+$/.test(code)) return;
      // Leu dentro de um campo: deixa o próprio campo tratar (lançamento, embarque, busca)
      if (isTyping(startEl) && startEl.id !== 'global-search') return;
      e.preventDefault();
      handleScan(code);
      return;
    }
    if (e.key.length === 1) buf += e.key;
  }, true);
  function handleScan(code) {
    const kb = document.getElementById('kb-find-input');
    if (kb) { kb.value = code; kb.form.requestSubmit(); return; }
    const opField = document.querySelector('form input[name=op_number]:not([type=hidden])');
    if (opField) {
      opField.value = code; opField.dispatchEvent(new Event('input', { bubbles: true })); opField.dispatchEvent(new Event('change', { bubbles: true }));
      if ((opField.form.method || 'get').toLowerCase() === 'get') opField.form.requestSubmit(); else opField.focus();
      return;
    }
    location.href = '/buscar?q=' + encodeURIComponent(code);
  }

  // ---------- Atalhos de teclado ----------
  const SHORTCUTS = launcherOnly
    ? [['L', 'Lançar (quadro hora)', '/productions/hourly/quadro'], ['/', 'Buscar', null]]
    : [['D', 'Dashboard', '/'], ['L', 'Lançar (quadro hora)', '/productions/hourly/quadro'], ['R', 'Lançamento rápido', '/productions/new'], ['N', 'Nova OP', '/ops/new'], ['O', 'Lista de OPs', '/ops?view=lista'], ['Q', 'Quadro de OPs', '/ops?view=quadro'], ['E', 'Embarque', '/shipments/new'], ['A', 'Acompanhamento', '/acompanhamento/diario'], ['T', 'Modo TV', '/tv'], ['/', 'Buscar', null]];
  function showHelp() {
    const old = document.querySelector('.agil-help');
    if (old) return old.remove();
    const d = document.createElement('div');
    d.className = 'agil-help';
    d.innerHTML = `<div class="agil-help-card"><strong>Atalhos de teclado</strong><ul>${SHORTCUTS.map(([k, l]) => `<li><kbd>${k}</kbd>${l}</li>`).join('')}<li><kbd>?</kbd>Mostrar/ocultar esta ajuda</li><li><kbd>Esc</kbd>Fechar</li></ul><p>Leitor de código de barras: bipe a etiqueta em qualquer tela para abrir a OP.</p></div>`;
    d.addEventListener('click', ev => { if (ev.target === d) d.remove(); });
    document.body.appendChild(d);
  }
  document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey || e.altKey || isTyping(document.activeElement) || document.querySelector('dialog[open]')) return;
    if (e.key === 'Escape') { document.querySelector('.agil-help')?.remove(); return; }
    if (e.key === '?') { e.preventDefault(); showHelp(); return; }
    if (e.key === '/') { const s = document.getElementById('global-search'); if (s) { e.preventDefault(); s.focus(); } return; }
    const hit = SHORTCUTS.find(([k, , href]) => href && k.toLowerCase() === e.key.toLowerCase());
    if (hit) { e.preventDefault(); if (hit[2] === '/tv') window.open('/tv', '_blank'); else location.href = hit[2]; }
  });
  const topBar = document.querySelector('.top-meta-actions');
  if (topBar && !matchMedia('(pointer: coarse)').matches) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'btn secondary agil-help-btn'; b.title = 'Atalhos de teclado (?)'; b.textContent = '⌨';
    b.addEventListener('click', showHelp);
    topBar.prepend(b);
  }

  // ---------- Filtros lembrados e visões salvas ----------
  const REMEMBER = ['/ops', '/shipments', '/acompanhamento/diario', '/premios/producao', '/closures', '/custos'];
  const path = location.pathname;
  if (REMEMBER.includes(path)) {
    const key = 'agilfac-filters:' + path;
    const p = new URLSearchParams(location.search);
    ['notice', 'error', 'undo'].forEach(k => p.delete(k));
    if (p.get('limpar') === '1') {
      del(key);
      history.replaceState(null, '', path);
    } else if (!location.search) {
      const saved = get(key);
      if (saved) { location.replace(path + '?' + saved); return; }
    } else if (p.toString()) set(key, p.toString());
    // Link "Limpar filtros" nos formulários de filtro
    const filterForm = document.querySelector('form.inline-form[method=get]');
    if (filterForm && [...p.keys()].some(k => k !== 'view' && p.get(k)) && !filterForm.querySelector('.agil-clear')) {
      const a = document.createElement('a');
      a.className = 'btn secondary agil-clear'; a.href = path + '?limpar=1'; a.textContent = 'Limpar filtros';
      filterForm.appendChild(a);
    }
    if (path === '/ops' && filterForm) {
      const VKEY = 'agilfac-views:/ops';
      const views = () => { try { return JSON.parse(get(VKEY) || '[]'); } catch (_) { return []; } };
      const bar = document.createElement('div');
      bar.className = 'agil-views';
      const paint = () => {
        const cur = p.toString();
        bar.innerHTML = '<span>⭐ Visões:</span>' + views().map((v, i) => `<a class="agil-view${v.q === cur ? ' is-active' : ''}" href="/ops?${v.q}">${esc(v.name)}<button type="button" data-del="${i}" title="Remover">×</button></a>`).join('') + '<button type="button" class="agil-view-add">+ Salvar esta visão</button>';
      };
      paint();
      bar.addEventListener('click', e => {
        const d = e.target.closest('[data-del]');
        if (d) { e.preventDefault(); const v = views(); v.splice(Number(d.dataset.del), 1); set(VKEY, JSON.stringify(v)); paint(); return; }
        if (e.target.closest('.agil-view-add')) {
          const name = prompt('Nome da visão (ex.: Atrasadas COLCCI):');
          if (!name) return;
          const v = views(); v.push({ name: name.slice(0, 40), q: p.toString() || 'view=lista' }); set(VKEY, JSON.stringify(v)); paint();
        }
      });
      filterForm.parentNode.insertBefore(bar, filterForm);
    }
  }
})();
