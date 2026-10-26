const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');

// Adicionar item de menu do CRM no Sidebar
const menuTarget = `<a href="/ops">`;
const menuAddition = `<a href="/operacional/crm-ops">🧵 CRM Kanban OPs</a>\n        ${menuTarget}`;
if (!code.includes('/operacional/crm-ops')) {
  code = code.replace(menuTarget, menuAddition);
}

// Função de renderização do CRM Kanban
const crmKanbanFunction = `
function renderCrmKanbanPage(req, res, sessionContext) {
  let ops = [];
  try {
    ops = db.prepare(\`
      SELECT o.*,
        COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity
      FROM ops o
      LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
      WHERE o.is_reversed = 0
      GROUP BY o.id ORDER BY o.created_at DESC
    \`).all();
  } catch (_e) { ops = []; }

  const stages = [
    { id: 'fila', title: '1. Fila / Planejada' },
    { id: 'preparacao', title: '2. Em Preparação' },
    { id: 'costura', title: '3. Em Costura (WIP)' },
    { id: 'qualidade', title: '4. Qualidade' },
    { id: 'finalizada', title: '5. Finalizada' },
    { id: 'pausada', title: '🔴 Pausada' }
  ];

  const cols = stages.map(st => {
    const stageOps = ops.filter(o => (o.crm_stage || 'fila') === st.id);
    const cards = stageOps.map(o => {
      const pct = Math.round(((o.produced_quantity || 0) / (o.total_pieces || 1)) * 100);
      return \`
        <div style="background:#fff; border:1px solid #e2e8f0; border-radius:10px; padding:12px; margin-bottom:10px; border-left:5px solid #2563eb;">
          <div style="display:flex; justify-content:space-between; font-weight:bold;">
            <span>\${o.op_number}</span>
            <span style="font-size:11px; color:#64748b;">\${o.brand || ''}</span>
          </div>
          <div style="font-size:13px; margin:4px 0;">\${o.product_name}</div>
          <div style="font-size:11px; color:#64748b;">\${o.total_pieces} pçs</div>
          <div style="background:#e2e8f0; border-radius:6px; height:12px; margin-top:6px; overflow:hidden;">
            <div style="background:#2563eb; width:\${Math.min(pct, 100)}%; height:100%; color:#fff; font-size:8px; text-align:center; line-height:12px;">\${pct}%</div>
          </div>
        </div>
      \`;
    }).join('');

    return \`
      <div style="background:#f1f5f9; border-radius:12px; padding:12px; min-height:400px;">
        <div style="font-weight:bold; font-size:13px; margin-bottom:10px; display:flex; justify-content:space-between;">
          <span>\${st.title}</span>
          <span style="background:#cbd5e1; padding:2px 8px; border-radius:10px; font-size:11px;">\${stageOps.length}</span>
        </div>
        \${cards || '<p style="font-size:12px; color:#94a3b8;">Sem OPs</p>'}
      </div>
    \`;
  }).join('');

  const html = pageLayout({
    title: 'CRM Kanban de OPs',
    content: \`
      <h2>CRM Operacional de OPs (Chão de Fábrica)</h2>
      <p class="hint">Acompanhamento visual em tempo real do fluxo de produção.</p>
      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:14px; margin-top:16px;">
        \${cols}
      </div>
    \`,
    sessionContext
  });

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
`;

// Injetar a função e a rota
if (!code.includes('renderCrmKanbanPage')) {
  code = code.replace("if (reqPath === '/dashboard' || reqPath === '/') {", `${crmKanbanFunction}\nif (reqPath === '/operacional/crm-ops') { return renderCrmKanbanPage(req, res, sessionContext); }\nif (reqPath === '/dashboard' || reqPath === '/') {`);
}

fs.writeFileSync('server.js', code);
console.log('✅ Rota do CRM Kanban injetada no server.js original com sucesso!');
