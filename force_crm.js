const fs = require('fs');
let code = fs.readFileSync('server.js', 'utf8');

// Restaurar do backup limpo
if (fs.existsSync('server.js.bak')) {
  code = fs.readFileSync('server.js.bak', 'utf8');
}

// 1. Injetar no navItems (menu lateral) usando o atributo correto (path)
code = code.replace(
  "const navItems = [",
  "const navItems = [\n    { path: '/operacional/crm-ops', label: 'CRM OPs', icon: '🧵' },"
);

// 2. Bloco da rota CRM
const crmBlock = `
  if (reqPath === '/operacional/crm-ops') {
    let ops = [];
    try {
      ops = db.prepare(\`
        SELECT o.*, COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity
        FROM ops o
        LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
        WHERE o.is_reversed = 0
        GROUP BY o.id ORDER BY o.created_at DESC
      \`).all();
    } catch (e) { ops = []; }

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
            <div style="font-size:13px; margin:4px 0; color:#1e293b;">\${o.product_name}</div>
            <div style="font-size:11px; color:#64748b;">\${o.total_pieces} peças</div>
            <div style="background:#e2e8f0; border-radius:6px; height:12px; margin-top:6px; overflow:hidden;">
              <div style="background:#2563eb; width:\${Math.min(pct, 100)}%; height:100%; color:#fff; font-size:8px; text-align:center; line-height:12px;">\${pct}%</div>
            </div>
          </div>
        \`;
      }).join('');

      return \`
        <div style="background:#f1f5f9; border-radius:12px; padding:12px; min-height:450px;">
          <div style="font-weight:bold; font-size:13px; margin-bottom:10px; display:flex; justify-content:space-between; color:#0f172a;">
            <span>\${st.title}</span>
            <span style="background:#cbd5e1; padding:2px 8px; border-radius:10px; font-size:11px;">\${stageOps.length}</span>
          </div>
          \${cards || '<p style="font-size:12px; color:#94a3b8;">Sem OPs nesta etapa</p>'}
        </div>
      \`;
    }).join('');

    const html = pageLayout({
      title: 'CRM Kanban de OPs',
      content: \`
        <h2>🧵 CRM Operacional de OPs (Chão de Fábrica)</h2>
        <p class="hint">Acompanhamento visual em tempo real do fluxo de produção.</p>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:14px; margin-top:16px;">
          \${cols}
        </div>
      \`,
      sessionContext
    });

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }
`;

// Injetar a rota NO TOPO do manipulador do servidor http.createServer
code = code.replace(
  "const reqPath = parsedUrl.pathname;",
  `const reqPath = parsedUrl.pathname;\n${crmBlock}`
);

fs.writeFileSync('server.js', code);
console.log('✅ Rota injetada no topo do servidor com sucesso!');
