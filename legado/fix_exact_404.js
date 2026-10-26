const fs = require('fs');

// 1. Carregar server.js original limpo
let code = fs.readFileSync('server.js', 'utf8');
if (fs.existsSync('server.js.bak')) {
  code = fs.readFileSync('server.js.bak', 'utf8');
}

// 2. Garantir o item no menu lateral (navItems)
if (!code.includes("path: '/operacional/crm-ops'")) {
  code = code.replace(
    "const navItems = [",
    "const navItems = [\n    { path: '/operacional/crm-ops', label: 'CRM OPs', icon: '🧵' },"
  );
}

// 3. Função de renderização do CRM Kanban
const crmFunctionCode = `
function renderCrmKanbanPage(query = {}, role = 'adm') {
  let ops = [];
  try {
    ops = db.prepare(\`
      SELECT o.*, COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity
      FROM ops o
      LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
      WHERE o.is_reversed = 0
      GROUP BY o.id ORDER BY o.id DESC
    \`).all();
  } catch (e) {
    console.error("Erro no CRM Kanban:", e);
    ops = [];
  }

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
      const totalPcs = Number(o.total_pieces || 1);
      const prodPcs = Number(o.produced_quantity || 0);
      const pct = Math.round((prodPcs / totalPcs) * 100);

      return \`
        <div style="background:#fff; border:1px solid #cbd5e1; border-radius:10px; padding:12px; margin-bottom:10px; border-left:5px solid #2563eb; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
          <div style="display:flex; justify-content:space-between; font-weight:bold; font-size:14px;">
            <span style="color:#1d4ed8;">\${o.op_number}</span>
            <span style="font-size:11px; background:#e0f2fe; color:#0369a1; padding:2px 6px; border-radius:6px;">\${o.brand || 'Geral'}</span>
          </div>
          <div style="font-size:13px; font-weight:600; margin:6px 0; color:#0f172a;">\${o.product_name}</div>
          <div style="font-size:11px; color:#64748b;">Total: <strong>\${o.total_pieces}</strong> pçs</div>
          
          <div style="background:#e2e8f0; border-radius:6px; height:14px; margin-top:8px; overflow:hidden;">
            <div style="background:#2563eb; width:\${Math.min(pct, 100)}%; height:100%; color:#fff; font-size:9px; font-weight:bold; text-align:center; line-height:14px;">\${pct}%</div>
          </div>
          <div style="font-size:10px; color:#64748b; margin-top:4px; text-align:right;">\${prodPcs} de \${totalPcs} pçs</div>
        </div>
      \`;
    }).join('');

    return \`
      <div style="background:#f8fafc; border-radius:12px; padding:12px; min-height:450px; border:1px solid #cbd5e1;">
        <div style="font-weight:bold; font-size:13px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center; color:#0f172a; border-bottom:2px solid #cbd5e1; padding-bottom:6px;">
          <span>\${st.title}</span>
          <span style="background:#2563eb; color:#fff; padding:2px 8px; border-radius:10px; font-size:11px;">\${stageOps.length}</span>
        </div>
        \${cards || '<p style="font-size:12px; color:#94a3b8; text-align:center; margin-top:20px;">Sem OPs nesta coluna</p>'}
      </div>
    \`;
  }).join('');

  const content = \`
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
      <div>
        <h2 style="margin:0;">🧵 CRM Operacional de OPs (Chão de Fábrica)</h2>
        <p class="hint" style="margin:4px 0 0;">Acompanhamento visual em tempo real do fluxo de produção.</p>
      </div>
      <span style="background:#dcfce7; color:#15803d; padding:6px 12px; border-radius:8px; font-weight:bold; font-size:12px;">Total: \${ops.length} OPs</span>
    </div>
    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px;">
      \${cols}
    </div>
  \`;

  return pageLayout({ title: 'CRM OPs', content, role });
}
`;

if (!code.includes('function renderCrmKanbanPage')) {
  code += `\n${crmFunctionCode}\n`;
}

// 4. Injetar a verificação de rota EXATAMENTE antes do sendText(res, 'Not found', 404);
const notFoundTarget = "sendText(res, 'Not found', 404);";
const routeInjection = "if (req.method === 'GET' && pathname === '/operacional/crm-ops') return sendHtml(res, renderCrmKanbanPage(query, role));\n\n      " + notFoundTarget;

if (!code.includes("pathname === '/operacional/crm-ops'")) {
  code = code.replace(notFoundTarget, routeInjection);
}

fs.writeFileSync('server.js', code);
console.log('✅ Rota injetada perfeitamente antes da linha 7834!');
