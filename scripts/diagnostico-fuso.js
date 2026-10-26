// T0.2 — Diagnóstico (somente leitura): lançamentos feitos entre 21h e 0h (Brasília)
// que provavelmente receberam a data do DIA SEGUINTE por causa do fuso UTC antigo.
// Critério: production_date = data UTC do created_at E diferente da data em Brasília.
// Não altera nada. Uso: node scripts/diagnostico-fuso.js
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const TENANTS_DIR = path.join(__dirname, '..', 'data', 'tenants');
const files = fs.readdirSync(TENANTS_DIR).filter(f => f.endsWith('.sqlite'));

let total = 0;
for (const file of files) {
  const db = new DatabaseSync(path.join(TENANTS_DIR, file), { readOnly: true });
  const rows = db.prepare(`
    SELECT p.id, p.production_date, p.created_at,
           datetime(p.created_at, '-3 hours') AS created_brt,
           o.op_number, e.full_name AS colaborador, p.produced_quantity, p.produced_minutes, p.is_reversed
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    LEFT JOIN employees e ON e.id = p.employee_id
    WHERE p.production_date = date(p.created_at)
      AND p.production_date <> date(p.created_at, '-3 hours')
    ORDER BY p.created_at
  `).all();
  db.close();

  console.log(`\n=== ${file.replace('.sqlite', '')}: ${rows.length} lançamento(s) suspeito(s)`);
  for (const r of rows) {
    console.log(
      `#${r.id} | gravado ${r.created_brt} (Brasília) | data do lançamento ${r.production_date}` +
      ` | OP ${r.op_number} | ${r.colaborador || '-'} | ${r.produced_quantity} pç | ${Number(r.produced_minutes).toFixed(2)} min` +
      (r.is_reversed ? ' | ESTORNADO' : '')
    );
  }
  total += rows.length;
}
console.log(`\nTotal: ${total}. Revisar manualmente; nada foi alterado.`);
