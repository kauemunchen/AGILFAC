// Completa o "-001" nas OPs cadastradas só com 7 dígitos (ex.: 1801772 -> 1801772-001).
// Também atualiza as cópias do número em embarques e fechamentos de célula (mesma OP).
// Se já existir uma OP "XXXXXXX-001", NÃO altera e lista como conflito para revisão.
//
// Uso:
//   node scripts/corrigir-sufixo-op.js              -> só mostra o que seria alterado (todas as empresas)
//   node scripts/corrigir-sufixo-op.js --aplicar    -> faz backup de cada banco e aplica
//   node scripts/corrigir-sufixo-op.js --aplicar mais-textil   -> só uma empresa
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const args = process.argv.slice(2);
const apply = args.includes('--aplicar');
const only = args.filter(a => !a.startsWith('--'));
const ROOT = path.join(__dirname, '..');
const TENANTS_DIR = path.join(ROOT, 'data', 'tenants');
const stamp = new Date().toISOString().replace(/[:.]/g, '-');

const files = fs.readdirSync(TENANTS_DIR)
  .filter(f => f.endsWith('.sqlite'))
  .filter(f => !only.length || only.includes(f.replace('.sqlite', '')));

console.log(apply ? '=== MODO APLICAR ===' : '=== SIMULAÇÃO (nada será alterado). Para aplicar: --aplicar ===');
let grandTotal = 0;
for (const file of files) {
  const dbPath = path.join(TENANTS_DIR, file);
  const db = new DatabaseSync(dbPath);
  const hasTable = name => Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
  const rows = db.prepare(`SELECT id, op_number, product_name, status_color FROM ops WHERE TRIM(op_number) GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9]' ORDER BY op_number`).all();
  const toFix = [];
  const conflicts = [];
  for (const row of rows) {
    const target = `${row.op_number.trim()}-001`;
    const exists = db.prepare('SELECT id FROM ops WHERE TRIM(op_number) = ? COLLATE NOCASE').get(target);
    (exists ? conflicts : toFix).push({ ...row, target, conflictId: exists?.id });
  }
  console.log(`\n--- ${file.replace('.sqlite', '')}: ${toFix.length} OP(s) para corrigir, ${conflicts.length} conflito(s)`);
  toFix.slice(0, 15).forEach(r => console.log(`  ${r.op_number} -> ${r.target}  (${r.product_name}, ${r.status_color})`));
  if (toFix.length > 15) console.log(`  ... e mais ${toFix.length - 15}`);
  conflicts.forEach(r => console.log(`  CONFLITO: ${r.op_number} e ${r.target} existem as duas (ids ${r.id} e ${r.conflictId}) — revisar manualmente`));
  grandTotal += toFix.length;

  if (apply && toFix.length) {
    const backupPath = path.join(ROOT, 'backups', `pre-sufixo-op-${file.replace('.sqlite', '')}-${stamp}.sqlite`);
    fs.mkdirSync(path.dirname(backupPath), { recursive: true });
    db.exec(`VACUUM INTO '${backupPath.replace(/'/g, "''")}'`);
    db.exec('BEGIN');
    try {
      const upOp = db.prepare('UPDATE ops SET op_number = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
      const upShip = hasTable('shipment_items') ? db.prepare('UPDATE shipment_items SET op_number = ? WHERE op_id = ?') : null;
      const upCell = hasTable('cell_closure_items') ? db.prepare('UPDATE cell_closure_items SET op_number = ? WHERE op_id = ?') : null;
      for (const r of toFix) {
        upOp.run(r.target, r.id);
        if (upShip) upShip.run(r.target, r.id);
        if (upCell) upCell.run(r.target, r.id);
      }
      db.exec('COMMIT');
      console.log(`  ✓ aplicado. Backup antes da alteração: ${path.relative(ROOT, backupPath)}`);
    } catch (error) {
      db.exec('ROLLBACK');
      console.log(`  ✗ ERRO, nada foi alterado: ${error.message}`);
    }
  }
  db.close();
}
console.log(`\nTotal: ${grandTotal} OP(s) ${apply ? 'corrigidas' : 'seriam corrigidas'}.`);
