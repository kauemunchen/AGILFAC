// T0.8 — Cópia consistente de todos os bancos (mestre + empresas) com VACUUM INTO.
// Roda DENTRO do container (o host chama via docker exec). Não copia o arquivo direto,
// para não pegar o banco no meio de uma gravação (WAL).
// Uso: node scripts/backup.js <pasta-destino>
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const dest = path.resolve(ROOT, process.argv[2] || `backups/snap-${Date.now()}`);
fs.mkdirSync(path.join(dest, 'tenants'), { recursive: true });

const sources = [{ src: path.join(ROOT, 'data', 'master.sqlite'), out: path.join(dest, 'master.sqlite') }];
const tenantsDir = path.join(ROOT, 'data', 'tenants');
for (const file of fs.readdirSync(tenantsDir).filter(f => f.endsWith('.sqlite'))) {
  sources.push({ src: path.join(tenantsDir, file), out: path.join(dest, 'tenants', file) });
}

let failures = 0;
for (const { src, out } of sources) {
  try {
    const db = new DatabaseSync(src, { readOnly: true });
    db.exec(`VACUUM INTO '${out.replace(/'/g, "''")}'`);
    db.close();
    const check = new DatabaseSync(out, { readOnly: true });
    const ok = check.prepare('PRAGMA integrity_check').get();
    check.close();
    const status = Object.values(ok)[0];
    if (status !== 'ok') throw new Error(`integrity_check: ${status}`);
    console.log(`OK ${path.relative(ROOT, src)} (${(fs.statSync(out).size / 1024).toFixed(0)} KB)`);
  } catch (error) {
    failures += 1;
    console.error(`ERRO ${path.relative(ROOT, src)}: ${error.message}`);
  }
}
if (failures) process.exit(1);
