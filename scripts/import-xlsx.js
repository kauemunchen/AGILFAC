const path = require('path');
const XLSX = require('xlsx');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const MASTER_DB_PATH = path.join(DATA_DIR, 'master.sqlite');
const LEGACY_DB_PATH = path.join(DATA_DIR, 'app.sqlite');

const args = process.argv.slice(2);
const companyArg = args.find(arg => arg.startsWith('--company='));
const companySlug = companyArg ? companyArg.slice('--company='.length).trim() : '';
const file = args.find(arg => !arg.startsWith('--'));

if (!file) {
  console.error('Uso: node scripts/import-xlsx.js [--company=slug-da-empresa] <arquivo.xlsx>');
  process.exit(1);
}

function resolveTenantDbPath() {
  if (!companySlug) return LEGACY_DB_PATH;
  const masterDb = new DatabaseSync(MASTER_DB_PATH);
  const company = masterDb.prepare('SELECT db_path FROM companies WHERE LOWER(slug) = LOWER(?) LIMIT 1').get(companySlug);
  if (!company) {
    console.error(`Empresa não encontrada: ${companySlug}`);
    process.exit(1);
  }
  return path.isAbsolute(company.db_path) ? company.db_path : path.join(ROOT, company.db_path);
}

const db = new DatabaseSync(resolveTenantDbPath());
const wb = XLSX.readFile(file, { cellDates: false });

const SHEETS = [
  { name: 'PRODUÇÕES ', type: 'producao', source: 'PRODUÇÕES' },
  { name: 'MOSTRUARIOS ', type: 'mostruario', source: 'MOSTRUARIOS' },
  { name: 'O.PS NO PÓS F23', type: 'mostruario', source: 'O.PS NO PÓS F23' }
];

function excelDateToISO(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) return value;
  if (typeof value === 'number') {
    const utcDays = Math.floor(value - 25569);
    const utcValue = utcDays * 86400;
    const dateInfo = new Date(utcValue * 1000);
    return dateInfo.toISOString().slice(0, 10);
  }
  return null;
}

function num(v, fallback = 0) {
  if (v === '' || v === null || v === undefined) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

const insert = db.prepare(`
  INSERT INTO ops (
    barcode, op_number, product_name, op_type, brand, total_pieces,
    minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const existingStmt = db.prepare('SELECT id FROM ops WHERE op_number = ?');
const summary = [];

for (const sheetCfg of SHEETS) {
  const ws = wb.Sheets[sheetCfg.name];
  if (!ws) {
    summary.push({ sheet: sheetCfg.name, inserted: 0, skipped: 0, reason: 'aba não encontrada' });
    continue;
  }
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
  let inserted = 0;
  let skipped = 0;

  for (const row of rows) {
    const op = String(row[1] || '').trim();
    if (!op || /^o\.p/i.test(op)) continue;

    const entryDate = excelDateToISO(row[0]) || new Date().toISOString().slice(0, 10);
    const product = String(row[2] || '').trim();
    const brand = String(row[3] || '').trim() || null;
    const totalPieces = num(row[4] || row[3], 0);
    const f21 = num(row[6] || row[5], 0);
    const totalMinutes = num(row[7], 0);
    const obs = String(row[8] || '').trim();

    if (!product || !totalPieces) {
      skipped++;
      continue;
    }
    if (existingStmt.get(op)) {
      skipped++;
      continue;
    }

    const notesParts = [`Importado da aba ${sheetCfg.source}`];
    if (totalMinutes) notesParts.push(`Total planilha: ${totalMinutes}`);
    if (obs) notesParts.push(`Obs: ${obs}`);

    insert.run(
      null,
      op,
      product,
      sheetCfg.type,
      brand,
      totalPieces,
      f21,
      0,
      'interno',
      0,
      entryDate,
      notesParts.join(' | '),
      'verde'
    );
    inserted++;
  }

  summary.push({ sheet: sheetCfg.source, inserted, skipped });
}

console.log(JSON.stringify({ company: companySlug || 'legacy-default', summary }, null, 2));
