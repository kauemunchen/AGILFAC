const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'agilfac-billing-test-'));
const APP_ROOT = path.join(TEMP_ROOT, 'app');
const PORT = 8199;
const LOGIN = { company: 'mais-textil', username: 'qa-billing', password: 'qa-billing-123' };
const TEST_DATE = '2026-05-08';
const VALID_OPS = ['OP-BILL-QA-1', 'OP-BILL-QA-2'];
const NOT_BILLED_OP = 'OP-BILL-QA-3';
const PRE_BILLED_OP = 'OP-BILL-QA-OLD';
const RETURNED_OP = 'OP-BILL-QA-RET';
const INVALID_OP = 'OP-BILL-QA-X';

function copyApp() {
  fs.mkdirSync(APP_ROOT, { recursive: true });
  for (const entry of ['server.js', 'public', 'database', 'data']) {
    fs.cpSync(path.join(PROJECT_ROOT, entry), path.join(APP_ROOT, entry), { recursive: true });
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(String(password || ''), salt, 64).toString('hex')}`;
}

function ensureColumn(db, tableName, columnName, definition) {
  const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
  if (!columns.some(column => column.name === columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

function seedScenario() {
  const masterPath = path.join(APP_ROOT, 'data', 'master.sqlite');
  const masterDb = new DatabaseSync(masterPath);
  const company = masterDb.prepare('SELECT id FROM companies WHERE slug = ?').get(LOGIN.company);
  if (!company) throw new Error('Empresa de teste não encontrada no banco mestre.');
  masterDb.prepare('DELETE FROM company_users WHERE company_id = ? AND username = ?').run(company.id, LOGIN.username);
  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active)
    VALUES (?, ?, ?, ?, 'adm', 1)
  `).run(company.id, LOGIN.username, 'QA Billing', hashPassword(LOGIN.password));

  const tenantPath = path.join(APP_ROOT, 'data', 'tenants', `${LOGIN.company}.sqlite`);
  const db = new DatabaseSync(tenantPath);
  ensureColumn(db, 'ops', 'is_billed', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(db, 'ops', 'billed_at', 'TEXT');
  ensureColumn(db, 'ops', 'billing_notes', 'TEXT');
  ensureColumn(db, 'ops', 'billed_by_user_id', 'INTEGER');
  db.exec(`
    CREATE TABLE IF NOT EXISTS op_billing_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
      billed_at TEXT NOT NULL,
      notes TEXT,
      batch_reference TEXT,
      created_by_user_id INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.prepare("INSERT OR IGNORE INTO brands (name) VALUES ('Marca QA')").run();
  db.prepare("INSERT OR IGNORE INTO collections (name) VALUES ('Coleção QA')").run();

  for (const opNumber of [...VALID_OPS, NOT_BILLED_OP, PRE_BILLED_OP, RETURNED_OP]) {
    const existing = db.prepare('SELECT id FROM ops WHERE op_number = ?').get(opNumber);
    if (existing) {
      db.prepare('DELETE FROM op_billing_history WHERE op_id = ?').run(existing.id);
      db.prepare('DELETE FROM op_daily_productions WHERE op_id = ?').run(existing.id);
      db.prepare('DELETE FROM shipment_items WHERE op_id = ?').run(existing.id);
      db.prepare('DELETE FROM op_occurrences WHERE op_id = ?').run(existing.id);
      db.prepare('DELETE FROM ops WHERE id = ?').run(existing.id);
    }
  }

  const insertOp = db.prepare(`
    INSERT INTO ops (
      op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color,
      is_billed, billed_at, billing_notes
    ) VALUES (?, ?, 'producao', 'Marca QA', 'Coleção QA', 'com piloto', 'reta', ?, 1.8, 0.2, 'interno', 0.1, ?, ?, 'verde', ?, ?, ?)
  `);

  for (const opNumber of VALID_OPS) {
    insertOp.run(opNumber, `Produto ${opNumber}`, 30, TEST_DATE, 'Cenário automatizado cobrança', 0, null, null);
  }
  insertOp.run(NOT_BILLED_OP, `Produto ${NOT_BILLED_OP}`, 20, TEST_DATE, 'Permanece sem cobrança', 0, null, null);
  const returned = insertOp.run(RETURNED_OP, `Produto ${RETURNED_OP}`, 10, TEST_DATE, 'OP devolvida sem produção', 0, null, null);
  db.prepare(`
    UPDATE ops
    SET lifecycle_type = 'devolvida_sem_producao',
        status_color = 'azul',
        return_reason = 'Cliente devolveu sem costurar',
        returned_without_production_at = '2026-05-07 10:00:00'
    WHERE id = ?
  `).run(Number(returned.lastInsertRowid));
  const preBilled = insertOp.run(PRE_BILLED_OP, `Produto ${PRE_BILLED_OP}`, 15, TEST_DATE, 'Já cobrada antes', 1, '2026-05-01', 'Cobrança antiga');
  db.prepare(`
    INSERT INTO op_billing_history (op_id, billed_at, notes, batch_reference, created_by_user_id)
    VALUES (?, '2026-05-01', 'Cobrança antiga', 'COBR-ANTIGO', NULL)
  `).run(Number(preBilled.lastInsertRowid));
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForServer() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${PORT}/login`);
      if (response.ok) return;
    } catch (_error) {}
    await wait(250);
  }
  throw new Error('Servidor de teste não respondeu a tempo.');
}

async function request(url, options = {}, jar = { cookie: '' }) {
  const headers = new Headers(options.headers || {});
  if (jar.cookie) headers.set('cookie', jar.cookie);
  const response = await fetch(url, { ...options, headers, redirect: 'manual' });
  const setCookie = response.headers.get('set-cookie');
  if (setCookie) jar.cookie = setCookie.split(';')[0];
  return response;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function run() {
  copyApp();
  seedScenario();
  const child = spawn(process.execPath, ['server.js'], {
    cwd: APP_ROOT,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', data => process.stdout.write(data));
  child.stderr.on('data', data => process.stderr.write(data));

  try {
    await waitForServer();
    const jar = { cookie: '' };
    const loginBody = new URLSearchParams({ ...LOGIN, returnTo: '/' }).toString();
    const loginResponse = await request(`http://127.0.0.1:${PORT}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: loginBody
    }, jar);
    assert(loginResponse.status === 302, 'Login não redirecionou como esperado.');
    assert(jar.cookie.includes('agilfac_session='), 'Cookie de sessão não foi criado.');

    const screenHtml = await (await request(`http://127.0.0.1:${PORT}/billing-reconciliation`, {}, jar)).text();
    assert(screenHtml.includes('Conciliação de cobrança'), 'Tela do módulo de cobrança não carregou.');

    const postBody = new URLSearchParams({
      billed_at: TEST_DATE,
      notes: 'Cobrança lote QA',
      op_numbers: `${VALID_OPS[0]}\n${VALID_OPS[1]}\n${PRE_BILLED_OP}\n${RETURNED_OP}\n${VALID_OPS[0]}\n${INVALID_OP}`
    }).toString();
    const postResponse = await request(`http://127.0.0.1:${PORT}/billing-reconciliation`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: postBody
    }, jar);
    const postHtml = await postResponse.text();
    assert(postResponse.status === 200, 'Conciliação de cobrança não retornou sucesso.');
    assert(postHtml.includes('2 OP(s) marcadas como cobradas.'), 'Resumo de cobrança não exibiu quantidade processada.');
    assert(postHtml.includes('Duplicada no texto informado'), 'Resultado não sinalizou OP duplicada.');
    assert(postHtml.includes('Já cobrada em 2026-05-01'), 'Resultado não sinalizou OP já cobrada.');
    assert(postHtml.includes('OP devolvida sem produção'), 'Resultado não sinalizou OP devolvida.');
    assert(postHtml.includes('OP não encontrada'), 'Resultado não sinalizou OP inválida.');

    const billedListHtml = await (await request(`http://127.0.0.1:${PORT}/ops?billing_status=billed`, {}, jar)).text();
    assert(billedListHtml.includes(VALID_OPS[0]) && billedListHtml.includes(VALID_OPS[1]), 'Filtro de OPs cobradas não listou as OPs conciliadas.');
    assert(!billedListHtml.includes(NOT_BILLED_OP), 'Filtro de OPs cobradas trouxe OP não cobrada.');

    const notBilledListHtml = await (await request(`http://127.0.0.1:${PORT}/ops?billing_status=not_billed`, {}, jar)).text();
    assert(notBilledListHtml.includes(NOT_BILLED_OP), 'Filtro de OPs não cobradas não exibiu a OP pendente.');
    assert(!notBilledListHtml.includes(VALID_OPS[0]), 'Filtro de OPs não cobradas exibiu OP já cobrada.');
    assert(!notBilledListHtml.includes(RETURNED_OP), 'Filtro de OPs não cobradas exibiu OP devolvida.');

    const returnedListHtml = await (await request(`http://127.0.0.1:${PORT}/ops?billing_status=returned`, {}, jar)).text();
    assert(returnedListHtml.includes(RETURNED_OP), 'Filtro de OPs devolvidas não exibiu a OP devolvida.');
    assert(returnedListHtml.includes('Devolvida'), 'Filtro de OPs devolvidas não exibiu status de cobrança devolvida.');

    const tenantDb = new DatabaseSync(path.join(APP_ROOT, 'data', 'tenants', `${LOGIN.company}.sqlite`));
    const billedRows = tenantDb.prepare(`
      SELECT op_number, is_billed, billed_at, billing_notes FROM ops WHERE op_number IN (?, ?)
    `).all(...VALID_OPS);
    assert(billedRows.every(row => Number(row.is_billed) === 1), 'Nem todas as OPs válidas foram marcadas como cobradas no banco.');
    assert(billedRows.every(row => row.billed_at === TEST_DATE), 'Data de cobrança não foi gravada corretamente.');
    assert(billedRows.every(row => row.billing_notes === 'Cobrança lote QA'), 'Observação da cobrança não foi gravada corretamente.');

    const historyCount = tenantDb.prepare(`
      SELECT COUNT(*) AS count FROM op_billing_history WHERE op_id IN (
        SELECT id FROM ops WHERE op_number IN (?, ?)
      ) AND billed_at = ?
    `).get(...VALID_OPS, TEST_DATE).count;
    assert(Number(historyCount) === 2, 'Histórico de cobrança não registrou as duas OPs conciliadas.');

    const opDetail = tenantDb.prepare('SELECT id FROM ops WHERE op_number = ?').get(VALID_OPS[0]);
    const detailHtml = await (await request(`http://127.0.0.1:${PORT}/ops/${opDetail.id}`, {}, jar)).text();
    assert(detailHtml.includes('Histórico de cobrança'), 'Detalhe da OP não exibiu bloco de histórico de cobrança.');
    assert(detailHtml.includes('Cobrança lote QA'), 'Detalhe da OP não exibiu observação da cobrança.');

    const returnedDetail = tenantDb.prepare('SELECT id FROM ops WHERE op_number = ?').get(RETURNED_OP);
    const returnedDetailHtml = await (await request(`http://127.0.0.1:${PORT}/ops/${returnedDetail.id}`, {}, jar)).text();
    assert(returnedDetailHtml.includes('<dt>Cobrança</dt><dd>Devolvida</dd>'), 'Detalhe da OP devolvida não exibiu cobrança como devolvida.');
    assert(returnedDetailHtml.includes('Devolvida sem produção'), 'Detalhe da OP devolvida não exibiu fluxo próprio.');

    console.log('\nTeste do módulo de conciliação de cobrança concluído com sucesso.');
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
