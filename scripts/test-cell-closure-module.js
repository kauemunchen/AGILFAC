const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'agilfac-cell-closure-test-'));
const APP_ROOT = path.join(TEMP_ROOT, 'app');
const PORT = 8198;
const LOGIN = { company: 'mais-textil', username: 'qa-fechamento-celula', password: 'qa-fechamento-123' };
const OPS = ['OP-FECH-CEL-01', 'OP-FECH-CEL-02'];

function copyApp() {
  fs.mkdirSync(APP_ROOT, { recursive: true });
  for (const entry of ['server.js', 'public', 'database', 'data', 'package.json']) {
    fs.cpSync(path.join(PROJECT_ROOT, entry), path.join(APP_ROOT, entry), { recursive: true });
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(String(password || ''), salt, 64).toString('hex')}`;
}

function seedScenario() {
  const masterPath = path.join(APP_ROOT, 'data', 'master.sqlite');
  const masterDb = new DatabaseSync(masterPath);
  const company = masterDb.prepare('SELECT id FROM companies WHERE slug = ?').get('mais-textil');
  if (!company) throw new Error('Empresa de teste não encontrada no banco mestre.');
  masterDb.prepare('DELETE FROM company_users WHERE company_id = ? AND username = ?').run(company.id, LOGIN.username);
  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active)
    VALUES (?, ?, ?, ?, 'adm', 1)
  `).run(company.id, LOGIN.username, 'QA Fechamento Célula', hashPassword(LOGIN.password));

  const tenantPath = path.join(APP_ROOT, 'data', 'tenants', 'mais-textil.sqlite');
  const db = new DatabaseSync(tenantPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS cell_closures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      cell_id INTEGER NOT NULL REFERENCES sewing_cells(id),
      supplier_rate_per_minute REAL NOT NULL DEFAULT 0,
      cell_rate_per_minute REAL NOT NULL DEFAULT 0,
      notes TEXT,
      total_ops INTEGER NOT NULL DEFAULT 0,
      total_pieces INTEGER NOT NULL DEFAULT 0,
      total_minutes REAL NOT NULL DEFAULT 0,
      total_received_amount REAL NOT NULL DEFAULT 0,
      total_paid_amount REAL NOT NULL DEFAULT 0,
      total_profit_amount REAL NOT NULL DEFAULT 0,
      created_by_user_id INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS cell_closure_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      closure_id INTEGER NOT NULL REFERENCES cell_closures(id) ON DELETE CASCADE,
      op_id INTEGER NOT NULL REFERENCES ops(id),
      op_number TEXT NOT NULL,
      product_name TEXT NOT NULL,
      brand TEXT,
      total_pieces INTEGER NOT NULL DEFAULT 0,
      minutes_per_piece REAL NOT NULL DEFAULT 0,
      total_minutes REAL NOT NULL DEFAULT 0,
      supplier_rate_per_minute REAL NOT NULL DEFAULT 0,
      cell_rate_per_minute REAL NOT NULL DEFAULT 0,
      received_amount REAL NOT NULL DEFAULT 0,
      paid_amount REAL NOT NULL DEFAULT 0,
      profit_amount REAL NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (closure_id, op_id)
    );
  `);

  let cell = db.prepare('SELECT id, name FROM sewing_cells WHERE name = ?').get('Célula Fechamento QA');
  if (!cell) {
    const result = db.prepare('INSERT INTO sewing_cells (name, is_active, notes) VALUES (?, 1, ?)').run('Célula Fechamento QA', 'Criada pelo teste automatizado');
    cell = { id: Number(result.lastInsertRowid), name: 'Célula Fechamento QA' };
  }

  db.prepare('DELETE FROM cell_closure_items WHERE closure_id IN (SELECT id FROM cell_closures WHERE title = ?)').run('Fechamento QA Junho');
  db.prepare('DELETE FROM cell_closures WHERE title = ?').run('Fechamento QA Junho');

  for (const [index, opNumber] of OPS.entries()) {
    const existing = db.prepare('SELECT id FROM ops WHERE op_number = ?').get(opNumber);
    if (existing) {
      db.prepare('DELETE FROM op_cell_transfers WHERE op_id = ?').run(existing.id);
      db.prepare('DELETE FROM op_daily_productions WHERE op_id = ?').run(existing.id);
      db.prepare('DELETE FROM ops WHERE id = ?').run(existing.id);
    }
    const result = db.prepare(`
      INSERT INTO ops (
        op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
        total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color
      ) VALUES (?, ?, 'producao', ?, ?, 'com piloto', 'reta', ?, ?, 0, 'interno', 0.25, ?, ?, 'rosa')
    `).run(opNumber, `Produto QA ${index + 1}`, 'Marca QA', 'Coleção QA', index === 0 ? 10 : 5, index === 0 ? 1.5 : 2.0, '2026-06-10', 'Cenário automático para fechamento de células');
    db.prepare(`INSERT INTO op_cell_transfers (op_id, cell_id, quantity_sent, quantity_returned, sent_at, sent_notes) VALUES (?, ?, ?, 0, '2026-06-10', 'Envio para teste do fechamento')`).run(Number(result.lastInsertRowid), cell.id, index === 0 ? 10 : 5);
  }

  return { tenantPath, cell };
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
  const seeded = seedScenario();
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

    const screenHtml = await (await request(`http://127.0.0.1:${PORT}/cells/closures`, {}, jar)).text();
    assert(screenHtml.includes('Fechamento de células'), 'Tela do módulo de fechamento de células não carregou.');
    assert(screenHtml.includes('Fech. células'), 'Menu não exibiu o item de fechamento de células.');

    const postParams = new URLSearchParams({
      title: 'Fechamento QA Junho',
      start_date: '2026-06-01',
      end_date: '2026-06-10',
      cell_id: String(seeded.cell.id),
      supplier_rate_per_minute: '0.80',
      cell_rate_per_minute: '0.55',
      op_numbers: OPS.join('\n'),
      notes: 'Teste automatizado do fechamento de células'
    });
    postParams.append('item_op_number', OPS[0]);
    postParams.append('item_supplier_rate_per_minute', '0.82');
    postParams.append('item_cell_rate_per_minute', '0.50');
    postParams.append('item_op_number', OPS[1]);
    postParams.append('item_supplier_rate_per_minute', '0.70');
    postParams.append('item_cell_rate_per_minute', '0.60');
    const postBody = postParams.toString();
    const postResponse = await request(`http://127.0.0.1:${PORT}/cells/closures`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: postBody
    }, jar);
    assert(postResponse.status === 302, 'Criação do fechamento de células deveria redirecionar.');
    const location = postResponse.headers.get('location') || '';
    assert(location.startsWith('/cells/closures/'), 'Redirecionamento não abriu o detalhe do fechamento salvo.');

    const detailHtml = await (await request(`http://127.0.0.1:${PORT}${location}`, {}, jar)).text();
    assert(detailHtml.includes('Fechamento QA Junho'), 'Detalhe não exibiu o título salvo.');
    assert(detailHtml.includes('OP-FECH-CEL-01') && detailHtml.includes('OP-FECH-CEL-02'), 'Detalhe não exibiu as OPs salvas.');
    assert(detailHtml.includes('R$ 5,80') || detailHtml.includes('R$ 5,80'), 'Detalhe não exibiu o lucro total esperado.');
    assert(detailHtml.includes('Fornecedor/min.') && detailHtml.includes('Célula/min.'), 'Detalhe não exibiu as colunas de preço por minuto por OP.');
    assert(detailHtml.includes('Recebido') && detailHtml.includes('Pago') && detailHtml.includes('Lucro'), 'Detalhe não exibiu as colunas financeiras obrigatórias.');

    const listHtml = await (await request(`http://127.0.0.1:${PORT}/cells/closures`, {}, jar)).text();
    assert(listHtml.includes('Fechamento QA Junho'), 'Listagem não exibiu o fechamento recém salvo.');

    const tenantDb = new DatabaseSync(seeded.tenantPath);
    const closure = tenantDb.prepare('SELECT * FROM cell_closures WHERE title = ?').get('Fechamento QA Junho');
    assert(closure, 'Fechamento não foi salvo no banco.');
    assert(Number(closure.total_ops) === 2, 'Fechamento não gravou o total de OPs corretamente.');
    assert(Number(closure.total_pieces) === 15, 'Fechamento não gravou o total de peças corretamente.');
    assert(Number(closure.total_minutes) === 25, 'Fechamento não gravou o total de minutos corretamente.');
    assert(Number(closure.total_received_amount) === 19.3, 'Fechamento não gravou o total recebido corretamente.');
    assert(Number(closure.total_paid_amount) === 13.5, 'Fechamento não gravou o total pago corretamente.');
    assert(Number(closure.total_profit_amount) === 5.8, 'Fechamento não gravou o total de lucro corretamente.');

    const items = tenantDb.prepare('SELECT op_number, supplier_rate_per_minute, cell_rate_per_minute, total_minutes, received_amount, paid_amount, profit_amount FROM cell_closure_items WHERE closure_id = ? ORDER BY op_number').all(closure.id);
    assert(items.length === 2, 'Itens do fechamento não foram salvos corretamente.');
    assert(items[0].op_number === 'OP-FECH-CEL-01' && Number(items[0].supplier_rate_per_minute) === 0.82 && Number(items[0].cell_rate_per_minute) === 0.5 && Number(items[0].profit_amount) === 4.8, 'Primeira OP não gravou o cálculo esperado.');
    assert(items[1].op_number === 'OP-FECH-CEL-02' && Number(items[1].supplier_rate_per_minute) === 0.7 && Number(items[1].cell_rate_per_minute) === 0.6 && Number(items[1].profit_amount) === 1, 'Segunda OP não gravou o cálculo esperado.');

    console.log('\nTeste do módulo de fechamento de células concluído com sucesso.');
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
