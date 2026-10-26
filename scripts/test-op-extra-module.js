const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'agilfac-op-extra-test-'));
const APP_ROOT = path.join(TEMP_ROOT, 'app');
const PORT = 8198;
const LOGIN = { company: 'mais-textil', username: 'qa-op-extra', password: 'qa-op-extra-123' };
const TEST_OP = 'OP-EXTRA-QA';
const TEST_DATE = '2026-04-10';

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
  const company = masterDb.prepare('SELECT id FROM companies WHERE slug = ?').get('mais-textil');
  if (!company) throw new Error('Empresa de teste não encontrada no banco mestre.');
  masterDb.prepare('DELETE FROM company_users WHERE company_id = ? AND username = ?').run(company.id, LOGIN.username);
  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active)
    VALUES (?, ?, ?, ?, 'adm', 1)
  `).run(company.id, LOGIN.username, 'QA Tempo Extra', hashPassword(LOGIN.password));

  const tenantPath = path.join(APP_ROOT, 'data', 'tenants', 'mais-textil.sqlite');
  const db = new DatabaseSync(tenantPath);
  ensureColumn(db, 'op_daily_productions', 'extra_time_id', 'INTEGER');
  ensureColumn(db, 'op_daily_productions', 'extra_reason_snapshot', 'TEXT');
  ensureColumn(db, 'op_daily_productions', 'extra_description_snapshot', 'TEXT');
  ensureColumn(db, 'op_daily_productions', 'extra_effective_date_snapshot', 'TEXT');
  ensureColumn(db, 'op_daily_productions', 'extra_minutes_per_piece_snapshot', 'REAL');
  const employee = db.prepare('SELECT id, registration_code, full_name FROM employees ORDER BY id LIMIT 1').get();
  if (!employee) throw new Error('Nenhum colaborador encontrado para o cenário de teste do tempo extra.');

  const existing = db.prepare('SELECT id FROM ops WHERE op_number = ?').get(TEST_OP);
  if (existing) {
    db.prepare('DELETE FROM op_daily_productions WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM op_extra_times WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM ops WHERE id = ?').run(existing.id);
  }

  const opResult = db.prepare(`
    INSERT INTO ops (
      op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color
    ) VALUES (?, ?, 'producao', ?, ?, 'com piloto', 'reta', ?, ?, ?, 'interno', 0.15, ?, ?, 'verde')
  `).run(TEST_OP, 'Produto QA tempo extra', 'Marca QA', 'Coleção QA', 50, 1.5, 0.2, TEST_DATE, 'Cenário automatizado do módulo de tempo extra');
  const opId = Number(opResult.lastInsertRowid);

  db.prepare(`
    INSERT INTO op_extra_times (
      op_id, extra_minutes_per_piece, reason, description, effective_date, notes, is_active, created_by_user_id, created_at, updated_at
    ) VALUES (?, 0.5, 'retrabalho QA', 'Validação automática', ?, 'Criado pelo teste automatizado', 1, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `).run(opId, TEST_DATE);

  const extraRow = db.prepare('SELECT id FROM op_extra_times WHERE op_id = ? ORDER BY id DESC LIMIT 1').get(opId);
  db.prepare(`
    INSERT INTO op_daily_productions (
      op_id, employee_id, production_date, produced_quantity, used_minutes_f21, normal_minutes, extra_minutes, produced_minutes,
      extra_time_id, extra_reason_snapshot, extra_description_snapshot, extra_effective_date_snapshot, extra_minutes_per_piece_snapshot,
      created_by_user_id, is_reversed, created_at
    ) VALUES (?, ?, ?, 4, 1.5, 5.2, 2.0, 7.2, ?, 'retrabalho QA', 'Validação automática', ?, 0.5, NULL, 0, CURRENT_TIMESTAMP)
  `).run(opId, employee.id, TEST_DATE, extraRow.id, TEST_DATE);

  return { employee, opId, extraId: extraRow.id };
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

    const editBody = new URLSearchParams({
      op_number: TEST_OP,
      extra_minutes_per_piece: '0.75',
      reason: 'retrabalho QA atualizado',
      description: 'Motivo editado após lançamento',
      effective_date: TEST_DATE,
      is_active: '1',
      notes: 'edição automatizada'
    }).toString();
    const editResponse = await request(`http://127.0.0.1:${PORT}/op-extra-times/${seeded.extraId}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: editBody
    }, jar);
    assert(editResponse.status === 302, 'Edição do cadastro de tempo extra não redirecionou como esperado.');

    const reportUrl = `http://127.0.0.1:${PORT}/op-extra-times/report?period=custom&start_date=${TEST_DATE}&end_date=${TEST_DATE}&op_number=${encodeURIComponent(TEST_OP)}`;
    const reportHtml = await (await request(reportUrl, {}, jar)).text();
    assert(reportHtml.includes('Consolidado por colaboradora'), 'Relatório de tempo extra não exibiu consolidado por colaboradora.');
    assert(reportHtml.includes('Consolidado por OP'), 'Relatório de tempo extra não exibiu consolidado por OP.');
    assert(reportHtml.includes('retrabalho QA'), 'Relatório de tempo extra não exibiu o motivo histórico aplicado.');
    assert(!reportHtml.includes('retrabalho QA atualizado'), 'Relatório de tempo extra passou a exibir o motivo novo em vez do snapshot histórico.');
    assert(reportHtml.includes(TEST_OP), 'Relatório de tempo extra não exibiu a OP de teste.');

    const exportUrl = `http://127.0.0.1:${PORT}/op-extra-times/report/export?period=custom&start_date=${TEST_DATE}&end_date=${TEST_DATE}&op_number=${encodeURIComponent(TEST_OP)}`;
    const exportHtml = await (await request(exportUrl, {}, jar)).text();
    assert(exportHtml.includes('Relatório de tempo extra de OP'), 'Exportação/impressão do tempo extra não abriu a página específica.');
    assert(exportHtml.includes('Imprimir / Salvar PDF'), 'Exportação/impressão do tempo extra não trouxe ação de impressão.');
    assert(exportHtml.includes('retrabalho QA'), 'Exportação/impressão do tempo extra não exibiu o motivo histórico.');

    const safeDeleteResponse = await request(`http://127.0.0.1:${PORT}/op-extra-times/${seeded.extraId}/delete`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: ''
    }, jar);
    assert(safeDeleteResponse.status === 302, 'Exclusão controlada do cadastro de tempo extra não redirecionou.');

    const listingHtml = await (await request(`http://127.0.0.1:${PORT}/op-extra-times`, {}, jar)).text();
    assert(listingHtml.includes('Inativar seguro') || listingHtml.includes('0 lançamento(s)') || listingHtml.includes('1 lançamento(s)'), 'Tela do cadastro de tempo extra não carregou o bloco de controle esperado.');
    const tenantDbAfter = new DatabaseSync(path.join(APP_ROOT, 'data', 'tenants', 'mais-textil.sqlite'));
    const extraAfter = tenantDbAfter.prepare('SELECT is_active FROM op_extra_times WHERE id = ?').get(seeded.extraId);
    assert(extraAfter && Number(extraAfter.is_active) === 0, 'Cadastro usado em lançamentos não foi inativado de forma segura.');

    const closureUrl = `http://127.0.0.1:${PORT}/closures?period=custom&start_date=${TEST_DATE}&end_date=${TEST_DATE}&employee_id=${seeded.employee.id}`;
    const closureHtml = await (await request(closureUrl, {}, jar)).text();
    assert(closureHtml.includes('Min. extras'), 'Fechamento não exibiu card de minutos extras.');
    assert(closureHtml.includes('<th>Extra</th>'), 'Fechamento não exibiu coluna de extra nas tabelas.');
    assert(closureHtml.includes('2.00'), 'Fechamento não refletiu os minutos extras do cenário.');

    const prizeUrl = `http://127.0.0.1:${PORT}/premios/producao?period=custom&start_date=${TEST_DATE}&end_date=${TEST_DATE}&employee_id=${seeded.employee.id}`;
    const prizeHtml = await (await request(prizeUrl, {}, jar)).text();
    assert(prizeHtml.includes('Min. extras'), 'Prêmio de produção não exibiu card de minutos extras.');
    assert(prizeHtml.includes('<th>Extra</th>'), 'Prêmio de produção não exibiu coluna de extra.');
    assert(prizeHtml.includes('Meta 60%'), 'Prêmio de produção não carregou a tabela consolidada do relatório.');

    console.log('\nTeste do módulo de tempo extra concluído com sucesso.');
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
