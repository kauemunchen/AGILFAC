const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'agilfac-no-industrialization-test-'));
const APP_ROOT = path.join(TEMP_ROOT, 'app');
const PORT = 8200;
const LOGIN = { company: 'mais-textil', username: 'qa-no-industrial', password: 'qa-no-industrial-123' };
const TEST_OP = 'OP-QA-NI-ATALHO';
const TEST_DATE = '2026-05-11';
const TEST_REASON = 'Cliente devolveu sem costurar';

function copyApp() {
  fs.mkdirSync(APP_ROOT, { recursive: true });
  for (const entry of ['server.js', 'public', 'database', 'data']) {
    fs.cpSync(path.join(PROJECT_ROOT, entry), path.join(APP_ROOT, entry), { recursive: true });
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(String(password || ''), salt, 64).toString('hex')}`;
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
  `).run(company.id, LOGIN.username, 'QA No Industrial', hashPassword(LOGIN.password));

  const tenantPath = path.join(APP_ROOT, 'data', 'tenants', `${LOGIN.company}.sqlite`);
  const db = new DatabaseSync(tenantPath);
  db.prepare("INSERT OR IGNORE INTO brands (name) VALUES ('Marca QA')").run();
  db.prepare("INSERT OR IGNORE INTO collections (name) VALUES ('Coleção QA')").run();

  const existing = db.prepare('SELECT id FROM ops WHERE op_number = ?').get(TEST_OP);
  if (existing) {
    db.prepare('DELETE FROM op_billing_history WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM op_problem_items WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM op_daily_productions WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM shipment_items WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM op_occurrences WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM op_cell_transfers WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM reversal_audit_log WHERE target_type = ? AND target_id = ?').run('op', existing.id);
    db.prepare('DELETE FROM ops WHERE id = ?').run(existing.id);
  }

  db.prepare(`
    INSERT INTO ops (
      op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color, lifecycle_type
    ) VALUES (?, ?, 'producao', 'Marca QA', 'Coleção QA', 'com piloto', 'reta', ?, 1.8, 0.2, 'interno', 0.15, ?, ?, 'verde', 'normal')
  `).run(TEST_OP, `Produto ${TEST_OP}`, 24, TEST_DATE, 'Cenário automatizado atalho não industrializar');
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
    const loginBody = new URLSearchParams({ ...LOGIN, returnTo: '/ops' }).toString();
    const loginResponse = await request(`http://127.0.0.1:${PORT}/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: loginBody
    }, jar);
    assert(loginResponse.status === 302, 'Login não redirecionou como esperado.');
    assert(jar.cookie.includes('agilfac_session='), 'Cookie de sessão não foi criado.');

    const listHtmlBefore = await (await request(`http://127.0.0.1:${PORT}/ops?q=${encodeURIComponent(TEST_OP)}`, {}, jar)).text();
    assert(listHtmlBefore.includes('Devolução sem costurar'), 'Consulta de OPs não exibiu o atalho de devolução sem costurar.');
    assert(listHtmlBefore.includes(TEST_OP), 'Consulta de OPs não exibiu a OP de teste.');

    const tenantDb = new DatabaseSync(path.join(APP_ROOT, 'data', 'tenants', `${LOGIN.company}.sqlite`));
    const op = tenantDb.prepare('SELECT id FROM ops WHERE op_number = ?').get(TEST_OP);
    assert(op, 'OP de teste não foi criada.');

    const shortcutResponse = await request(`http://127.0.0.1:${PORT}/estornos/op/without-industrialization`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        id: String(op.id),
        redirect_to: `/ops?q=${TEST_OP}`,
        reason: TEST_REASON
      }).toString()
    }, jar);
    assert(shortcutResponse.status === 302, 'Atalho de devolução sem costurar não redirecionou como esperado.');
    const redirectLocation = shortcutResponse.headers.get('location') || '';
    assert(redirectLocation.startsWith(`/ops?q=${TEST_OP}`), 'Atalho não retornou para a consulta de OPs.');
    assert(redirectLocation.includes('notice='), 'Atalho não anexou mensagem de sucesso na volta para a consulta.');

    const updated = tenantDb.prepare('SELECT lifecycle_type, status_color, return_reason, returned_without_production_at FROM ops WHERE id = ?').get(op.id);
    assert(updated.lifecycle_type === 'devolvida_sem_producao', 'OP não foi marcada como devolvida sem produção no banco.');
    assert(updated.status_color === 'azul', 'OP não ficou azul após a baixa sem industrialização.');
    assert(updated.return_reason === TEST_REASON, 'Motivo da baixa sem industrialização não foi salvo.');
    assert(updated.returned_without_production_at, 'Data/hora da baixa sem industrialização não foi gravada.');

    const listHtmlAfter = await (await request(`http://127.0.0.1:${PORT}${redirectLocation}`, {}, jar)).text();
    assert(listHtmlAfter.includes('devolvida'), 'Consulta de OPs não exibiu badge de devolvida.');
    assert(listHtmlAfter.includes('<td>0</td>'), 'Consulta de OPs não exibiu saldo zerado para a OP não industrializada.');
    assert(!listHtmlAfter.includes('Devolução sem costurar'), 'Atalho continuou aparecendo após a OP já estar baixada.');

    const detailHtml = await (await request(`http://127.0.0.1:${PORT}/ops/${op.id}`, {}, jar)).text();
    assert(detailHtml.includes('Motivo da devolução'), 'Detalhe da OP não exibiu o motivo da devolução.');
    assert(detailHtml.includes(TEST_REASON), 'Detalhe da OP não exibiu o texto do motivo salvo.');
    assert(detailHtml.includes('<dt>Saldo</dt><dd>0</dd>'), 'Detalhe da OP não exibiu saldo zerado após a baixa sem industrialização.');

    const shipmentHtml = await (await request(`http://127.0.0.1:${PORT}/shipments/new?op_number=${encodeURIComponent(TEST_OP)}`, {}, jar)).text();
    assert(shipmentHtml.includes(TEST_OP), 'OP baixada sem industrialização não apareceu apta para embarque.');
    assert(shipmentHtml.includes('0.00') || shipmentHtml.includes('-'), 'Tela de embarque não refletiu a regra de minutos zerados/ocultos para não industrializada.');

    console.log('\nTeste do atalho de devolução sem costurar concluído com sucesso.');
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
