const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'agilfac-cell-test-'));
const APP_ROOT = path.join(TEMP_ROOT, 'app');
const PORT = 8197;
const LOGIN = { company: 'mais-textil', username: 'qa-cell', password: 'qa-cell-123' };
const TEST_OP = 'OP-CELL-TEST';

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
  const company = masterDb.prepare('SELECT id FROM companies WHERE slug = ?').get('mais-textil');
  if (!company) throw new Error('Empresa de teste não encontrada no banco mestre.');
  masterDb.prepare('DELETE FROM company_users WHERE company_id = ? AND username = ?').run(company.id, LOGIN.username);
  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active)
    VALUES (?, ?, ?, ?, 'adm', 1)
  `).run(company.id, LOGIN.username, 'QA Célula', hashPassword(LOGIN.password));

  const tenantPath = path.join(APP_ROOT, 'data', 'tenants', 'mais-textil.sqlite');
  const db = new DatabaseSync(tenantPath);
  const transferColumns = db.prepare(`PRAGMA table_info(op_cell_transfers)`).all().map(column => column.name);
  if (!transferColumns.includes('quantity_sent')) db.exec('ALTER TABLE op_cell_transfers ADD COLUMN quantity_sent INTEGER NOT NULL DEFAULT 0');
  if (!transferColumns.includes('quantity_returned')) db.exec('ALTER TABLE op_cell_transfers ADD COLUMN quantity_returned INTEGER NOT NULL DEFAULT 0');
  db.prepare(`UPDATE op_cell_transfers SET quantity_sent = COALESCE(NULLIF(quantity_sent, 0), (SELECT total_pieces FROM ops WHERE ops.id = op_cell_transfers.op_id), 0) WHERE COALESCE(quantity_sent, 0) <= 0`).run();
  db.prepare(`UPDATE op_cell_transfers SET quantity_returned = CASE WHEN returned_at IS NOT NULL THEN COALESCE(NULLIF(quantity_returned, 0), quantity_sent, 0) ELSE COALESCE(quantity_returned, 0) END WHERE quantity_returned IS NULL OR (returned_at IS NOT NULL AND COALESCE(quantity_returned, 0) = 0)`).run();
  const employee = db.prepare('SELECT id FROM employees ORDER BY id LIMIT 1').get();
  if (!employee) throw new Error('Nenhum colaborador encontrado para testar lançamento bloqueado.');

  let cell = db.prepare('SELECT id, name FROM sewing_cells WHERE name = ?').get('Célula Teste QA');
  if (!cell) {
    const result = db.prepare('INSERT INTO sewing_cells (name, is_active, notes) VALUES (?, 1, ?)').run('Célula Teste QA', 'Criada pelo teste automatizado');
    cell = { id: Number(result.lastInsertRowid), name: 'Célula Teste QA' };
  }
  let secondCell = db.prepare('SELECT id, name FROM sewing_cells WHERE name = ?').get('Célula Teste QA 2');
  if (!secondCell) {
    const result = db.prepare('INSERT INTO sewing_cells (name, is_active, notes) VALUES (?, 1, ?)').run('Célula Teste QA 2', 'Segunda célula do teste automatizado');
    secondCell = { id: Number(result.lastInsertRowid), name: 'Célula Teste QA 2' };
  }

  const existing = db.prepare('SELECT id FROM ops WHERE op_number = ?').get(TEST_OP);
  if (existing) {
    db.prepare('DELETE FROM op_daily_productions WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM op_cell_transfers WHERE op_id = ?').run(existing.id);
    db.prepare('DELETE FROM ops WHERE id = ?').run(existing.id);
  }

  const insertOp = db.prepare(`
    INSERT INTO ops (
      op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color
    ) VALUES (?, ?, 'producao', ?, ?, 'com piloto', 'reta', ?, ?, 0, 'interno', 0.25, ?, ?, 'rosa')
  `);
  const opResult = insertOp.run(TEST_OP, 'Produto QA célula', 'Marca QA', 'Coleção QA', 12, 1.5, '2026-04-09', 'Cenário automático para célula');
  const opId = Number(opResult.lastInsertRowid);

  db.prepare(`
    INSERT INTO op_cell_transfers (op_id, cell_id, quantity_sent, quantity_returned, sent_at, sent_notes)
    VALUES (?, ?, 4, 0, '2026-04-09', 'Primeiro envio parcial automatizado')
  `).run(opId, cell.id);

  return { employeeId: employee.id, opId, cellName: cell.name, secondCellId: secondCell.id, secondCellName: secondCell.name };
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

    const previewResponse = await request(`http://127.0.0.1:${PORT}/api/op-preview?op_number=${encodeURIComponent(TEST_OP)}`, {}, jar);
    const preview = await previewResponse.json();
    assert(preview.found === true, 'Preview rápido não encontrou a OP de teste.');
    assert(preview.is_in_cell === true, 'Preview rápido não marcou a OP como em célula.');
    assert(preview.active_cell_name === seeded.cellName, 'Preview rápido não retornou a célula ativa.');

    const blockedBody = new URLSearchParams({
      mode: 'quick',
      employee_id: String(seeded.employeeId),
      production_date: '2026-04-09',
      op_number: TEST_OP,
      used_minutes_f21: '1.500',
      produced_quantity: '2'
    }).toString();
    const blockedResponse = await request(`http://127.0.0.1:${PORT}/productions`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: blockedBody
    }, jar);
    const blockedHtml = await blockedResponse.text();
    assert(blockedResponse.status === 422, 'Lançamento em célula deveria retornar 422.');
    assert(blockedHtml.includes('Faça o retorno da célula antes de lançar produção normal'), 'Mensagem de bloqueio não apareceu no lançamento normal.');

    const sendSecondBody = new URLSearchParams({
      cell_id: String(seeded.secondCellId),
      quantity_sent: '3',
      sent_at: '2026-04-10',
      sent_notes: 'Segundo envio parcial automatizado'
    }).toString();
    const sendSecondResponse = await request(`http://127.0.0.1:${PORT}/ops/${seeded.opId}/cell/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: sendSecondBody
    }, jar);
    assert(sendSecondResponse.status === 302, 'Segundo envio parcial para outra célula deveria redirecionar.');

    const detailHtmlAfterSend = await (await request(`http://127.0.0.1:${PORT}/ops/${seeded.opId}`, {}, jar)).text();
    assert(detailHtmlAfterSend.includes('Quantidade para enviar'), 'Detalhe da OP não mostrou campo de envio parcial por quantidade.');
    assert(detailHtmlAfterSend.includes('Pendências abertas por célula'), 'Detalhe da OP não mostrou etapa testável de pendências abertas por célula.');
    assert(detailHtmlAfterSend.includes(seeded.secondCellName), 'Detalhe da OP não listou a segunda célula aberta para a mesma OP.');

    const tenantPath = path.join(APP_ROOT, 'data', 'tenants', 'mais-textil.sqlite');
    const tenantDb = new DatabaseSync(tenantPath);
    let openTransfers = tenantDb.prepare(`SELECT id, quantity_sent, quantity_returned FROM op_cell_transfers WHERE op_id = ? AND quantity_sent > quantity_returned ORDER BY id`).all(seeded.opId);
    assert(openTransfers.length === 2, 'Era esperado haver dois envios abertos em células.');

    const firstReturnBody = new URLSearchParams({
      transfer_id: String(openTransfers[0].id),
      quantity_returned: String(openTransfers[0].quantity_sent),
      returned_at: '2026-04-11',
      return_notes: 'Retorno total da primeira célula'
    }).toString();
    const firstReturnResponse = await request(`http://127.0.0.1:${PORT}/ops/${seeded.opId}/cell/return`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: firstReturnBody
    }, jar);
    assert(firstReturnResponse.status === 302, 'Primeiro retorno de célula deveria redirecionar.');

    let opRow = tenantDb.prepare('SELECT status_color FROM ops WHERE id = ?').get(seeded.opId);
    assert(opRow.status_color === 'rosa', 'OP deveria continuar rosa enquanto ainda existe saldo pendente em outra célula.');

    openTransfers = tenantDb.prepare(`SELECT id, quantity_sent, quantity_returned FROM op_cell_transfers WHERE op_id = ? AND quantity_sent > quantity_returned ORDER BY id`).all(seeded.opId);
    const secondReturnBody = new URLSearchParams({
      transfer_id: String(openTransfers[0].id),
      quantity_returned: String(openTransfers[0].quantity_sent - openTransfers[0].quantity_returned),
      returned_at: '2026-04-12',
      return_notes: 'Retorno total da segunda célula'
    }).toString();
    const secondReturnResponse = await request(`http://127.0.0.1:${PORT}/ops/${seeded.opId}/cell/return`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: secondReturnBody
    }, jar);
    assert(secondReturnResponse.status === 302, 'Segundo retorno de célula deveria redirecionar.');

    opRow = tenantDb.prepare('SELECT status_color FROM ops WHERE id = ?').get(seeded.opId);
    assert(opRow.status_color === 'verde', 'OP deve sair do rosa quando não houver mais saldo pendente, mas não pode ficar azul sem fechar todo o total da OP.');

    const thirdSendBody = new URLSearchParams({
      cell_id: String(seeded.secondCellId),
      quantity_sent: '5',
      sent_at: '2026-04-13',
      sent_notes: 'Terceiro envio para fechamento total'
    }).toString();
    const thirdSendResponse = await request(`http://127.0.0.1:${PORT}/ops/${seeded.opId}/cell/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: thirdSendBody
    }, jar);
    assert(thirdSendResponse.status === 302, 'Terceiro envio para célula deveria redirecionar.');

    opRow = tenantDb.prepare('SELECT status_color FROM ops WHERE id = ?').get(seeded.opId);
    assert(opRow.status_color === 'rosa', 'OP deve voltar para rosa quando um novo saldo for enviado para célula.');

    openTransfers = tenantDb.prepare(`SELECT id, quantity_sent, quantity_returned FROM op_cell_transfers WHERE op_id = ? AND quantity_sent > quantity_returned ORDER BY id`).all(seeded.opId);
    const thirdReturnBody = new URLSearchParams({
      transfer_id: String(openTransfers[0].id),
      quantity_returned: String(openTransfers[0].quantity_sent - openTransfers[0].quantity_returned),
      returned_at: '2026-04-14',
      return_notes: 'Retorno total para fechamento'
    }).toString();
    const thirdReturnResponse = await request(`http://127.0.0.1:${PORT}/ops/${seeded.opId}/cell/return`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: thirdReturnBody
    }, jar);
    assert(thirdReturnResponse.status === 302, 'Retorno final de célula deveria redirecionar.');

    opRow = tenantDb.prepare('SELECT status_color FROM ops WHERE id = ?').get(seeded.opId);
    assert(opRow.status_color === 'azul', 'OP deve ficar azul somente depois que todo o saldo retornar e o total da OP estiver considerado.');

    const dashboardHtml = await (await request(`http://127.0.0.1:${PORT}/?producao_start_date=2026-04-01&producao_end_date=2026-04-30`, {}, jar)).text();
    assert(dashboardHtml.includes('Rosa (em célula)'), 'Dashboard não exibiu card rosa.');
    assert(dashboardHtml.includes('OPs em célula no filtro atual'), 'Dashboard não exibiu a lista rápida de OPs em célula.');

    const reportHtml = await (await request(`http://127.0.0.1:${PORT}/cells/report?start_date=2026-04-01&end_date=2026-04-30`, {}, jar)).text();
    assert(reportHtml.includes('Resumo por célula'), 'Relatório de célula não abriu o resumo por célula.');
    assert(reportHtml.includes('Recebeu'), 'Relatório de célula não mostrou coluna de peças recebidas.');
    assert(reportHtml.includes('Devolveu'), 'Relatório de célula não mostrou coluna de peças devolvidas.');
    assert(reportHtml.includes('Saldo aberto'), 'Relatório de célula não mostrou saldo em aberto por célula.');

    console.log('\nTeste do módulo célula concluído com sucesso.');
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
