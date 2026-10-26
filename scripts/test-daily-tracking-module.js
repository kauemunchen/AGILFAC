const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const TEMP_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'agilfac-daily-tracking-test-'));
const APP_ROOT = path.join(TEMP_ROOT, 'app');
const PORT = 8199;
const LOGIN = { company: 'mais-textil', username: 'qa-daily-tracking', password: 'qa-daily-tracking-123' };
const EMPLOYEE_CODE = 'QA-DIARIO-01';
const OP_NUMBER = 'OP-QA-DIARIO-01';

function iso(date) {
  return date.toISOString().slice(0, 10);
}

function formatPtBr(dateIso) {
  const [year, month, day] = String(dateIso).split('-');
  return `${day}/${month}/${year}`;
}

function getOperationalRange(refDateIso) {
  const date = new Date(`${refDateIso}T00:00:00Z`);
  const y = date.getUTCFullYear();
  const m = date.getUTCMonth();
  const d = date.getUTCDate();
  let start;
  let end;
  if (d >= 26) {
    start = new Date(Date.UTC(y, m, 26));
    end = new Date(Date.UTC(y, m + 1, 25));
  } else {
    start = new Date(Date.UTC(y, m - 1, 26));
    end = new Date(Date.UTC(y, m, 25));
  }
  return { start: iso(start), end: iso(end) };
}

function enumerateDates(start, end) {
  const dates = [];
  const cursor = new Date(`${start}T00:00:00Z`);
  const limit = new Date(`${end}T00:00:00Z`);
  while (cursor <= limit) {
    dates.push(iso(cursor));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return dates;
}

function isBusinessDay(dateIso, holidays = new Set()) {
  const date = new Date(`${dateIso}T00:00:00Z`);
  const day = date.getUTCDay();
  return day >= 1 && day <= 5 && !holidays.has(dateIso);
}

function businessDaysBetween(start, end, holidays = new Set()) {
  return enumerateDates(start, end).filter(date => isBusinessDay(date, holidays));
}

function copyApp() {
  fs.mkdirSync(APP_ROOT, { recursive: true });
  for (const entry of ['server.js', 'public', 'database', 'data']) {
    fs.cpSync(path.join(PROJECT_ROOT, entry), path.join(APP_ROOT, entry), { recursive: true });
  }
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(String(password || ''), salt, 64).toString('hex')}`;
}

function setSetting(db, key, value) {
  db.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
  `).run(key, value);
}

function seedScenario() {
  const todayIso = iso(new Date());
  const range = getOperationalRange(todayIso);
  const allElapsedBusinessDays = businessDaysBetween(range.start, todayIso, new Set());
  const productionDate = allElapsedBusinessDays[0];
  const holidayDate = allElapsedBusinessDays.find(date => date !== productionDate) || allElapsedBusinessDays[1];
  if (!productionDate || !holidayDate) throw new Error('Não foi possível montar datas úteis suficientes para o cenário de teste.');

  const masterPath = path.join(APP_ROOT, 'data', 'master.sqlite');
  const masterDb = new DatabaseSync(masterPath);
  const company = masterDb.prepare('SELECT id FROM companies WHERE slug = ?').get(LOGIN.company);
  if (!company) throw new Error('Empresa de teste não encontrada no banco mestre.');
  masterDb.prepare('DELETE FROM company_users WHERE company_id = ? AND username = ?').run(company.id, LOGIN.username);
  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active)
    VALUES (?, ?, ?, ?, 'adm', 1)
  `).run(company.id, LOGIN.username, 'QA Acompanhamento Diário', hashPassword(LOGIN.password));

  const tenantPath = path.join(APP_ROOT, 'data', 'tenants', `${LOGIN.company}.sqlite`);
  const db = new DatabaseSync(tenantPath);

  setSetting(db, 'holiday_dates', holidayDate);
  setSetting(db, 'holiday_recurring_mmdd', '');
  setSetting(db, 'worked_holiday_dates', '');

  db.prepare('DELETE FROM op_daily_productions WHERE employee_id IN (SELECT id FROM employees WHERE registration_code = ?)').run(EMPLOYEE_CODE);
  db.prepare('DELETE FROM ops WHERE op_number = ?').run(OP_NUMBER);
  db.prepare('DELETE FROM employees WHERE registration_code = ?').run(EMPLOYEE_CODE);

  const employeeResult = db.prepare(`
    INSERT INTO employees (registration_code, full_name, start_date, termination_date, is_active, notes, created_at, updated_at)
    VALUES (?, ?, ?, NULL, 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `).run(EMPLOYEE_CODE, 'QA Acompanhamento Diário', range.start, 'Funcionária criada pelo teste automatizado do acompanhamento diário');
  const employeeId = Number(employeeResult.lastInsertRowid);

  const opResult = db.prepare(`
    INSERT INTO ops (
      op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, status_color
    ) VALUES (?, ?, 'producao', ?, ?, 'com piloto', 'reta', ?, ?, ?, 'interno', 0, ?, ?, 'verde')
  `).run(OP_NUMBER, 'Produto QA diário', 'Marca QA', 'Coleção QA', 500, 10, 0, productionDate, 'Cenário automatizado do acompanhamento diário');
  const opId = Number(opResult.lastInsertRowid);

  db.prepare(`
    INSERT INTO op_daily_productions (
      op_id, employee_id, production_date, produced_quantity, used_minutes_f21,
      normal_minutes, extra_minutes, produced_minutes, created_by_user_id, is_reversed, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL, 0, CURRENT_TIMESTAMP)
  `).run(opId, employeeId, productionDate, 500, 10, 5000, 5000);

  const holidays = new Set([holidayDate]);
  const elapsedBusinessDays = businessDaysBetween(range.start, todayIso, holidays);
  const fullBusinessDays = businessDaysBetween(range.start, range.end, holidays);
  const currentPercent = Number(((5000 / (elapsedBusinessDays.length * 528)) * 100).toFixed(2));
  const fullPercent = Number(((5000 / (fullBusinessDays.length * 528)) * 100).toFixed(2));

  return {
    employeeId,
    productionDate,
    holidayDate,
    range,
    todayIso,
    elapsedDays: elapsedBusinessDays.length,
    fullDays: fullBusinessDays.length,
    currentPercent,
    fullPercent
  };
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

    const trackingUrl = `http://127.0.0.1:${PORT}/acompanhamento/diario?base_date=${seeded.todayIso}&employee_id=${seeded.employeeId}`;
    const trackingHtml = await (await request(trackingUrl, {}, jar)).text();
    assert(trackingHtml.includes('Acompanhamento diário de resultado'), 'Tela do acompanhamento diário não carregou.');
    assert(trackingHtml.includes(formatPtBr(seeded.range.start)), 'Tela não exibiu início do período operacional esperado.');
    assert(trackingHtml.includes(formatPtBr(seeded.range.end)), 'Tela não exibiu fim do período operacional esperado.');
    assert(trackingHtml.includes(`${seeded.elapsedDays}/${seeded.fullDays}`), 'Tela não exibiu dias úteis decorridos/total esperados.');
    assert(trackingHtml.includes('5000.00'), 'Tela não exibiu os minutos acumulados do cenário.');
    assert(trackingHtml.includes(`${seeded.currentPercent.toFixed(2)}%`), 'Tela não exibiu o percentual atual esperado.');
    assert(trackingHtml.includes(`${seeded.fullPercent.toFixed(2)}%`), 'Tela não exibiu o percentual do período cheio esperado.');
    assert(trackingHtml.includes(formatPtBr(seeded.productionDate)), 'Tela não exibiu a data do último lançamento.');
    assert(trackingHtml.includes('mesmos dias úteis/feriados já usados no fechamento'), 'Tela não explicou a base compartilhada de dias úteis/feriados.');
    assert(trackingHtml.includes('Ranking gerencial 26 → 25'), 'Tela não exibiu o ranking gerencial do período.');
    assert(trackingHtml.includes('Acima de 60%'), 'Tela não destacou visualmente quem já bateu 60%.');
    assert(trackingHtml.includes('Próxima etapa visível/testável'), 'Tela não exibiu a próxima etapa visível/testável.');
    assert(trackingHtml.includes('/premios/producao'), 'Tela não trouxe link para testar o próximo passo no prêmio de produção.');
    assert(trackingHtml.includes('/closures'), 'Tela não trouxe link para testar o próximo passo no fechamento.');
    assert(trackingHtml.includes('/acompanhamento/diario/export?base_date='), 'Tela não exibiu o botão/link para a versão de impressão com os filtros atuais.');

    const exportHtml = await (await request(`http://127.0.0.1:${PORT}/acompanhamento/diario/export?base_date=${seeded.todayIso}&employee_id=${seeded.employeeId}`, {}, jar)).text();
    assert(exportHtml.includes('Relatório gerencial · acompanhamento diário'), 'Versão de exportação/impressão não carregou.');
    assert(exportHtml.includes('Imprimir / Salvar PDF'), 'Versão de exportação não exibiu o botão de impressão/PDF.');
    assert(exportHtml.includes('Resumo gerencial do período'), 'Versão de exportação não exibiu o resumo gerencial.');
    assert(exportHtml.includes('Ranking gerencial 26 → 25'), 'Versão de exportação não exibiu o ranking.');
    assert(exportHtml.includes('Tabela principal do acompanhamento'), 'Versão de exportação não exibiu a tabela principal.');
    assert(exportHtml.includes(EMPLOYEE_CODE), 'Versão de exportação não preservou o filtro/colaboradora do cenário.');
    assert(exportHtml.includes(formatPtBr(seeded.range.start)), 'Versão de exportação não exibiu o início do período filtrado.');
    assert(exportHtml.includes(formatPtBr(seeded.range.end)), 'Versão de exportação não exibiu o fim do período filtrado.');

    const dashboardHtml = await (await request(`http://127.0.0.1:${PORT}/`, {}, jar)).text();
    assert(dashboardHtml.includes('Acompanhamento diário do mês operacional'), 'Dashboard não exibiu o bloco-resumo do acompanhamento diário.');
    assert(dashboardHtml.includes('/acompanhamento/diario'), 'Dashboard não exibiu link para a tela completa do acompanhamento diário.');
    assert(dashboardHtml.includes(EMPLOYEE_CODE), 'Dashboard não exibiu a colaboradora do cenário no bloco do acompanhamento diário.');
    assert(dashboardHtml.includes('Resumo gerencial do acompanhamento'), 'Dashboard não exibiu o resumo gerencial do acompanhamento.');
    assert(dashboardHtml.includes('Validar próximo passo'), 'Dashboard não exibiu o atalho para validar a próxima etapa.');

    console.log('\nTeste do módulo de acompanhamento diário concluído com sucesso.');
  } finally {
    child.kill('SIGTERM');
    fs.rmSync(TEMP_ROOT, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
