// T0.4 — Diagnóstico (somente leitura) da divergência de minutos/eficiência entre telas.
// Uso: node scripts/diagnostico-eficiencia.js [inicio] [fim] [tenant]
//      ex.: node scripts/diagnostico-eficiencia.js 2026-09-26 2026-10-25 mais-textil
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const [inicio = '2026-09-26', fim = '2026-10-25', soTenant = ''] = process.argv.slice(2);
const TENANTS_DIR = path.join(__dirname, '..', 'data', 'tenants');
const BASE_DIA = 528;
const DIAS = ['dom', 'seg', 'ter', 'qua', 'qui', 'sex', 'sáb'];

const r2 = n => Math.round((Number(n) || 0) * 100) / 100;
const fmt = n => r2(n).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const pct = (a, b) => (b > 0 ? `${fmt((a / b) * 100)}%` : '-');
const dow = d => new Date(`${d}T00:00:00Z`).getUTCDay();
function datas(a, b) {
  const out = [];
  for (let d = new Date(`${a}T00:00:00Z`); d <= new Date(`${b}T00:00:00Z`); d.setUTCDate(d.getUTCDate() + 1)) out.push(d.toISOString().slice(0, 10));
  return out;
}

function feriados(db) {
  const get = k => db.prepare('SELECT value FROM app_settings WHERE key = ?').get(k)?.value || '';
  const lista = s => String(s).split(/[,\n;]/).map(x => x.trim()).filter(Boolean);
  const set = new Set(lista(get('holiday_dates')));
  for (const mmdd of lista(get('holiday_recurring_mmdd'))) {
    if (!/^\d{2}-\d{2}$/.test(mmdd)) continue;
    for (let y = 2020; y <= 2035; y++) set.add(`${y}-${mmdd}`);
  }
  for (const d of lista(get('worked_holiday_dates'))) set.delete(d);
  return set;
}

const arquivos = fs.readdirSync(TENANTS_DIR).filter(f => f.endsWith('.sqlite') && (!soTenant || f === `${soTenant}.sqlite`));
console.log(`Período: ${inicio} a ${fim}\n`);

for (const arq of arquivos) {
  const db = new DatabaseSync(path.join(TENANTS_DIR, arq), { readOnly: true });
  const hol = feriados(db);
  const util = d => dow(d) >= 1 && dow(d) <= 5 && !hol.has(d);

  const emps = new Map(db.prepare('SELECT id, registration_code, full_name, start_date, termination_date FROM employees').all().map(e => [e.id, e]));
  const diasUteisEmp = e => datas(
    e.start_date && e.start_date > inicio ? e.start_date : inicio,
    e.termination_date && e.termination_date < fim ? e.termination_date : fim
  ).filter(util);

  const lanc = db.prepare(`
    SELECT p.id, p.employee_id, p.production_date, p.produced_minutes, p.normal_minutes, p.extra_minutes,
           o.op_number, o.op_type, COALESCE(o.is_reversed, 0) AS op_estornada,
           COALESCE(o.lifecycle_type, 'normal') AS lifecycle
    FROM op_daily_productions p
    LEFT JOIN ops o ON o.id = p.op_id
    WHERE p.is_reversed = 0 AND p.production_date BETWEEN ? AND ?
  `).all(inicio, fim);

  const causas = {};
  const add = (c, m) => { causas[c] = r2((causas[c] || 0) + m); };
  let totalBruto = 0, premio = 0, fechamento = 0;
  const porTipo = {};
  const diffLinhas = [];
  let baseTotal = 0;
  const empComDias = new Set();
  for (const e of emps.values()) {
    const n = diasUteisEmp(e).length;
    if (n > 0) { empComDias.add(e.id); baseTotal += n * BASE_DIA; }
  }

  for (const l of lanc) {
    const m = Number(l.produced_minutes) || 0;
    totalBruto += m;
    porTipo[l.op_type || '(sem tipo)'] = r2((porTipo[l.op_type || '(sem tipo)'] || 0) + m);
    if (l.op_estornada) add('OP estornada (lançamento ativo)', m);
    if (l.lifecycle !== 'normal') add(`OP ${l.lifecycle}`, m);

    const e = emps.get(l.employee_id);
    if (!e || !empComDias.has(e.id)) { add('Colaboradora sem dias úteis no período (fora do prêmio e do fechamento)', m); continue; }
    premio += m;

    let motivo = '';
    if (e.start_date && l.production_date < e.start_date) motivo = 'Antes da admissão';
    else if (e.termination_date && l.production_date > e.termination_date) motivo = 'Depois do desligamento';
    else if (hol.has(l.production_date)) motivo = 'Feriado';
    else if (dow(l.production_date) === 6) motivo = 'Sábado';
    else if (dow(l.production_date) === 0) motivo = 'Domingo';

    if (motivo) {
      add(`Prêmio conta / Fechamento ignora: ${motivo}`, m);
      diffLinhas.push({ ...l, motivo, nome: e.full_name });
    } else {
      fechamento += m;
    }
  }

  console.log(`=================== ${arq.replace('.sqlite', '')} ===================`);
  console.log(`Lançamentos ativos no período: ${lanc.length} | minutos brutos: ${fmt(totalBruto)}`);
  console.log(`Regra PRÊMIO (todos os lançamentos de quem tem dia útil): ${fmt(premio)} min → ${pct(premio, baseTotal)}`);
  console.log(`Regra FECHAMENTO (só dias úteis da colaboradora):        ${fmt(fechamento)} min → ${pct(fechamento, baseTotal)}`);
  console.log(`Diferença: ${fmt(premio - fechamento)} min | base do período: ${fmt(baseTotal)} min\n`);
  console.log('Causas:');
  for (const [c, m] of Object.entries(causas).sort((a, b) => b[1] - a[1])) console.log(`  ${fmt(m).padStart(12)} min  ${c}`);
  console.log('\nMinutos por tipo de OP (o Dashboard filtra por tipo, padrão "mostruario"):');
  for (const [t, m] of Object.entries(porTipo)) console.log(`  ${fmt(m).padStart(12)} min  ${t}`);
  if (diffLinhas.length) {
    console.log(`\nLançamentos na diferença (${diffLinhas.length}):`);
    for (const l of diffLinhas.sort((a, b) => a.production_date.localeCompare(b.production_date)).slice(0, 60)) {
      console.log(`  #${l.id} ${l.production_date} (${DIAS[dow(l.production_date)]}) | ${l.motivo} | ${l.nome} | OP ${l.op_number} | ${fmt(l.produced_minutes)} min`);
    }
    if (diffLinhas.length > 60) console.log(`  ... e mais ${diffLinhas.length - 60}`);
  }
  console.log('');
  db.close();
}
