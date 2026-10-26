// T0.2 — garante que "hoje" e a hora atual seguem o horário de Brasília,
// independente do fuso do servidor (o VPS roda em UTC).
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const src = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const pick = re => {
  const m = src.match(re);
  if (!m) throw new Error(`Trecho não encontrado: ${re}`);
  return m[0];
};

const code = [
  pick(/const BUSINESS_TZ[\s\S]*?const BUSINESS_HOUR_FMT[^\n]*\n/),
  pick(/function today\([\s\S]*?\n}\n/),
  pick(/function currentHourSlot\([\s\S]*?\n}\n/),
  pick(/function nowPt\([\s\S]*?\n}\n/),
  'module.exports = { today, currentHourSlot, nowPt };'
].join('\n');

const ctx = { module: {}, Intl, Date, String, Number };
vm.runInNewContext(code, ctx);
const { today, currentHourSlot, nowPt } = ctx.module.exports;

// 02:30 UTC de 18/10 = 23:30 de 17/10 em Brasília
assert.strictEqual(today(new Date('2026-10-18T02:30:00Z')), '2026-10-17');
assert.strictEqual(currentHourSlot(new Date('2026-10-18T02:30:00Z')), '23:00');
// 23:50 BRT continua no mesmo dia
assert.strictEqual(today(new Date('2026-10-18T02:50:00Z')), '2026-10-17');
// 03:00 UTC = meia-noite BRT -> vira o dia
assert.strictEqual(today(new Date('2026-10-18T03:00:00Z')), '2026-10-18');
assert.strictEqual(currentHourSlot(new Date('2026-10-18T03:00:00Z')), '00:00');
// Meio do dia
assert.strictEqual(currentHourSlot(new Date('2026-10-26T19:45:00Z')), '16:00');

// Data de negócio não muda; timestamp UTC do SQLite é exibido em Brasília
assert.strictEqual(nowPt('2026-10-17'), '17/10/2026');
assert.strictEqual(nowPt('2026-10-18 02:30:00'), '17/10/2026, 23:30');
assert.strictEqual(nowPt('2026-10-18T02:30:00.000Z'), '17/10/2026, 23:30');
assert.strictEqual(nowPt(''), '-');

console.log('OK: test-timezone (8 cenários)');
