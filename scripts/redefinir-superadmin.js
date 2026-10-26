// Gera uma nova senha aleatória para o superadmin (mostrada só neste terminal)
// e encerra as sessões abertas. Uso: node scripts/redefinir-superadmin.js [usuario]
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const username = String(process.argv[2] || 'superadmin').trim().toLowerCase();
const master = new DatabaseSync(path.join(__dirname, '..', 'data', 'master.sqlite'));
const admin = master.prepare('SELECT id FROM super_admins WHERE LOWER(username) = ?').get(username);
if (!admin) {
  console.error(`Superadmin "${username}" não encontrado. Existentes: ${master.prepare('SELECT username FROM super_admins').all().map(r => r.username).join(', ')}`);
  process.exit(1);
}
const password = crypto.randomBytes(12).toString('base64url');
const salt = crypto.randomBytes(16).toString('hex');
const hash = `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
master.prepare('UPDATE super_admins SET password_hash = ?, is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hash, admin.id);
try { master.prepare('DELETE FROM super_admin_sessions WHERE super_admin_id = ?').run(admin.id); } catch (_) {}
console.log(`Superadmin: ${username}\nNova senha: ${password}\nAcesse: https://app.agilfac.com.br/superadmin/login`);
