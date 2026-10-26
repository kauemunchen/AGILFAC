// T0.6 — Cria (ou reativa) um usuário Administrador nominal em uma ou mais empresas.
// Gera uma senha temporária ALEATÓRIA, mostrada só neste terminal. O usuário é
// obrigado a trocar a senha no primeiro login.
//
// Uso: node scripts/criar-usuario-admin.js <usuario> "<Nome completo>" <empresa1> [empresa2 ...]
//  ex: node scripts/criar-usuario-admin.js kaue "Kauê München" mais-textil douglas-confeccoes mais-joinville
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const [username, fullName, ...slugs] = process.argv.slice(2);
if (!username || !fullName || !slugs.length) {
  console.error('Uso: node scripts/criar-usuario-admin.js <usuario> "<Nome completo>" <empresa1> [empresa2 ...]');
  process.exit(1);
}

const master = new DatabaseSync(path.join(__dirname, '..', 'data', 'master.sqlite'));
const cols = master.prepare('PRAGMA table_info(company_users)').all().map(c => c.name);
if (!cols.includes('must_change_password')) {
  console.error('O sistema ainda não foi atualizado com a T0.6. Aguarde o deploy e reinicie o container.');
  process.exit(1);
}

const hash = password => {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
};
const login = String(username).trim().toLowerCase();

for (const slug of slugs) {
  const company = master.prepare('SELECT id, name FROM companies WHERE LOWER(slug) = LOWER(?)').get(slug);
  if (!company) { console.log(`✗ ${slug}: empresa não encontrada`); continue; }
  const temp = crypto.randomBytes(9).toString('base64url'); // 12 caracteres
  const existing = master.prepare('SELECT id FROM company_users WHERE company_id = ? AND LOWER(username) = ?').get(company.id, login);
  if (existing) {
    master.prepare(`UPDATE company_users SET full_name = ?, password_hash = ?, role = 'adm', is_active = 1, must_change_password = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(fullName, hash(temp), existing.id);
    master.prepare('DELETE FROM sessions WHERE company_user_id = ?').run(existing.id);
  } else {
    master.prepare(`INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active, must_change_password, updated_at)
      VALUES (?, ?, ?, ?, 'adm', 1, 1, CURRENT_TIMESTAMP)`).run(company.id, login, fullName, hash(temp));
  }
  console.log(`✓ ${company.name} (empresa: ${slug}) · usuário: ${login} · senha temporária: ${temp}`);
}
console.log('\nNo primeiro login o sistema vai pedir para trocar a senha. Não envie essas senhas por mensagem.');
