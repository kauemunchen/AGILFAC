// T0.6 — Desativa um usuário (não apaga, por causa da auditoria).
// Recusa desativar se a empresa ficaria sem nenhum Administrador ativo que já
// trocou a senha temporária.
//
// Uso: node scripts/desativar-usuario.js <usuario> <empresa1> [empresa2 ...]
//  ex: node scripts/desativar-usuario.js admin mais-textil douglas-confeccoes mais-joinville
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const [username, ...slugs] = process.argv.slice(2);
if (!username || !slugs.length) {
  console.error('Uso: node scripts/desativar-usuario.js <usuario> <empresa1> [empresa2 ...]');
  process.exit(1);
}
const master = new DatabaseSync(path.join(__dirname, '..', 'data', 'master.sqlite'));
const login = String(username).trim().toLowerCase();

for (const slug of slugs) {
  const company = master.prepare('SELECT id, name FROM companies WHERE LOWER(slug) = LOWER(?)').get(slug);
  if (!company) { console.log(`✗ ${slug}: empresa não encontrada`); continue; }
  const user = master.prepare('SELECT id, is_active FROM company_users WHERE company_id = ? AND LOWER(username) = ?').get(company.id, login);
  if (!user) { console.log(`✗ ${slug}: usuário "${login}" não existe`); continue; }
  if (!user.is_active) { console.log(`= ${slug}: "${login}" já estava desativado`); continue; }
  const otherAdmins = master.prepare(`
    SELECT COUNT(*) AS n FROM company_users
    WHERE company_id = ? AND id <> ? AND role = 'adm' AND is_active = 1 AND COALESCE(must_change_password, 0) = 0
  `).get(company.id, user.id).n;
  if (!otherAdmins) {
    console.log(`✗ ${slug}: NÃO desativado — não há outro Administrador ativo que já tenha entrado e trocado a senha.`);
    continue;
  }
  master.prepare('UPDATE company_users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  master.prepare('DELETE FROM sessions WHERE company_user_id = ?').run(user.id);
  console.log(`✓ ${slug}: "${login}" desativado`);
}
