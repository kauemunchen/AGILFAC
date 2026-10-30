const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const querystring = require('querystring');
const { AsyncLocalStorage } = require('async_hooks');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 8090);

// Fuso oficial do negócio. Datas de negócio (lançamento, envio, embarque) são sempre
// no horário de Brasília; timestamps de auditoria (created_at etc.) ficam em UTC.
const BUSINESS_TZ = 'America/Sao_Paulo';
const BUSINESS_DATE_FMT = new Intl.DateTimeFormat('en-CA', { timeZone: BUSINESS_TZ, year: 'numeric', month: '2-digit', day: '2-digit' });
const BUSINESS_HOUR_FMT = new Intl.DateTimeFormat('en-GB', { timeZone: BUSINESS_TZ, hour: '2-digit', hourCycle: 'h23' });

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const TENANTS_DIR = path.join(DATA_DIR, 'tenants');
const LEGACY_DB_PATH = path.join(DATA_DIR, 'app.sqlite');
const MASTER_DB_PATH = path.join(DATA_DIR, 'master.sqlite');
const SCHEMA_PATH = path.join(ROOT, 'database', 'schema.sql');
const MASTER_SCHEMA_PATH = path.join(ROOT, 'database', 'master-schema.sql');
const AVAILABLE_MINUTES_DAY = 528; // padrão; o valor efetivo vem de Parâmetros (baseMinutesDay())
const SESSION_COOKIE = 'agilfac_session';
const SUPERADMIN_SESSION_COOKIE = 'agilfac_superadmin_session';
const SESSION_TTL_DAYS = 7;
// T0.6 — segurança de acesso
const SESSION_IDLE_HOURS = 12;
const PASSWORD_MIN_LENGTH = 8;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_WINDOW_MINUTES = 15;
const ROLE_LABELS = { adm: 'Administrador', operacional: 'Operacional', resultados: 'Resultados', apontamento: 'Apontamento', lancador: 'Lançador' };
const REVERSAL_TYPES = { op: 'Cadastro de OP', production: 'Lançamento diário', shipment: 'Embarque' };
const CELL_ALLOWED_ROLES = new Set(['adm', 'operacional', 'lancador']);
const DEFAULT_COMPANY_NAME = 'AgilFac';
const BLOCKED_BRAND_NAMES = new Set(['primavera 27']);

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(TENANTS_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

const requestContext = new AsyncLocalStorage();
const masterDb = new DatabaseSync(MASTER_DB_PATH);
masterDb.exec(fs.readFileSync(MASTER_SCHEMA_PATH, 'utf8'));
migrateMasterDatabase();

const tenantDbCache = new Map();
const BOOTSTRAP_INFO = bootstrapMasterData();
const DEFAULT_COMPANY = getDefaultCompany();
const DEFAULT_TENANT_DB = DEFAULT_COMPANY ? getTenantDbForCompany(DEFAULT_COMPANY) : null;
if (DEFAULT_TENANT_DB) {
  bootstrapTenantDatabase(DEFAULT_TENANT_DB);
}

const db = new Proxy({}, {
  get(_target, prop) {
    const activeDb = getActiveDb();
    const value = activeDb[prop];
    return typeof value === 'function' ? value.bind(activeDb) : value;
  }
});

function repairMasterSessionsForeignKey() {
  const row = masterDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'sessions'").get();
  const createSql = String(row?.sql || '');
  if (!createSql || createSql.includes('REFERENCES company_users(id)')) return;
  masterDb.exec('PRAGMA foreign_keys = OFF');
  masterDb.exec(`
    ALTER TABLE sessions RENAME TO sessions_fk_legacy;
    CREATE TABLE sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_token TEXT NOT NULL UNIQUE,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      company_user_id INTEGER NOT NULL REFERENCES company_users(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT INTO sessions (id, session_token, company_id, company_user_id, expires_at, created_at)
    SELECT id, session_token, company_id, company_user_id, expires_at, created_at FROM sessions_fk_legacy;
    DROP TABLE sessions_fk_legacy;
  `);
  masterDb.exec('CREATE INDEX IF NOT EXISTS idx_sessions_company_id ON sessions(company_id)');
  masterDb.exec('CREATE INDEX IF NOT EXISTS idx_sessions_company_user_id ON sessions(company_user_id)');
  masterDb.exec('CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)');
  masterDb.exec('PRAGMA foreign_keys = ON');
}

function upgradeCompanyUserRoleConstraint() {
  const row = masterDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'company_users'").get();
  const createSql = String(row?.sql || '');
  if (!createSql || createSql.includes("'lancador'")) return;
  masterDb.exec('PRAGMA foreign_keys = OFF');
  masterDb.exec(`
    ALTER TABLE company_users RENAME TO company_users_role_legacy;
    CREATE TABLE company_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      username TEXT NOT NULL,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('adm', 'operacional', 'resultados', 'apontamento', 'lancador')),
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      must_change_password INTEGER NOT NULL DEFAULT 0,
      last_login_at TEXT,
      UNIQUE (company_id, username)
    );
  `);
  const legacyCols = masterDb.prepare('PRAGMA table_info(company_users_role_legacy)').all().map(c => c.name);
  const newCols = masterDb.prepare('PRAGMA table_info(company_users)').all().map(c => c.name);
  const cols = newCols.filter(c => legacyCols.includes(c)).join(', ');
  masterDb.exec(`INSERT INTO company_users (${cols}) SELECT ${cols} FROM company_users_role_legacy`);
  repairMasterSessionsForeignKey();
  masterDb.exec('DROP TABLE company_users_role_legacy');
  masterDb.exec('CREATE INDEX IF NOT EXISTS idx_company_users_company_id ON company_users(company_id)');
  masterDb.exec('PRAGMA foreign_keys = ON');
}

function migrateMasterSecurity() {
  ensureColumn(masterDb, 'company_users', 'must_change_password', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(masterDb, 'company_users', 'last_login_at', 'TEXT');
  ensureColumn(masterDb, 'sessions', 'last_seen_at', 'TEXT');
  masterDb.exec(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scope TEXT NOT NULL,
      company_slug TEXT,
      username TEXT,
      ip TEXT,
      user_agent TEXT,
      success INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts (scope, ip, company_slug, username, created_at);
  `);
}

function getClientIp(req) {
  const forwarded = String(req?.headers?.['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req?.socket?.remoteAddress || '';
}

function isSecureRequest(req) {
  return String(req?.headers?.['x-forwarded-proto'] || '').toLowerCase() === 'https' || Boolean(req?.socket?.encrypted);
}

function isLoginBlocked(scope, req, companySlug, username) {
  const row = masterDb.prepare(`
    SELECT COUNT(*) AS n FROM login_attempts
    WHERE scope = ? AND success = 0 AND ip = ? AND COALESCE(company_slug, '') = ? AND LOWER(COALESCE(username, '')) = LOWER(?)
      AND created_at >= datetime('now', ?)
  `).get(scope, getClientIp(req), String(companySlug || ''), String(username || ''), `-${LOGIN_WINDOW_MINUTES} minutes`);
  return Number(row?.n || 0) >= LOGIN_MAX_FAILURES;
}

function recordLoginAttempt(scope, req, companySlug, username, success) {
  masterDb.prepare(`
    INSERT INTO login_attempts (scope, company_slug, username, ip, user_agent, success)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(scope, String(companySlug || ''), String(username || '').slice(0, 120), getClientIp(req), String(req?.headers?.['user-agent'] || '').slice(0, 300), success ? 1 : 0);
}

function validateNewPassword(password) {
  if (String(password || '').length < PASSWORD_MIN_LENGTH) throw new Error(`A senha precisa ter pelo menos ${PASSWORD_MIN_LENGTH} caracteres.`);
}

function migrateMasterDatabase() {
  upgradeCompanyUserRoleConstraint();
  repairMasterSessionsForeignKey();
  migrateMasterSecurity();
  masterDb.exec(`
    CREATE TABLE IF NOT EXISTS super_admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  masterDb.exec(`
    CREATE TABLE IF NOT EXISTS super_admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_token TEXT NOT NULL UNIQUE,
      super_admin_id INTEGER NOT NULL REFERENCES super_admins(id) ON DELETE CASCADE,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function getActiveDb() {
  const store = requestContext.getStore();
  if (store && store.tenantDb) return store.tenantDb;
  if (DEFAULT_TENANT_DB) return DEFAULT_TENANT_DB;
  throw new Error('Nenhum banco da empresa foi resolvido para esta requisição.');
}

function getRequestAuth() {
  return requestContext.getStore()?.auth || null;
}

function slugifyCompanyName(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    || 'empresa';
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const normalized = String(password || '');
  const hash = crypto.scryptSync(normalized, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, hash] = String(storedHash || '').split(':');
  if (!salt || !hash) return false;
  const computed = crypto.scryptSync(String(password || ''), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computed, 'hex'));
}

function resolveTenantDbPath(dbPath) {
  return path.isAbsolute(dbPath) ? dbPath : path.join(ROOT, dbPath);
}

function getTenantDbForCompany(company) {
  const resolvedPath = resolveTenantDbPath(company.db_path);
  if (!tenantDbCache.has(resolvedPath)) {
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    const tenantDb = new DatabaseSync(resolvedPath);
    bootstrapTenantDatabase(tenantDb);
    tenantDbCache.set(resolvedPath, tenantDb);
  }
  return tenantDbCache.get(resolvedPath);
}

function bootstrapTenantDatabase(tenantDb) {
  tenantDb.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  migrateDatabase(tenantDb);
}

function getLegacyCompanyName() {
  if (!fs.existsSync(LEGACY_DB_PATH)) return DEFAULT_COMPANY_NAME;
  try {
    const legacyDb = new DatabaseSync(LEGACY_DB_PATH);
    legacyDb.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
    migrateDatabase(legacyDb);
    const row = legacyDb.prepare("SELECT value FROM app_settings WHERE key = 'company_name' LIMIT 1").get();
    legacyDb.close();
    return String(row?.value || DEFAULT_COMPANY_NAME).trim() || DEFAULT_COMPANY_NAME;
  } catch (_error) {
    return DEFAULT_COMPANY_NAME;
  }
}

function bootstrapMasterData() {
  let company = masterDb.prepare('SELECT id, slug, name, db_path, is_active FROM companies ORDER BY id LIMIT 1').get();
  let generatedPassword = null;
  let generatedSuperadminPassword = null;
  if (!company) {
    const companyName = getLegacyCompanyName();
    const slug = slugifyCompanyName(companyName);
    const tenantRelativePath = path.join('data', 'tenants', `${slug}.sqlite`);
    const tenantAbsolutePath = path.join(ROOT, tenantRelativePath);
    fs.mkdirSync(path.dirname(tenantAbsolutePath), { recursive: true });
    if (fs.existsSync(LEGACY_DB_PATH) && !fs.existsSync(tenantAbsolutePath)) {
      fs.copyFileSync(LEGACY_DB_PATH, tenantAbsolutePath);
    }
    const insert = masterDb.prepare(`
      INSERT INTO companies (slug, name, db_path, is_active, updated_at)
      VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
    `);
    const result = insert.run(slug, companyName, tenantRelativePath);
    company = masterDb.prepare('SELECT id, slug, name, db_path, is_active FROM companies WHERE id = ?').get(result.lastInsertRowid);
  }

  const adminExists = masterDb.prepare('SELECT id FROM company_users WHERE company_id = ? LIMIT 1').get(company.id);
  if (!adminExists) {
    generatedPassword = process.env.AGILFAC_BOOTSTRAP_PASSWORD || crypto.randomBytes(6).toString('base64url');
    masterDb.prepare(`
      INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active, must_change_password, updated_at)
      VALUES (?, 'admin', 'Administrador inicial', ?, 'adm', 1, 1, CURRENT_TIMESTAMP)
    `).run(company.id, hashPassword(generatedPassword));

    const credentialsPath = path.join(DATA_DIR, 'bootstrap-admin.txt');
    fs.writeFileSync(credentialsPath, [
      `empresa=${company.slug}`,
      'usuario=admin',
      `senha=${generatedPassword}`,
      `gerado_em=${new Date().toISOString()}`
    ].join('\n'));
  }

  const superadminExists = masterDb.prepare('SELECT id FROM super_admins LIMIT 1').get();
  if (!superadminExists) {
    generatedSuperadminPassword = process.env.AGILFAC_SUPERADMIN_PASSWORD || crypto.randomBytes(8).toString('base64url');
    masterDb.prepare(`
      INSERT INTO super_admins (username, full_name, password_hash, is_active, updated_at)
      VALUES ('superadmin', 'Super Administrador', ?, 1, CURRENT_TIMESTAMP)
    `).run(hashPassword(generatedSuperadminPassword));

    const superadminPath = path.join(DATA_DIR, 'bootstrap-superadmin.txt');
    fs.writeFileSync(superadminPath, [
      'usuario=superadmin',
      `senha=${generatedSuperadminPassword}`,
      `gerado_em=${new Date().toISOString()}`
    ].join('\n'));
  }

  return { company, generatedPassword, generatedSuperadminPassword };
}

function getDefaultCompany() {
  return masterDb.prepare('SELECT id, slug, name, db_path, is_active FROM companies WHERE is_active = 1 ORDER BY id LIMIT 1').get() || null;
}

function findCompanyByLogin(value) {
  const normalized = String(value || '').trim();
  if (!normalized) return null;
  return masterDb.prepare(`
    SELECT id, slug, name, db_path, is_active
    FROM companies
    WHERE is_active = 1 AND (LOWER(slug) = LOWER(?) OR LOWER(name) = LOWER(?))
    LIMIT 1
  `).get(normalized, normalized) || null;
}

function authenticateCompanyUser(companyId, username, password) {
  const user = masterDb.prepare(`
    SELECT id, company_id, username, full_name, password_hash, role, is_active, must_change_password
    FROM company_users
    WHERE company_id = ? AND LOWER(username) = LOWER(?) AND is_active = 1
    LIMIT 1
  `).get(companyId, String(username || '').trim());
  if (!user) return null;
  if (!verifyPassword(password, user.password_hash)) return null;
  return user;
}

function createSession(company, user) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  masterDb.prepare(`
    INSERT INTO sessions (session_token, company_id, company_user_id, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(token, company.id, user.id, expiresAt);
  return { token, expiresAt };
}

function destroySession(token) {
  if (!token) return;
  masterDb.prepare('DELETE FROM sessions WHERE session_token = ?').run(token);
}

function getSessionContext(req) {
  const cookies = parseCookies(req);
  const token = String(cookies[SESSION_COOKIE] || '').trim();
  if (!token) return null;
  const row = masterDb.prepare(`
    SELECT
      s.session_token,
      s.expires_at,
      c.id AS company_id,
      c.slug AS company_slug,
      c.name AS company_name,
      c.db_path AS company_db_path,
      u.id AS user_id,
      u.username,
      u.full_name,
      u.role,
      u.is_active AS user_is_active,
      u.must_change_password,
      COALESCE(s.last_seen_at, s.created_at) AS last_seen_at
    FROM sessions s
    JOIN companies c ON c.id = s.company_id
    JOIN company_users u ON u.id = s.company_user_id
    WHERE s.session_token = ? AND c.is_active = 1
    LIMIT 1
  `).get(token);
  if (!row) return null;
  if (row.user_is_active !== 1 || new Date(row.expires_at).getTime() <= Date.now()) {
    destroySession(token);
    return null;
  }
  const lastSeen = new Date(String(row.last_seen_at).includes('T') ? row.last_seen_at : `${String(row.last_seen_at).replace(' ', 'T')}Z`).getTime();
  if (Number.isFinite(lastSeen) && Date.now() - lastSeen > SESSION_IDLE_HOURS * 60 * 60 * 1000) {
    destroySession(token);
    return null;
  }
  if (!Number.isFinite(lastSeen) || Date.now() - lastSeen > 60 * 1000) {
    masterDb.prepare('UPDATE sessions SET last_seen_at = ? WHERE session_token = ?').run(new Date().toISOString(), token);
  }
  const company = {
    id: row.company_id,
    slug: row.company_slug,
    name: row.company_name,
    db_path: row.company_db_path,
    is_active: 1
  };
  return {
    token,
    company,
    user: {
      id: row.user_id,
      username: row.username,
      full_name: row.full_name,
      role: row.role,
      must_change_password: Number(row.must_change_password || 0) === 1
    },
    role: row.role,
    tenantDb: getTenantDbForCompany(company)
  };
}

function authenticateSuperAdmin(username, password) {
  const admin = masterDb.prepare(`
    SELECT id, username, full_name, password_hash, is_active
    FROM super_admins
    WHERE LOWER(username) = LOWER(?) AND is_active = 1
    LIMIT 1
  `).get(String(username || '').trim());
  if (!admin) return null;
  if (!verifyPassword(password, admin.password_hash)) return null;
  return admin;
}

function createSuperAdminSession(admin) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();
  masterDb.prepare(`
    INSERT INTO super_admin_sessions (session_token, super_admin_id, expires_at)
    VALUES (?, ?, ?)
  `).run(token, admin.id, expiresAt);
  return { token, expiresAt };
}

function destroySuperAdminSession(token) {
  if (!token) return;
  masterDb.prepare('DELETE FROM super_admin_sessions WHERE session_token = ?').run(token);
}

function getSuperAdminSession(req) {
  const cookies = parseCookies(req);
  const token = String(cookies[SUPERADMIN_SESSION_COOKIE] || '').trim();
  if (!token) return null;
  const row = masterDb.prepare(`
    SELECT s.session_token, s.expires_at, a.id, a.username, a.full_name, a.is_active
    FROM super_admin_sessions s
    JOIN super_admins a ON a.id = s.super_admin_id
    WHERE s.session_token = ?
    LIMIT 1
  `).get(token);
  if (!row) return null;
  if (row.is_active !== 1 || new Date(row.expires_at).getTime() <= Date.now()) {
    destroySuperAdminSession(token);
    return null;
  }
  return {
    token,
    admin: { id: row.id, username: row.username, full_name: row.full_name },
    expiresAt: row.expires_at
  };
}

function setSuperAdminSessionCookie(res, token, expiresAt, req = null) {
  const maxAge = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
  appendSetCookie(res, `${SUPERADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/superadmin; HttpOnly; Max-Age=${maxAge}; SameSite=Strict${isSecureRequest(req) ? '; Secure' : ''}`);
}

function clearSuperAdminSessionCookie(res) {
  appendSetCookie(res, `${SUPERADMIN_SESSION_COOKIE}=; Path=/superadmin; HttpOnly; Max-Age=0; SameSite=Lax`);
}

function getMasterCompanies() {
  return masterDb.prepare(`
    SELECT c.*, COUNT(u.id) AS total_users
    FROM companies c
    LEFT JOIN company_users u ON u.company_id = c.id AND u.is_active = 1
    GROUP BY c.id
    ORDER BY c.name COLLATE NOCASE
  `).all();
}

function getMasterCompanyUsers() {
  return masterDb.prepare(`
    SELECT u.id, u.company_id, u.username, u.full_name, u.role, u.is_active, u.created_at, c.name AS company_name, c.slug AS company_slug
    FROM company_users u
    JOIN companies c ON c.id = u.company_id
    ORDER BY c.name COLLATE NOCASE, u.username COLLATE NOCASE
  `).all();
}

function createTenantCompany({ name, slug, adminUsername, adminPassword }) {
  const normalizedName = String(name || '').trim();
  const normalizedSlug = slugifyCompanyName(slug || normalizedName);
  const normalizedAdminUsername = String(adminUsername || 'admin').trim().toLowerCase();
  if (!normalizedName) throw new Error('Informe o nome da empresa.');
  if (!normalizedSlug) throw new Error('Informe o identificador da empresa.');
  if (!normalizedAdminUsername) throw new Error('Informe o usuário administrador.');
  validateNewPassword(adminPassword);
  const exists = masterDb.prepare('SELECT id FROM companies WHERE LOWER(slug) = LOWER(?) LIMIT 1').get(normalizedSlug);
  if (exists) throw new Error('Já existe uma empresa com esse identificador.');

  const tenantRelativePath = path.join('data', 'tenants', `${normalizedSlug}.sqlite`);
  const tenantAbsolutePath = path.join(ROOT, tenantRelativePath);
  if (fs.existsSync(tenantAbsolutePath)) throw new Error('O banco dessa empresa já existe no servidor.');

  fs.mkdirSync(path.dirname(tenantAbsolutePath), { recursive: true });
  const tenantDb = new DatabaseSync(tenantAbsolutePath);
  bootstrapTenantDatabase(tenantDb);
  tenantDb.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES ('company_name', ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
  `).run(normalizedName);
  tenantDb.close();
  tenantDbCache.delete(tenantAbsolutePath);

  const result = masterDb.prepare(`
    INSERT INTO companies (slug, name, db_path, is_active, updated_at)
    VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
  `).run(normalizedSlug, normalizedName, tenantRelativePath);

  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active, must_change_password, updated_at)
    VALUES (?, ?, 'Administrador inicial', ?, 'adm', 1, 1, CURRENT_TIMESTAMP)
  `).run(result.lastInsertRowid, normalizedAdminUsername, hashPassword(adminPassword));

  return { id: Number(result.lastInsertRowid), name: normalizedName, slug: normalizedSlug, db_path: tenantRelativePath };
}

function createCompanyUser({ companyId, username, fullName, password, role }) {
  const company = masterDb.prepare('SELECT id, name FROM companies WHERE id = ? AND is_active = 1 LIMIT 1').get(Number(companyId));
  if (!company) throw new Error('Empresa inválida.');
  const normalizedUsername = String(username || '').trim().toLowerCase();
  const normalizedFullName = String(fullName || '').trim();
  const normalizedRole = ROLE_LABELS[role] ? role : '';
  if (!normalizedUsername) throw new Error('Informe o usuário.');
  if (!normalizedFullName) throw new Error('Informe o nome completo do usuário.');
  if (!normalizedRole) throw new Error('Perfil inválido.');
  validateNewPassword(password);
  const exists = masterDb.prepare('SELECT id FROM company_users WHERE company_id = ? AND LOWER(username) = LOWER(?) LIMIT 1').get(company.id, normalizedUsername);
  if (exists) throw new Error('Já existe um usuário com esse login nessa empresa.');
  masterDb.prepare(`
    INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active, must_change_password, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, 1, CURRENT_TIMESTAMP)
  `).run(company.id, normalizedUsername, normalizedFullName, hashPassword(password), normalizedRole);
}

// Redefinição pelo administrador: usuário é obrigado a trocar no próximo login
function updateCompanyUserPassword({ userId, password, mustChange = true }) {
  validateNewPassword(password);
  const result = masterDb.prepare('UPDATE company_users SET password_hash = ?, must_change_password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hashPassword(password), mustChange ? 1 : 0, Number(userId));
  if (!result.changes) throw new Error('Usuário não encontrado.');
  // Derruba as sessões abertas do usuário
  masterDb.prepare('DELETE FROM sessions WHERE company_user_id = ?').run(Number(userId));
}

const mimeTypes = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.webmanifest': 'application/manifest+json; charset=utf-8'
};


function ensureTenantLegacyUsersCompat(tenantDb) {
  const referencesLegacy = tenantDb.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE sql LIKE '%users_role_legacy%' AND type='table'").get().count > 0;
  if (!referencesLegacy) return;
  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS users_role_legacy AS
    SELECT id, username, full_name, password_hash, role, is_active, created_at, updated_at
    FROM users
    WHERE 1 = 0
  `);
  tenantDb.exec('DELETE FROM users_role_legacy');
  tenantDb.exec(`
    INSERT INTO users_role_legacy (id, username, full_name, password_hash, role, is_active, created_at, updated_at)
    SELECT id, username, full_name, password_hash, role, is_active, created_at, updated_at FROM users
  `);
  tenantDb.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_users_legacy_insert
    AFTER INSERT ON users
    BEGIN
      INSERT OR REPLACE INTO users_role_legacy (id, username, full_name, password_hash, role, is_active, created_at, updated_at)
      VALUES (NEW.id, NEW.username, NEW.full_name, NEW.password_hash, NEW.role, NEW.is_active, NEW.created_at, NEW.updated_at);
    END
  `);
  tenantDb.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_users_legacy_update
    AFTER UPDATE ON users
    BEGIN
      UPDATE users_role_legacy
      SET username = NEW.username,
          full_name = NEW.full_name,
          password_hash = NEW.password_hash,
          role = NEW.role,
          is_active = NEW.is_active,
          created_at = NEW.created_at,
          updated_at = NEW.updated_at
      WHERE id = NEW.id;
    END
  `);
  tenantDb.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_users_legacy_delete
    AFTER DELETE ON users
    BEGIN
      DELETE FROM users_role_legacy WHERE id = OLD.id;
    END
  `);
}

function upgradeTenantUserRoleConstraint(tenantDb) {
  const row = tenantDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'").get();
  const createSql = String(row?.sql || '');
  // A tabela "users" do banco da empresa é legada (o login usa company_users no banco mestre).
  // Não é recriada para o perfil Lançador: recriar quebraria as referências antigas (users_role_legacy).
  if (!createSql || createSql.includes("'apontamento'")) {
    ensureTenantLegacyUsersCompat(tenantDb);
    return;
  }
  tenantDb.exec('PRAGMA foreign_keys = OFF');
  tenantDb.exec(`
    ALTER TABLE users RENAME TO users_role_legacy;
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      password_hash TEXT,
      role TEXT NOT NULL CHECK (role IN ('adm', 'operacional', 'resultados', 'apontamento', 'lancador')),
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  {
    const legacyCols = tenantDb.prepare('PRAGMA table_info(users_role_legacy)').all().map(c => c.name);
    const cols = ['id', 'username', 'full_name', 'password_hash', 'role', 'is_active', 'created_at', 'updated_at'].filter(c => legacyCols.includes(c)).join(', ');
    tenantDb.exec(`INSERT INTO users (${cols}) SELECT ${cols} FROM users_role_legacy`);
  }
  ensureTenantLegacyUsersCompat(tenantDb);
  tenantDb.exec('PRAGMA foreign_keys = ON');
}

function migrateDatabase(tenantDb = db) {
  upgradeOpsStatusColorConstraint(tenantDb);
  repairLegacyOpForeignKeys(tenantDb);
  upgradeTenantUserRoleConstraint(tenantDb);
  ensureColumn(tenantDb, 'employees', 'start_date', 'TEXT');
  ensureColumn(tenantDb, 'employees', 'termination_date', 'TEXT');
  ensureColumn(tenantDb, 'employees', 'birth_date', 'TEXT');
  ensureColumn(tenantDb, 'employees', 'job_role', 'TEXT');
  ensureColumn(tenantDb, 'employees', 'phone', 'TEXT');
  ensureColumn(tenantDb, 'employees', 'target_percent', 'REAL');
  ensureColumn(tenantDb, 'ops', 'collection_name', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'delivery_date', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'pilot_mode', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'appliance', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'is_billed', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'ops', 'billed_at', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'billing_notes', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'billed_by_user_id', 'INTEGER REFERENCES users(id)');
  ensureColumn(tenantDb, 'ops', 'is_reversed', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'ops', 'reversed_at', 'TEXT');
  ensureColumn(tenantDb, 'ops', 'reversed_reason', 'TEXT');
  ensureColumn(tenantDb, 'op_daily_productions', 'normal_minutes', 'REAL NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'op_daily_productions', 'extra_minutes', 'REAL NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'op_daily_productions', 'extra_time_id', 'INTEGER REFERENCES op_extra_times(id)');
  ensureColumn(tenantDb, 'op_daily_productions', 'extra_reason_snapshot', 'TEXT');
  ensureColumn(tenantDb, 'op_daily_productions', 'extra_description_snapshot', 'TEXT');
  ensureColumn(tenantDb, 'op_daily_productions', 'extra_effective_date_snapshot', 'TEXT');
  ensureColumn(tenantDb, 'op_daily_productions', 'extra_minutes_per_piece_snapshot', 'REAL');
  tenantDb.prepare(`
    UPDATE op_daily_productions
    SET normal_minutes = produced_minutes
    WHERE COALESCE(normal_minutes, 0) = 0
      AND COALESCE(extra_minutes, 0) = 0
      AND COALESCE(produced_minutes, 0) != 0
  `).run();
  ensureColumn(tenantDb, 'op_daily_productions', 'is_reversed', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'op_daily_productions', 'reversed_at', 'TEXT');
  ensureColumn(tenantDb, 'op_daily_productions', 'reversed_reason', 'TEXT');

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS hourly_productions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
      employee_id INTEGER NOT NULL REFERENCES employees(id),
      production_date TEXT NOT NULL,
      hour_slot TEXT NOT NULL,
      produced_quantity INTEGER NOT NULL CHECK (produced_quantity > 0),
      used_minutes_f21 REAL NOT NULL,
      normal_minutes REAL NOT NULL DEFAULT 0,
      extra_minutes REAL NOT NULL DEFAULT 0,
      produced_minutes REAL NOT NULL,
      extra_time_id INTEGER REFERENCES op_extra_times(id),
      extra_reason_snapshot TEXT,
      extra_description_snapshot TEXT,
      extra_effective_date_snapshot TEXT,
      extra_minutes_per_piece_snapshot REAL,
      notes TEXT,
      created_by_user_id INTEGER REFERENCES users(id),
      is_validated INTEGER NOT NULL DEFAULT 0,
      validated_at TEXT,
      validated_daily_production_id INTEGER REFERENCES op_daily_productions(id),
      validated_by_user_id INTEGER REFERENCES users(id),
      is_reversed INTEGER NOT NULL DEFAULT 0,
      reversed_at TEXT,
      reversed_reason TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  tenantDb.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_hourly_productions_unique_active ON hourly_productions (employee_id, production_date, hour_slot) WHERE is_reversed = 0`);
  // Hora zero: hora em que a costureira não produziu peça (fica registrada, sem minutos)
  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS hourly_zero_hours (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL REFERENCES employees(id),
      production_date TEXT NOT NULL,
      hour_slot TEXT NOT NULL,
      reason TEXT,
      is_reversed INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_hourly_zero_unique_active ON hourly_zero_hours (employee_id, production_date, hour_slot) WHERE is_reversed = 0;
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS op_extra_times (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
      extra_minutes_per_piece REAL NOT NULL CHECK (extra_minutes_per_piece >= 0),
      reason TEXT NOT NULL,
      description TEXT,
      effective_date TEXT NOT NULL,
      notes TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_by_user_id INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS op_problem_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
      problem_date TEXT NOT NULL DEFAULT (date('now', '-3 hours')),
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      reason TEXT NOT NULL,
      notes TEXT,
      created_by_user_id INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  tenantDb.prepare(`
    UPDATE op_daily_productions
    SET
      extra_time_id = COALESCE(extra_time_id, (
        SELECT et.id
        FROM op_extra_times et
        WHERE et.op_id = op_daily_productions.op_id
          AND et.effective_date <= op_daily_productions.production_date
        ORDER BY et.effective_date DESC, et.id DESC
        LIMIT 1
      )),
      extra_reason_snapshot = COALESCE(NULLIF(extra_reason_snapshot, ''), (
        SELECT et.reason
        FROM op_extra_times et
        WHERE et.id = COALESCE(op_daily_productions.extra_time_id, (
          SELECT et2.id
          FROM op_extra_times et2
          WHERE et2.op_id = op_daily_productions.op_id
            AND et2.effective_date <= op_daily_productions.production_date
          ORDER BY et2.effective_date DESC, et2.id DESC
          LIMIT 1
        ))
      )),
      extra_description_snapshot = COALESCE(extra_description_snapshot, (
        SELECT et.description
        FROM op_extra_times et
        WHERE et.id = COALESCE(op_daily_productions.extra_time_id, (
          SELECT et2.id
          FROM op_extra_times et2
          WHERE et2.op_id = op_daily_productions.op_id
            AND et2.effective_date <= op_daily_productions.production_date
          ORDER BY et2.effective_date DESC, et2.id DESC
          LIMIT 1
        ))
      )),
      extra_effective_date_snapshot = COALESCE(extra_effective_date_snapshot, (
        SELECT et.effective_date
        FROM op_extra_times et
        WHERE et.id = COALESCE(op_daily_productions.extra_time_id, (
          SELECT et2.id
          FROM op_extra_times et2
          WHERE et2.op_id = op_daily_productions.op_id
            AND et2.effective_date <= op_daily_productions.production_date
          ORDER BY et2.effective_date DESC, et2.id DESC
          LIMIT 1
        ))
      )),
      extra_minutes_per_piece_snapshot = COALESCE(extra_minutes_per_piece_snapshot,
        CASE WHEN COALESCE(op_daily_productions.produced_quantity, 0) > 0 THEN ROUND(op_daily_productions.extra_minutes / op_daily_productions.produced_quantity, 3) ELSE NULL END
      )
    WHERE COALESCE(op_daily_productions.extra_minutes, 0) > 0
  `).run();
  ensureColumn(tenantDb, 'shipments', 'is_reversed', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'shipments', 'reversed_at', 'TEXT');
  ensureColumn(tenantDb, 'shipments', 'reversed_reason', 'TEXT');

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS brands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS collections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS sewing_cells (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      is_active INTEGER NOT NULL DEFAULT 1,
      notes TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS op_cell_transfers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
      cell_id INTEGER NOT NULL REFERENCES sewing_cells(id),
      quantity_sent INTEGER NOT NULL CHECK (quantity_sent > 0),
      quantity_returned INTEGER NOT NULL DEFAULT 0 CHECK (quantity_returned >= 0),
      sent_at TEXT NOT NULL,
      sent_notes TEXT,
      returned_at TEXT,
      return_notes TEXT,
      created_by_user_id INTEGER REFERENCES users(id),
      returned_by_user_id INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CHECK (quantity_returned <= quantity_sent)
    )
  `);

  ensureColumn(tenantDb, 'op_cell_transfers', 'quantity_sent', 'INTEGER NOT NULL DEFAULT 0');
  ensureColumn(tenantDb, 'op_cell_transfers', 'quantity_returned', 'INTEGER NOT NULL DEFAULT 0');
  tenantDb.prepare(`
    UPDATE op_cell_transfers
    SET quantity_sent = COALESCE(NULLIF(quantity_sent, 0), (SELECT total_pieces FROM ops WHERE ops.id = op_cell_transfers.op_id), 0)
    WHERE COALESCE(quantity_sent, 0) <= 0
  `).run();
  tenantDb.prepare(`
    UPDATE op_cell_transfers
    SET quantity_returned = CASE
      WHEN returned_at IS NOT NULL THEN COALESCE(NULLIF(quantity_returned, 0), quantity_sent, 0)
      ELSE COALESCE(quantity_returned, 0)
    END
    WHERE quantity_returned IS NULL OR (returned_at IS NOT NULL AND COALESCE(quantity_returned, 0) = 0)
  `).run();

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS cell_closures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      cell_id INTEGER NOT NULL REFERENCES sewing_cells(id),
      supplier_rate_per_minute REAL NOT NULL DEFAULT 0 CHECK (supplier_rate_per_minute >= 0),
      cell_rate_per_minute REAL NOT NULL DEFAULT 0 CHECK (cell_rate_per_minute >= 0),
      notes TEXT,
      total_ops INTEGER NOT NULL DEFAULT 0,
      total_pieces INTEGER NOT NULL DEFAULT 0,
      total_minutes REAL NOT NULL DEFAULT 0,
      total_received_amount REAL NOT NULL DEFAULT 0,
      total_paid_amount REAL NOT NULL DEFAULT 0,
      total_profit_amount REAL NOT NULL DEFAULT 0,
      created_by_user_id INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.exec(`
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
    )
  `);

  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS reversal_audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_type TEXT NOT NULL CHECK (target_type IN ('op', 'production', 'shipment')),
      target_id INTEGER NOT NULL,
      action_type TEXT NOT NULL CHECK (action_type IN ('estorno', 'correcao')),
      reason TEXT NOT NULL,
      before_json TEXT,
      after_json TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);


  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS op_billing_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
      billed_at TEXT NOT NULL,
      notes TEXT,
      batch_reference TEXT,
      created_by_user_id INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  tenantDb.prepare(`
    UPDATE ops
    SET brand = NULL, updated_at = CURRENT_TIMESTAMP
    WHERE LOWER(TRIM(COALESCE(brand, ''))) = 'primavera 27'
  `).run();

  tenantDb.prepare(`
    DELETE FROM brands
    WHERE LOWER(TRIM(name)) = 'primavera 27'
  `).run();

  tenantDb.prepare(`
    INSERT INTO brands (name)
    SELECT DISTINCT TRIM(brand)
    FROM ops
    WHERE TRIM(COALESCE(brand, '')) != ''
      AND LOWER(TRIM(brand)) != 'primavera 27'
      AND NOT EXISTS (
        SELECT 1 FROM brands b
        WHERE LOWER(TRIM(b.name)) = LOWER(TRIM(ops.brand))
      )
  `).run();

  tenantDb.prepare(`
    INSERT INTO collections (name)
    SELECT DISTINCT TRIM(collection_name)
    FROM ops
    WHERE TRIM(COALESCE(collection_name, '')) != ''
      AND NOT EXISTS (
        SELECT 1 FROM collections c
        WHERE LOWER(TRIM(c.name)) = LOWER(TRIM(ops.collection_name))
      )
  `).run();

  tenantDb.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES ('company_name', ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO NOTHING
  `).run(DEFAULT_COMPANY_NAME);

  tenantDb.exec('DROP VIEW IF EXISTS v_employee_daily_result');
  tenantDb.exec(`
    CREATE VIEW IF NOT EXISTS v_employee_daily_result AS
    SELECT
      p.employee_id,
      e.registration_code,
      e.full_name,
      e.start_date,
      e.termination_date,
      p.production_date,
      ROUND(SUM(p.produced_minutes), 2) AS produced_minutes_day,
      528.0 AS available_minutes_day,
      ROUND((SUM(p.produced_minutes) / 528.0) * 100, 2) AS result_percent_day
    FROM op_daily_productions p
    JOIN employees e ON e.id = p.employee_id
    GROUP BY p.employee_id, e.registration_code, e.full_name, e.start_date, e.termination_date, p.production_date
  `);

  migrateWorkSchedulesAndPrizeFlag(tenantDb);
  migrateOpNumberSuffix(tenantDb);
  migrateOpNumberSuffixReversedConflicts(tenantDb);
  ensureAlertTables(tenantDb);
}

// Segunda etapa (v2): quando a versão "-001" já existe mas está ESTORNADA, ela é renomeada
// para "-001-EST" e a OP ativa de 7 dígitos recebe o "-001". Conflitos com OP ativa continuam intocados.
function migrateOpNumberSuffixReversedConflicts(tenantDb) {
  if (tenantDb.prepare("SELECT 1 FROM app_settings WHERE key = 'migration_op_suffix_v2'").get()) return;
  const hasTable = name => Boolean(tenantDb.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
  const rows = tenantDb.prepare("SELECT id, TRIM(op_number) AS op_number FROM ops WHERE is_reversed = 0 AND TRIM(op_number) GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9]'").all();
  const find = tenantDb.prepare('SELECT id, is_reversed FROM ops WHERE TRIM(op_number) = ? COLLATE NOCASE');
  const rename = tenantDb.prepare('UPDATE ops SET op_number = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  const upShip = hasTable('shipment_items') ? tenantDb.prepare('UPDATE shipment_items SET op_number = ? WHERE op_id = ?') : null;
  const upCell = hasTable('cell_closure_items') ? tenantDb.prepare('UPDATE cell_closure_items SET op_number = ? WHERE op_id = ?') : null;
  const done = [];
  const skipped = [];
  tenantDb.exec('BEGIN');
  try {
    for (const row of rows) {
      const target = `${row.op_number}-001`;
      const existing = find.get(target);
      if (existing && !existing.is_reversed) { skipped.push(row.op_number); continue; }
      if (existing) {
        let archived = `${target}-EST`;
        for (let i = 2; find.get(archived); i += 1) archived = `${target}-EST${i}`;
        rename.run(archived, existing.id);
        if (upShip) upShip.run(archived, existing.id);
        if (upCell) upCell.run(archived, existing.id);
      }
      rename.run(target, row.id);
      if (upShip) upShip.run(target, row.id);
      if (upCell) upCell.run(target, row.id);
      done.push(row.op_number);
    }
    tenantDb.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('migration_op_suffix_v2', ?, CURRENT_TIMESTAMP)")
      .run(JSON.stringify({ fixed: done, skipped_active_conflict: skipped, at: new Date().toISOString() }));
    tenantDb.exec('COMMIT');
  } catch (error) {
    tenantDb.exec('ROLLBACK');
    console.error('Falha ao resolver conflitos de -001:', error.message);
  }
}

// Migração única: OPs com 7 dígitos ganham "-001" (ex.: 1801772 -> 1801772-001),
// inclusive nas cópias do número em embarques e fechamentos de célula.
// Se já existir a versão com "-001", não altera (fica registrado como conflito).
function migrateOpNumberSuffix(tenantDb) {
  if (tenantDb.prepare("SELECT 1 FROM app_settings WHERE key = 'migration_op_suffix_v1'").get()) return;
  const hasTable = name => Boolean(tenantDb.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name));
  const rows = tenantDb.prepare("SELECT id, TRIM(op_number) AS op_number FROM ops WHERE TRIM(op_number) GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9]'").all();
  const upOp = tenantDb.prepare('UPDATE ops SET op_number = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
  const upShip = hasTable('shipment_items') ? tenantDb.prepare('UPDATE shipment_items SET op_number = ? WHERE op_id = ?') : null;
  const upCell = hasTable('cell_closure_items') ? tenantDb.prepare('UPDATE cell_closure_items SET op_number = ? WHERE op_id = ?') : null;
  const exists = tenantDb.prepare('SELECT id FROM ops WHERE TRIM(op_number) = ? COLLATE NOCASE');
  let fixed = 0;
  const conflicts = [];
  tenantDb.exec('BEGIN');
  try {
    for (const row of rows) {
      const target = `${row.op_number}-001`;
      if (exists.get(target)) { conflicts.push(row.op_number); continue; }
      upOp.run(target, row.id);
      if (upShip) upShip.run(target, row.id);
      if (upCell) upCell.run(target, row.id);
      fixed += 1;
    }
    tenantDb.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('migration_op_suffix_v1', ?, CURRENT_TIMESTAMP)")
      .run(JSON.stringify({ fixed, conflicts, at: new Date().toISOString() }));
    tenantDb.exec('COMMIT');
  } catch (error) {
    tenantDb.exec('ROLLBACK');
    console.error('Falha ao completar -001 nas OPs:', error.message);
  }
}

// T0.3/T0.4 — Jornadas de trabalho e flag "conta para prêmio" nos lançamentos.
function migrateWorkSchedulesAndPrizeFlag(tenantDb) {
  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS work_schedules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      start_hour INTEGER NOT NULL CHECK (start_hour BETWEEN 0 AND 23),
      end_hour INTEGER NOT NULL CHECK (end_hour BETWEEN 1 AND 24),
      weekdays TEXT NOT NULL DEFAULT '1,2,3,4,5',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  ensureColumn(tenantDb, 'work_schedules', 'start_time', 'TEXT');
  ensureColumn(tenantDb, 'work_schedules', 'end_time', 'TEXT');
  ensureColumn(tenantDb, 'work_schedules', 'break_start', 'TEXT');
  ensureColumn(tenantDb, 'work_schedules', 'break_end', 'TEXT');
  tenantDb.exec(`
    UPDATE work_schedules SET
      start_time = COALESCE(start_time, printf('%02d:00', start_hour)),
      end_time = COALESCE(end_time, printf('%02d:00', end_hour))
    WHERE start_time IS NULL OR end_time IS NULL
  `);
  ensureColumn(tenantDb, 'employees', 'work_schedule_id', 'INTEGER REFERENCES work_schedules(id)');
  // Jornadas padrão (cadastradas uma única vez por empresa; podem ser editadas em Cadastros)
  if (!tenantDb.prepare("SELECT 1 FROM app_settings WHERE key = 'seed_work_schedules_v1'").get()) {
    const insertSchedule = tenantDb.prepare(`
      INSERT OR IGNORE INTO work_schedules (name, start_hour, end_hour, start_time, end_time, break_start, break_end, weekdays)
      VALUES (?, ?, ?, ?, ?, ?, ?, '1,2,3,4,5')
    `);
    insertSchedule.run('Primeiro turno', 5, 15, '05:00', '14:48', '09:00', '10:00');
    insertSchedule.run('Horário normal', 7, 17, '07:00', '16:48', '12:00', '13:00');
    tenantDb.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('seed_work_schedules_v1', '1', CURRENT_TIMESTAMP)").run();
  }
  ensureColumn(tenantDb, 'op_daily_productions', 'counts_for_prize', 'INTEGER NOT NULL DEFAULT 1');
  ensureColumn(tenantDb, 'op_daily_productions', 'launch_kind', 'TEXT');
  ensureColumn(tenantDb, 'op_daily_productions', 'worked_minutes', 'REAL');
  ensureColumn(tenantDb, 'hourly_productions', 'counts_for_prize', 'INTEGER NOT NULL DEFAULT 1');
  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS prize_flag_migration_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      daily_production_id INTEGER NOT NULL,
      production_date TEXT NOT NULL,
      employee_id INTEGER NOT NULL,
      produced_minutes REAL NOT NULL,
      reason TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Migração única: lançamentos antigos em sábado, domingo, feriado ou fora do período
  // ativo da colaboradora passam a NÃO contar para eficiência/prêmio (decisão do dono, 26/10/2026).
  const done = tenantDb.prepare("SELECT value FROM app_settings WHERE key = 'migration_prize_flag_v1'").get();
  if (done) return;

  const setting = key => tenantDb.prepare('SELECT value FROM app_settings WHERE key = ?').get(key)?.value || '';
  const holidays = buildHolidaySet(setting('holiday_dates'), setting('holiday_recurring_mmdd'), setting('worked_holiday_dates'));
  const rows = tenantDb.prepare(`
    SELECT p.id, p.production_date, p.employee_id, p.produced_minutes, e.start_date, e.termination_date
    FROM op_daily_productions p
    JOIN employees e ON e.id = p.employee_id
    WHERE p.is_reversed = 0 AND p.counts_for_prize = 1
  `).all();
  const mark = tenantDb.prepare('UPDATE op_daily_productions SET counts_for_prize = 0 WHERE id = ?');
  const markHourly = tenantDb.prepare('UPDATE hourly_productions SET counts_for_prize = 0 WHERE validated_daily_production_id = ?');
  const log = tenantDb.prepare('INSERT INTO prize_flag_migration_log (daily_production_id, production_date, employee_id, produced_minutes, reason) VALUES (?, ?, ?, ?, ?)');
  tenantDb.exec('BEGIN');
  try {
    for (const row of rows) {
      const reason = getNonPrizeReason(row.production_date, row, holidays);
      if (!reason) continue;
      mark.run(row.id);
      markHourly.run(row.id);
      log.run(row.id, row.production_date, row.employee_id, Number(row.produced_minutes || 0), reason);
    }
    tenantDb.prepare("INSERT INTO app_settings (key, value, updated_at) VALUES ('migration_prize_flag_v1', ?, CURRENT_TIMESTAMP)").run(new Date().toISOString());
    tenantDb.exec('COMMIT');
  } catch (error) {
    tenantDb.exec('ROLLBACK');
    throw error;
  }
}

function buildHolidaySet(explicitRaw, recurringRaw, workedOverrideRaw) {
  const split = raw => String(raw || '').split(/[,\n;]/).map(item => item.trim()).filter(Boolean);
  const all = new Set(split(explicitRaw));
  for (const mmdd of split(recurringRaw)) {
    if (!/^\d{2}-\d{2}$/.test(mmdd)) continue;
    for (let year = 2020; year <= 2035; year += 1) all.add(`${year}-${mmdd}`);
  }
  for (const workedDate of split(workedOverrideRaw)) all.delete(workedDate);
  return all;
}

// Motivo pelo qual um dia NÃO é dia útil da colaboradora (vazio = dia útil normal)
function getNonPrizeReason(dateValue, employee, holidays) {
  if (employee?.start_date && dateValue < employee.start_date) return 'antes_admissao';
  if (employee?.termination_date && dateValue > employee.termination_date) return 'apos_desligamento';
  if (holidays.has(dateValue)) return 'feriado';
  const weekday = new Date(`${dateValue}T00:00:00Z`).getUTCDay();
  if (weekday === 6) return 'sabado';
  if (weekday === 0) return 'domingo';
  return '';
}


function upgradeOpsStatusColorConstraint(tenantDb) {
  const row = tenantDb.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ops'").get();
  const createSql = String(row?.sql || '');
  if (!createSql || createSql.includes("'rosa'")) return;

  tenantDb.exec('PRAGMA foreign_keys = OFF');
  tenantDb.exec(`
    ALTER TABLE ops RENAME TO ops_legacy_status;

    CREATE TABLE ops (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      barcode TEXT UNIQUE,
      op_number TEXT NOT NULL UNIQUE,
      product_name TEXT NOT NULL,
      op_type TEXT NOT NULL CHECK (op_type IN ('producao', 'mostruario')),
      brand TEXT,
      collection_name TEXT,
      pilot_mode TEXT,
      appliance TEXT,
      total_pieces INTEGER NOT NULL CHECK (total_pieces > 0),
      minutes_f21 REAL NOT NULL CHECK (minutes_f21 >= 0),
      minutes_f22 REAL NOT NULL DEFAULT 0 CHECK (minutes_f22 >= 0),
      f23_mode TEXT NOT NULL CHECK (f23_mode IN ('interno', 'externo')),
      minutes_f23 REAL,
      entry_date TEXT NOT NULL DEFAULT (date('now', '-3 hours')),
      entered_by_user_id INTEGER REFERENCES users(id),
      notes TEXT,
      status_color TEXT NOT NULL DEFAULT 'verde' CHECK (status_color IN ('verde', 'amarelo', 'azul', 'rosa', 'vermelho')),
      lifecycle_type TEXT NOT NULL DEFAULT 'normal' CHECK (lifecycle_type IN ('normal', 'devolvida_sem_producao', 'nao_industrializada')),
      shipped_at TEXT,
      returned_without_production_at TEXT,
      return_reason TEXT,
      is_reversed INTEGER NOT NULL DEFAULT 0,
      reversed_at TEXT,
      reversed_reason TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CHECK ((f23_mode = 'interno' AND minutes_f23 IS NOT NULL) OR f23_mode = 'externo')
    );

    INSERT INTO ops (
      id, barcode, op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, entered_by_user_id, notes,
      status_color, lifecycle_type, shipped_at, returned_without_production_at, return_reason, is_reversed,
      reversed_at, reversed_reason, created_at, updated_at
    )
    SELECT
      id, barcode, op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance,
      total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, entered_by_user_id, notes,
      status_color, lifecycle_type, shipped_at, returned_without_production_at, return_reason, is_reversed,
      reversed_at, reversed_reason, created_at, updated_at
    FROM ops_legacy_status;

    DROP TABLE ops_legacy_status;
  `);
  tenantDb.exec('PRAGMA foreign_keys = ON');
}


function repairLegacyOpForeignKeys(tenantDb) {
  tenantDb.exec('DROP VIEW IF EXISTS v_op_production_summary');
  tenantDb.exec('DROP VIEW IF EXISTS v_employee_daily_result');
  const targets = [
    {
      name: 'op_daily_productions',
      createSql: `CREATE TABLE op_daily_productions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
        employee_id INTEGER NOT NULL REFERENCES employees(id),
        production_date TEXT NOT NULL,
        produced_quantity INTEGER NOT NULL CHECK (produced_quantity > 0),
        used_minutes_f21 REAL NOT NULL,
        normal_minutes REAL NOT NULL DEFAULT 0,
        extra_minutes REAL NOT NULL DEFAULT 0,
        produced_minutes REAL NOT NULL,
        created_by_user_id INTEGER REFERENCES users(id),
        is_reversed INTEGER NOT NULL DEFAULT 0,
        reversed_at TEXT,
        reversed_reason TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )`,
      columns: 'id, op_id, employee_id, production_date, produced_quantity, used_minutes_f21, normal_minutes, extra_minutes, produced_minutes, created_by_user_id, is_reversed, reversed_at, reversed_reason, created_at'
    },
    {
      name: 'op_occurrences',
      createSql: `CREATE TABLE op_occurrences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
        description TEXT NOT NULL,
        opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        opened_by_user_id INTEGER REFERENCES users(id),
        is_concluded INTEGER NOT NULL DEFAULT 0,
        concluded_at TEXT,
        conclusion_reason TEXT,
        concluded_by_user_id INTEGER REFERENCES users(id)
      )`,
      columns: 'id, op_id, description, opened_at, opened_by_user_id, is_concluded, concluded_at, conclusion_reason, concluded_by_user_id'
    },
    {
      name: 'shipment_items',
      createSql: `CREATE TABLE shipment_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shipment_id INTEGER NOT NULL REFERENCES shipments(id) ON DELETE CASCADE,
        op_id INTEGER NOT NULL REFERENCES ops(id),
        op_number TEXT NOT NULL,
        op_type TEXT NOT NULL CHECK (op_type IN ('producao', 'mostruario')),
        total_pieces INTEGER NOT NULL,
        sewing_minutes REAL NOT NULL DEFAULT 0,
        post_sewing_minutes REAL NOT NULL DEFAULT 0,
        total_minutes REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (shipment_id, op_id)
      )`,
      columns: 'id, shipment_id, op_id, op_number, op_type, total_pieces, sewing_minutes, post_sewing_minutes, total_minutes, created_at'
    },
    {
      name: 'op_cell_transfers',
      createSql: `CREATE TABLE op_cell_transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op_id INTEGER NOT NULL REFERENCES ops(id) ON DELETE CASCADE,
        cell_id INTEGER NOT NULL REFERENCES sewing_cells(id),
        quantity_sent INTEGER NOT NULL CHECK (quantity_sent > 0),
        quantity_returned INTEGER NOT NULL DEFAULT 0 CHECK (quantity_returned >= 0),
        sent_at TEXT NOT NULL,
        sent_notes TEXT,
        returned_at TEXT,
        return_notes TEXT,
        created_by_user_id INTEGER REFERENCES users(id),
        returned_by_user_id INTEGER REFERENCES users(id),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK (quantity_returned <= quantity_sent)
      )`,
      columns: 'id, op_id, cell_id, quantity_sent, quantity_returned, sent_at, sent_notes, returned_at, return_notes, created_by_user_id, returned_by_user_id, created_at, updated_at'
    }
  ];

  for (const target of targets) {
    const row = tenantDb.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name = ?").get(target.name);
    if (!String(row?.sql || '').includes('ops_legacy_status')) continue;
    tenantDb.exec('PRAGMA foreign_keys = OFF');
    tenantDb.exec(`ALTER TABLE ${target.name} RENAME TO ${target.name}_legacy_fix;`);
    tenantDb.exec(target.createSql);
    tenantDb.exec(`INSERT INTO ${target.name} (${target.columns}) SELECT ${target.columns} FROM ${target.name}_legacy_fix;`);
    tenantDb.exec(`DROP TABLE ${target.name}_legacy_fix;`);
    tenantDb.exec('PRAGMA foreign_keys = ON');
  }
}

function ensureColumn(tenantDb, tableName, columnName, definition) {
  const columns = tenantDb.prepare(`PRAGMA table_info(${tableName})`).all();
  const exists = columns.some(column => column.name === columnName);
  if (!exists) {
    tenantDb.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

function seedIfNeeded() {
  const hasEmployees = db.prepare('SELECT COUNT(*) AS count FROM employees').get().count;
  const hasOps = db.prepare('SELECT COUNT(*) AS count FROM ops').get().count;

  if (!hasEmployees) {
    const stmt = db.prepare('INSERT INTO employees (registration_code, full_name, notes) VALUES (?, ?, ?)');
    stmt.run('001', 'Ana Silva', 'Piloto inicial');
    stmt.run('014', 'Beatriz Costa', 'Costura reta');
    stmt.run('022', 'Carlos Souza', 'Apoio geral');
  }

  if (!hasOps) {
    const insertOp = db.prepare(`
      INSERT INTO ops (
        barcode, op_number, product_name, op_type, brand, total_pieces,
        minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    db.prepare("INSERT OR IGNORE INTO brands (name) VALUES (?)").run('Marca Alfa');
    db.prepare("INSERT OR IGNORE INTO brands (name) VALUES (?)").run('Marca Beta');
    insertOp.run('7891001001', 'OP-1001', 'Camisa Polo', 'producao', 'Marca Alfa', 300, 7.45, 2.5, 'interno', 1.2, today(), 'OP de exemplo');
    insertOp.run('7891001002', 'OP-1002', 'Jaqueta', 'mostruario', 'Marca Beta', 120, 9.37, 3.1, 'externo', null, today(), 'OP de exemplo');

    const op1 = db.prepare('SELECT id, minutes_f21 FROM ops WHERE op_number = ?').get('OP-1001');
    const op2 = db.prepare('SELECT id, minutes_f21 FROM ops WHERE op_number = ?').get('OP-1002');
    const ana = db.prepare('SELECT id FROM employees WHERE registration_code = ?').get('001');
    const bia = db.prepare('SELECT id FROM employees WHERE registration_code = ?').get('014');

    const launch = db.prepare(`
      INSERT INTO op_daily_productions (op_id, employee_id, production_date, produced_quantity, used_minutes_f21, produced_minutes)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    launch.run(op1.id, ana.id, today(), 20, op1.minutes_f21, round2(20 * op1.minutes_f21));
    launch.run(op1.id, bia.id, today(), 15, op1.minutes_f21, round2(15 * op1.minutes_f21));
    launch.run(op2.id, bia.id, today(), 10, op2.minutes_f21, round2(10 * op2.minutes_f21));

    recalculateOpStatus(op1.id);
    recalculateOpStatus(op2.id);
  }
}

function today(date = new Date()) {
  return BUSINESS_DATE_FMT.format(date);
}

function currentHourSlot(date = new Date()) {
  return `${BUSINESS_HOUR_FMT.format(date).padStart(2, '0')}:00`;
}

function normalizeHourSlotInput(value) {
  const raw = String(value || '').trim();
  if (!raw) return currentHourSlot();
  const compact = raw.replace(/\D/g, '');
  if (/^\d{3,4}$/.test(compact)) {
    const hour = Number(compact.slice(0, compact.length - 2));
    if (!Number.isInteger(hour) || hour < 0 || hour > 23) return '';
    return `${String(hour).padStart(2, '0')}:00`;
  }
  const match = raw.match(/^(\d{1,2})(?::(\d{1,2}))?$/);
  if (!match) return '';
  const hour = Number(match[1]);
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) return '';
  return `${String(hour).padStart(2, '0')}:00`;
}

function normalizeOpNumberInput(value) {
  const raw = String(value || '').trim().toUpperCase();
  if (!raw) return '';
  if (/^\d{7}$/.test(raw)) return `${raw}-001`;
  return raw;
}

function nowPt(value) {
  if (!value) return '-';
  const raw = String(value);
  if (raw.length === 10) {
    // Data de negócio: só reformatar, sem conversão de fuso
    return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeZone: 'UTC' }).format(new Date(`${raw}T00:00:00Z`));
  }
  // Timestamp de auditoria: gravado em UTC (CURRENT_TIMESTAMP vem sem "Z"), exibido em Brasília
  const normalized = /[zZ]|[+-]\d{2}:?\d{2}$/.test(raw) ? raw : `${raw.replace(' ', 'T')}Z`;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return raw;
  return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short', timeZone: BUSINESS_TZ }).format(date);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function round2(value) {
  return Math.round(Number(value || 0) * 100) / 100;
}

function round3(value) {
  return Math.round(Number(value || 0) * 1000) / 1000;
}

function getEffectiveLaunchMinutes(op) {
  const f21 = Number(op?.minutes_f21 || 0);
  const f22 = Number(op?.minutes_f22 || 0);
  return round3(Math.max(f21 - f22, 0));
}

function getActiveOpExtraTimeForOp(opId, refDate = today()) {
  return db.prepare(`
    SELECT *
    FROM op_extra_times
    WHERE op_id = ?
      AND is_active = 1
      AND effective_date <= ?
    ORDER BY effective_date DESC, id DESC
    LIMIT 1
  `).get(Number(opId), refDate) || null;
}

function calculateProductionLaunchMetrics(op, producedQuantity, usedMinutesF21, productionDate = today()) {
  const qty = Number(producedQuantity || 0);
  const launchF21 = round3(Number(usedMinutesF21 || 0));
  const normalPerPiece = Math.max(launchF21 - Number(op?.minutes_f22 || 0), 0);
  const extraConfig = getActiveOpExtraTimeForOp(op?.id, productionDate);
  const extraPerPiece = Number(extraConfig?.extra_minutes_per_piece || 0);
  const normalMinutes = round3(qty * normalPerPiece);
  const extraMinutes = round3(qty * extraPerPiece);
  const totalMinutes = round3(normalMinutes + extraMinutes);
  return {
    launchF21,
    normalPerPiece: round3(normalPerPiece),
    extraPerPiece: round3(extraPerPiece),
    normalMinutes,
    extraMinutes,
    totalMinutes,
    extraConfig,
    extraSnapshot: extraConfig ? {
      extra_time_id: Number(extraConfig.id),
      extra_reason_snapshot: extraConfig.reason || '',
      extra_description_snapshot: extraConfig.description || null,
      extra_effective_date_snapshot: extraConfig.effective_date || null,
      extra_minutes_per_piece_snapshot: round3(extraPerPiece)
    } : {
      extra_time_id: null,
      extra_reason_snapshot: null,
      extra_description_snapshot: null,
      extra_effective_date_snapshot: null,
      extra_minutes_per_piece_snapshot: null
    }
  };
}

function parseBody(req, maxBytes = 1_000_000) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > maxBytes) {
        reject(new Error('Payload muito grande'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(querystring.parse(raw)));
    req.on('error', reject);
  });
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function buildRedirectWithFlash(target, message, isError = false) {
  const safeTarget = typeof target === 'string' && target.startsWith('/') ? target : '/ops';
  const [pathname, search = ''] = safeTarget.split('?');
  const params = new URLSearchParams(search);
  params.set(isError ? 'error' : 'notice', message);
  const query = params.toString();
  return `${pathname}${query ? `?${query}` : ''}`;
}

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendText(res, text, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(text);
}

function sendJson(res, payload, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function serveStatic(reqPath, res) {
  const filePath = path.normalize(path.join(PUBLIC_DIR, reqPath.replace('/public/', '')));
  if (!filePath.startsWith(PUBLIC_DIR)) return sendText(res, 'Forbidden', 403);
  if (!fs.existsSync(filePath)) return sendText(res, 'Not found', 404);
  const ext = path.extname(filePath).toLowerCase();
  res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' });
  res.end(fs.readFileSync(filePath));
}


function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  return raw.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function appendSetCookie(res, cookieValue) {
  const current = res.getHeader('Set-Cookie');
  if (!current) {
    res.setHeader('Set-Cookie', cookieValue);
    return;
  }
  const values = Array.isArray(current) ? current.concat(cookieValue) : [current, cookieValue];
  res.setHeader('Set-Cookie', values);
}

function setSessionCookie(res, token, expiresAt, req = null) {
  const maxAge = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
  appendSetCookie(res, `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${maxAge}; SameSite=Lax${isSecureRequest(req) ? '; Secure' : ''}`);
}

function clearSessionCookie(res) {
  appendSetCookie(res, `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax`);
}

function getRequestRole() {
  return getRequestAuth()?.role || 'adm';
}

function isAdminRole(role) {
  return role === 'adm';
}

function canAccessCadastros(role) {
  return role === 'adm' || role === 'operacional';
}

function isHourlyLauncherRole(role) {
  return role === 'apontamento';
}

function canAccessHourlyLauncher(role) {
  return role === 'adm' || role === 'operacional' || role === 'apontamento' || role === 'lancador';
}

// T1.8 — Perfil Lançador (chão de fábrica): lançamentos, consulta de OP, célula, ocorrências,
// peças com problema e etiquetas de entrada. Sem financeiro, prêmio, fechamento e dados pessoais.
function isLancadorRole(role) {
  return role === 'lancador';
}

function isLancadorAllowed(method, pathname) {
  if (['GET', 'POST'].includes(method) && pathname === '/productions/hourly/quadro') return true;
  if (method === 'GET' && ['/productions/new', '/productions/hourly', '/ops', '/labels/entry', '/api/op-preview', '/conta/senha'].includes(pathname)) return true;
  if (method === 'POST' && ['/productions', '/productions/hourly', '/productions/hourly/validate', '/conta/senha', '/logout'].includes(pathname)) return true;
  if (method === 'GET' && /^\/ops\/\d+$/.test(pathname)) return true;
  if (method === 'POST' && /^\/productions\/hourly\/(\d+\/fix|zero\/\d+\/delete)$/.test(pathname)) return true;
  if (method === 'POST' && /^\/ops\/\d+\/(occurrences|problem-items|cell\/send|cell\/return)$/.test(pathname)) return true;
  if (method === 'POST' && /^\/ops\/\d+\/occurrences\/\d+\/conclude$/.test(pathname)) return true;
  return false;
}

function requireAuthentication(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const target = parsedUrl.pathname + parsedUrl.search;
  redirect(res, `/login?returnTo=${encodeURIComponent(target)}`);
  return true;
}

function requireAdmin(req, res, role) {
  if (isAdminRole(role)) return false;
  sendHtml(res, pageLayout({
    title: 'Acesso restrito',
    content: `<section class="panel"><h2>Acesso restrito</h2><p>Este módulo está liberado somente para perfil Administrador.</p><p class="hint">Perfil atual: ${escapeHtml(ROLE_LABELS[role] || role)}.</p></section>`,
    error: 'Acesso permitido apenas para administrador.',
    role
  }), 403);
  return true;
}

function requireHourlyLauncherAccess(res, role) {
  if (canAccessHourlyLauncher(role)) return false;
  sendHtml(res, pageLayout({
    title: 'Acesso restrito',
    content: `<section class="panel"><h2>Acesso restrito</h2><p>Este módulo está liberado somente para Administrador, Operacional e Apontamento.</p><p class="hint">Perfil atual: ${escapeHtml(ROLE_LABELS[role] || role)}.</p></section>`,
    error: 'Acesso não permitido para este perfil.',
    role
  }), 403);
  return true;
}

function renderLoginPage(values = {}, error = '', notice = '') {
  return `<!doctype html>
  <html lang="pt-BR">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Login - AgilFac</title>
    <link rel="stylesheet" href="/public/styles.css" />
    <link rel="manifest" href="/manifest.webmanifest" />
    <meta name="theme-color" content="#0f172a" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-title" content="AgilFac" />
    <link rel="apple-touch-icon" href="/public/icons/apple-touch-icon.png" />
  </head>
  <body>
    <main class="content" style="max-width:520px;margin:48px auto;">
      <section class="panel">
        <h1 style="margin-top:0;">Entrar no AgilFac</h1>
        <p class="hint">Acesse informando empresa, usuário e senha.</p>
        ${notice ? `<div class="alert success">${escapeHtml(notice)}</div>` : ''}
        ${error ? `<div class="alert error">${escapeHtml(error)}</div>` : ''}
        <form method="post" action="/login" class="stack-form">
          <input type="hidden" name="returnTo" value="${escapeHtml(values.returnTo || '')}" />
          <label>Empresa
            <input name="company" value="${escapeHtml(values.company || '')}" placeholder="Digite sua empresa" required />
          </label>
          <label>Usuário
            <input name="username" value="${escapeHtml(values.username || '')}" autocomplete="username" required />
          </label>
          <label>Senha
            <input name="password" type="password" autocomplete="current-password" required />
          </label>
          <button class="btn primary" type="submit">Entrar</button>
        </form>
      </section>
    </main>
  </body>
  </html>`;
}

function handleLogin(form, res, req = null) {
  const companyValue = String(form.company || '').trim();
  const username = String(form.username || '').trim();
  const password = String(form.password || '');
  const returnTo = String(form.returnTo || '/').trim() || '/';
  const companyKey = companyValue.toLowerCase();
  if (isLoginBlocked('company', req, companyKey, username)) {
    recordLoginAttempt('company', req, companyKey, username, false);
    return sendHtml(res, renderLoginPage({ company: companyValue, username, returnTo }, `Muitas tentativas. Aguarde ${LOGIN_WINDOW_MINUTES} minutos e tente novamente.`), 429);
  }
  const company = findCompanyByLogin(companyValue);
  const user = company ? authenticateCompanyUser(company.id, username, password) : null;
  if (!user) {
    recordLoginAttempt('company', req, companyKey, username, false);
    return sendHtml(res, renderLoginPage({ company: companyValue, username, returnTo }, 'Empresa, usuário ou senha inválidos.'), 401);
  }
  recordLoginAttempt('company', req, companyKey, username, true);
  masterDb.prepare('UPDATE company_users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), user.id);
  const session = createSession(company, user);
  setSessionCookie(res, session.token, session.expiresAt, req);
  if (Number(user.must_change_password || 0) === 1) return redirect(res, '/conta/senha');
  const safeReturn = returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/';
  redirect(res, safeReturn);
}

function renderChangePasswordPage(auth, error = '', notice = '') {
  const forced = auth?.user?.must_change_password;
  const content = `
    <section class="page-header"><div><h2>Trocar senha</h2><p>${forced ? 'Por segurança, defina uma senha pessoal antes de continuar.' : 'Defina uma nova senha de acesso.'}</p></div></section>
    <form class="panel stack-form" method="post" action="/conta/senha" style="max-width:420px">
      <label>Senha atual<input type="password" name="current_password" required autocomplete="current-password" /></label>
      <label>Nova senha<input type="password" name="new_password" required minlength="${PASSWORD_MIN_LENGTH}" autocomplete="new-password" /></label>
      <label>Confirmar nova senha<input type="password" name="confirm_password" required minlength="${PASSWORD_MIN_LENGTH}" autocomplete="new-password" /></label>
      <p class="hint">Mínimo de ${PASSWORD_MIN_LENGTH} caracteres. Não use a senha temporária.</p>
      <div class="actions"><button class="btn" type="submit">Salvar nova senha</button></div>
    </form>
    ${forced ? '<form method="post" action="/logout"><button class="btn secondary" type="submit">Sair</button></form>' : ''}
  `;
  return pageLayout({ title: 'Trocar senha', content, error, notice, role: auth?.role || 'adm' });
}

function handleChangePassword(form, res, auth) {
  const current = String(form.current_password || '');
  const next = String(form.new_password || '');
  const confirm = String(form.confirm_password || '');
  const row = masterDb.prepare('SELECT password_hash FROM company_users WHERE id = ?').get(auth.user.id);
  if (!row || !verifyPassword(current, row.password_hash)) return sendHtml(res, renderChangePasswordPage(auth, 'Senha atual incorreta.'), 422);
  if (next !== confirm) return sendHtml(res, renderChangePasswordPage(auth, 'A confirmação não confere com a nova senha.'), 422);
  if (next === current) return sendHtml(res, renderChangePasswordPage(auth, 'A nova senha precisa ser diferente da atual.'), 422);
  try {
    validateNewPassword(next);
  } catch (error) {
    return sendHtml(res, renderChangePasswordPage(auth, error.message), 422);
  }
  masterDb.prepare('UPDATE company_users SET password_hash = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hashPassword(next), auth.user.id);
  // Encerra outras sessões do usuário, mantém a atual
  masterDb.prepare('DELETE FROM sessions WHERE company_user_id = ? AND session_token <> ?').run(auth.user.id, auth.token);
  redirect(res, '/?notice=' + encodeURIComponent('Senha alterada com sucesso.'));
}

function handleLogout(req, res) {
  const cookies = parseCookies(req);
  destroySession(cookies[SESSION_COOKIE]);
  clearSessionCookie(res);
  redirect(res, '/login?notice=' + encodeURIComponent('Sessão encerrada com sucesso.'));
}

function renderSuperAdminLoginPage(values = {}, error = '', notice = '') {
  const bootstrapHint = BOOTSTRAP_INFO?.generatedSuperadminPassword ? `
    <div class="alert success">
      Primeiro acesso do superadmin liberado.<br />
      Usuário: <strong>superadmin</strong> · Senha temporária: <strong>${escapeHtml(BOOTSTRAP_INFO.generatedSuperadminPassword)}</strong>
    </div>
  ` : '';
  return `<!doctype html>
  <html lang="pt-BR">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Superadmin - AgilFac</title>
    <link rel="stylesheet" href="/public/styles.css" />
  </head>
  <body>
    <main class="content" style="max-width:520px;margin:48px auto;">
      <section class="panel">
        <h1 style="margin-top:0;">Superadmin AgilFac</h1>
        <p class="hint">Painel separado para criação de empresas e gestão estrutural.</p>
        ${notice ? `<div class="alert success">${escapeHtml(notice)}</div>` : ''}
        ${error ? `<div class="alert error">${escapeHtml(error)}</div>` : ''}
        ${bootstrapHint}
        <form method="post" action="/superadmin/login" class="stack-form">
          <label>Usuário<input name="username" value="${escapeHtml(values.username || '')}" autocomplete="username" required /></label>
          <label>Senha<input name="password" type="password" autocomplete="current-password" required /></label>
          <button class="btn primary" type="submit">Entrar no superadmin</button>
        </form>
      </section>
    </main>
  </body>
  </html>`;
}

function handleSuperAdminLogin(form, res, req = null) {
  const username = String(form.username || '').trim();
  const password = String(form.password || '');
  if (isLoginBlocked('superadmin', req, '', username)) {
    recordLoginAttempt('superadmin', req, '', username, false);
    return sendHtml(res, renderSuperAdminLoginPage({ username }, `Muitas tentativas. Aguarde ${LOGIN_WINDOW_MINUTES} minutos.`), 429);
  }
  const admin = authenticateSuperAdmin(username, password);
  if (!admin) {
    recordLoginAttempt('superadmin', req, '', username, false);
    return sendHtml(res, renderSuperAdminLoginPage({ username }, 'Usuário ou senha inválidos.'), 401);
  }
  recordLoginAttempt('superadmin', req, '', username, true);
  const session = createSuperAdminSession(admin);
  setSuperAdminSessionCookie(res, session.token, session.expiresAt, req);
  redirect(res, '/superadmin');
}

function handleSuperAdminLogout(req, res) {
  const cookies = parseCookies(req);
  destroySuperAdminSession(cookies[SUPERADMIN_SESSION_COOKIE]);
  clearSuperAdminSessionCookie(res);
  redirect(res, '/superadmin/login?notice=' + encodeURIComponent('Sessão de superadmin encerrada.'));
}

function renderSuperAdminPanel(query = {}, values = {}, error = '', notice = '') {
  const companies = getMasterCompanies();
  const content = `
    <section class="page-header"><div><h2>Superadmin</h2><p>Criação de empresas, bancos isolados e provisionamento inicial.</p></div></section>
    <section class="panel form-grid">
      <div class="full"><h3 style="margin-top:0;">Nova empresa</h3></div>
      <form class="full form-grid" method="post" action="/superadmin/companies">
        <label>Nome da empresa<input name="company_name" required value="${escapeHtml(values.company_name || '')}" /></label>
        <label>Slug / identificador<input name="company_slug" value="${escapeHtml(values.company_slug || '')}" placeholder="empresa-b" /></label>
        <label>Usuário admin inicial<input name="admin_username" value="${escapeHtml(values.admin_username || 'admin')}" required /></label>
        <label>Senha inicial<input type="password" name="admin_password" required /></label>
        <div class="full actions"><button class="btn" type="submit">Criar empresa e banco</button></div>
      </form>
    </section>
    ${renderSuperAdminBackupsSection()}
    <section class="panel">
      <h3 style="margin-top:0;">Empresas provisionadas</h3>
      ${companies.length ? `<div class="table-wrapper"><table><thead><tr><th>Empresa</th><th>Slug</th><th>Banco</th><th>Usuários</th></tr></thead><tbody>${companies.map(company => `
        <tr>
          <td>${escapeHtml(company.name)}</td>
          <td>${escapeHtml(company.slug)}</td>
          <td><span class="hint">${escapeHtml(company.db_path)}</span></td>
          <td>${escapeHtml(String(company.total_users || 0))}</td>
        </tr>
      `).join('')}</tbody></table></div>` : '<p class="hint">Nenhuma empresa cadastrada.</p>'}
    </section>
  `;
  const top = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Superadmin - AgilFac</title><link rel="stylesheet" href="/public/styles.css" /></head><body><div class="layout"><aside class="sidebar"><h1>Superadmin</h1><nav><a href="/superadmin" class="active">Empresas</a></nav><div class="sidebar-note"><strong>Painel estrutural</strong><p>Use este ambiente para criar novas empresas e provisionar bases isoladas.</p><form method="post" action="/superadmin/logout" style="margin-top:12px;"><button class="btn secondary" type="submit">Sair</button></form></div></aside><main class="content">${notice ? `<div class="alert success">${escapeHtml(notice)}</div>` : ''}${error ? `<div class="alert error">${escapeHtml(error)}</div>` : ''}${content}</main></div></body></html>`;
  return top;
}

// T0.8 — Backups disponíveis para download (somente superadmin; arquivos criptografados)
const BACKUP_DIR = path.join(ROOT, 'backups');
const BACKUP_FILE_RE = /^agilfac-[0-9_-]+\.tar\.gz\.enc$/;

function listBackupFiles() {
  const out = [];
  for (const sub of ['', 'mensal']) {
    const dir = path.join(BACKUP_DIR, sub);
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir)) {
      if (!BACKUP_FILE_RE.test(name)) continue;
      const stat = fs.statSync(path.join(dir, name));
      out.push({ kind: sub || 'diario', name, size: stat.size, mtime: stat.mtime });
    }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

function renderSuperAdminBackupsSection() {
  const files = listBackupFiles();
  return `
    <section class="panel">
      <h3 style="margin-top:0;">Backups</h3>
      <p class="hint">Cópia diária às 02:00 de todos os bancos, criptografada (AES-256). Guardados no servidor: 30 diários + 12 mensais. Baixe periodicamente para o seu computador.</p>
      ${files.length ? `<div class="table-wrapper"><table><thead><tr><th>Arquivo</th><th>Tipo</th><th>Gerado em</th><th>Tamanho</th><th></th></tr></thead><tbody>${files.map(f => `
        <tr>
          <td>${escapeHtml(f.name)}</td>
          <td>${f.kind === 'mensal' ? 'Mensal' : 'Diário'}</td>
          <td>${escapeHtml(nowPt(f.mtime.toISOString()))}</td>
          <td>${fmtNum(f.size / 1024 / 1024, 2)} MB</td>
          <td><a class="btn secondary" href="/superadmin/backups/download?kind=${f.kind}&file=${encodeURIComponent(f.name)}">Baixar</a></td>
        </tr>`).join('')}</tbody></table></div>` : '<p class="hint">Nenhum backup gerado ainda.</p>'}
    </section>`;
}

function handleSuperAdminBackupDownload(query, res) {
  const name = String(query.file || '');
  const sub = query.kind === 'mensal' ? 'mensal' : '';
  if (!BACKUP_FILE_RE.test(name)) return sendHtml(res, 'Arquivo inválido.', 400);
  const filePath = path.join(BACKUP_DIR, sub, name);
  if (!fs.existsSync(filePath)) return sendHtml(res, 'Arquivo não encontrado.', 404);
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${name}"`,
    'Content-Length': fs.statSync(filePath).size,
    'Cache-Control': 'no-store'
  });
  fs.createReadStream(filePath).pipe(res);
}

function handleSuperAdminCreateCompany(form, res) {
  try {
    createTenantCompany({
      name: form.company_name,
      slug: form.company_slug,
      adminUsername: form.admin_username,
      adminPassword: form.admin_password
    });
    redirect(res, `/superadmin?notice=${encodeURIComponent('Empresa criada com sucesso no painel de superadmin.')}`);
  } catch (error) {
    sendHtml(res, renderSuperAdminPanel({}, form, error.message), 422);
  }
}

function getBrandList({ onlyActive = true, search = '' } = {}) {
  let sql = 'SELECT id, name, is_active, created_at, updated_at FROM brands';
  const where = [];
  const params = [];
  if (onlyActive) {
    where.push('is_active = 1');
  }
  if (search) {
    where.push('name LIKE ?');
    params.push(`%${search}%`);
  }
  if (where.length) sql += ` WHERE ${where.join(' AND ')}`;
  sql += ' ORDER BY name COLLATE NOCASE';
  return db.prepare(sql).all(...params);
}

function findBrandByName(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return null;
  return db.prepare('SELECT * FROM brands WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1').get(normalized);
}

function getCollectionList({ onlyActive = true, search = '' } = {}) {
  let sql = 'SELECT id, name, is_active, created_at, updated_at FROM collections';
  const where = [];
  const params = [];
  if (onlyActive) {
    where.push('is_active = 1');
  }
  if (search) {
    where.push('name LIKE ?');
    params.push(`%${search}%`);
  }
  if (where.length) sql += ` WHERE ${where.join(' AND ')}`;
  sql += ' ORDER BY name COLLATE NOCASE';
  return db.prepare(sql).all(...params);
}

function findCollectionByName(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return null;
  return db.prepare('SELECT * FROM collections WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1').get(normalized);
}


function userCanManageCells(role = 'adm') {
  return CELL_ALLOWED_ROLES.has(String(role || '').trim());
}

function getCellList({ onlyActive = true, search = '' } = {}) {
  let sql = 'SELECT id, name, is_active, notes, created_at, updated_at FROM sewing_cells';
  const where = [];
  const params = [];
  if (onlyActive) where.push('is_active = 1');
  if (search) {
    where.push('(name LIKE ? OR COALESCE(notes, "") LIKE ?)');
    params.push(`%${search}%`, `%${search}%`);
  }
  if (where.length) sql += ` WHERE ${where.join(' AND ')}`;
  sql += ' ORDER BY name COLLATE NOCASE';
  return db.prepare(sql).all(...params);
}

function findCellByName(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return null;
  return db.prepare('SELECT * FROM sewing_cells WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1').get(normalized);
}

function getCellById(id) {
  return db.prepare('SELECT * FROM sewing_cells WHERE id = ?').get(Number(id));
}

function getOpenQuantityFromCellTransfer(transfer) {
  return Math.max(Number(transfer?.quantity_sent || 0) - Number(transfer?.quantity_returned || 0), 0);
}

function getCurrentCellTransfer(opId) {
  return db.prepare(`
    SELECT t.*, c.name AS cell_name
    FROM op_cell_transfers t
    JOIN sewing_cells c ON c.id = t.cell_id
    WHERE t.op_id = ? AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0)
    ORDER BY t.sent_at DESC, t.id DESC
    LIMIT 1
  `).get(Number(opId)) || null;
}

function getOpenCellTransfers(opId) {
  return db.prepare(`
    SELECT t.*, c.name AS cell_name
    FROM op_cell_transfers t
    JOIN sewing_cells c ON c.id = t.cell_id
    WHERE t.op_id = ? AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0)
    ORDER BY t.sent_at DESC, t.id DESC
  `).all(Number(opId));
}

function getOpCellTransfers(opId) {
  return db.prepare(`
    SELECT t.*, c.name AS cell_name
    FROM op_cell_transfers t
    JOIN sewing_cells c ON c.id = t.cell_id
    WHERE t.op_id = ?
    ORDER BY COALESCE(t.returned_at, t.sent_at) DESC, t.id DESC
  `).all(Number(opId));
}

function getOpCellBalance(opId) {
  const totals = db.prepare(`
    SELECT
      COALESCE(SUM(quantity_sent), 0) AS total_sent,
      COALESCE(SUM(quantity_returned), 0) AS total_returned,
      COALESCE(SUM(quantity_sent - quantity_returned), 0) AS total_open,
      COUNT(*) AS total_moves,
      SUM(CASE WHEN COALESCE(quantity_sent, 0) > COALESCE(quantity_returned, 0) THEN 1 ELSE 0 END) AS open_transfers
    FROM op_cell_transfers
    WHERE op_id = ?
  `).get(Number(opId)) || {};
  return {
    total_sent: Number(totals.total_sent || 0),
    total_returned: Number(totals.total_returned || 0),
    total_open: Math.max(Number(totals.total_open || 0), 0),
    total_moves: Number(totals.total_moves || 0),
    open_transfers: Number(totals.open_transfers || 0)
  };
}

function validateCellName(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return 'Informe o nome da célula.';
  if (normalized.length < 2) return 'A célula precisa ter pelo menos 2 caracteres.';
  return '';
}

function validateBrandName(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return 'Informe o nome da marca.';
  if (normalized.length < 2) return 'A marca precisa ter pelo menos 2 caracteres.';
  if (BLOCKED_BRAND_NAMES.has(normalized.toLowerCase())) return 'Essa marca não é permitida nesta base.';
  return '';
}

function validateCollectionName(name) {
  const normalized = String(name || '').trim();
  if (!normalized) return 'Informe o nome da coleção.';
  if (normalized.length < 2) return 'A coleção precisa ter pelo menos 2 caracteres.';
  return '';
}

// ===================== PARÂMETROS POR EMPRESA =====================
// Cada empresa ajusta suas regras em Parâmetros. Valores padrão = regras originais do AgilFac.
const PARAM_DEFAULTS = {
  base_minutes_day: '528',
  target_percent: '60',
  period_start_day: '26',
  workdays: '1,2,3,4,5',
  prize_tier1_percent: '40', prize_tier1_value: '30',
  prize_tier2_percent: '45', prize_tier2_value: '60',
  prize_tier3_percent: '50', prize_tier3_value: '90',
  prize_target_value: '400',
  prize_extra_block_minutes: '100',
  prize_extra_value: '10',
  absence_types_excluded_from_base: 'atestado,ferias,folga,afastamento',
  holiday_dates: '',
  holiday_recurring_mmdd: '',
  worked_holiday_dates: '',
  launch_previous_day_until_hour: '9'
};
const paramsCache = new WeakMap();

function getParams() {
  const dbKey = getActiveDb();
  const cached = paramsCache.get(dbKey);
  if (cached && Date.now() - cached.at < 60000) return cached.values;
  const rows = db.prepare(`SELECT key, value FROM app_settings WHERE key IN (${Object.keys(PARAM_DEFAULTS).map(() => '?').join(',')})`).all(...Object.keys(PARAM_DEFAULTS));
  const values = { ...PARAM_DEFAULTS };
  for (const row of rows) if (row.value !== null && row.value !== undefined) values[row.key] = String(row.value);
  paramsCache.set(dbKey, { at: Date.now(), values });
  return values;
}

function invalidateParams() {
  paramsCache.delete(getActiveDb());
}

function numParam(key) {
  const n = Number(String(getParams()[key]).replace(',', '.'));
  return Number.isFinite(n) ? n : Number(PARAM_DEFAULTS[key]);
}

function baseMinutesDay() { return numParam('base_minutes_day'); }
function targetPercent() { return numParam('target_percent'); }
function targetRatio() { return targetPercent() / 100; }
function tp() { return fmtNum(targetPercent(), Number.isInteger(targetPercent()) ? 0 : 2); }
// Meta mínima da colaboradora: própria (cadastro) ou a padrão da empresa (Parâmetros)
const employeeTargetCache = new WeakMap();
function employeeTargetPercent(employee) {
  if (!employee) return targetPercent();
  let value = employee.target_percent;
  if (value === undefined && (employee.id || employee.employee_id)) {
    const store = getActiveDb();
    let map = employeeTargetCache.get(store);
    if (!map || Date.now() - map.at > 30000) {
      map = { at: Date.now(), byId: new Map(db.prepare('SELECT id, target_percent FROM employees').all().map(r => [r.id, r.target_percent])) };
      employeeTargetCache.set(store, map);
    }
    value = map.byId.get(Number(employee.employee_id ?? employee.id));
  }
  return Number(value) > 0 ? Number(value) : targetPercent();
}
function employeeTargetRatio(employee) { return employeeTargetPercent(employee) / 100; }
function fmtPct(value) { return fmtNum(value, Number.isInteger(Number(value)) ? 0 : 2); }
function parseEmployeeTarget(value) {
  const n = Number(String(value ?? '').replace(',', '.').replace('%', ''));
  return Number.isFinite(n) && n > 0 && n <= 200 ? round2(n) : null;
}
function workdaySet() { return new Set(String(getParams().workdays).split(',').map(Number).filter(d => d >= 0 && d <= 6)); }
// Janela de data dos lançamentos (rápido, lista e por hora): hoje sempre; o dia anterior
// (último dia útil e o fim de semana entre eles) só até a hora definida em Parâmetros (padrão 09h).
// Administrador não tem trava (para datas antigas existe Hora extra / retroativo).
function launchDateWindow() {
  const cutoff = Math.min(Math.max(Math.round(numParam('launch_previous_day_until_hour')), 0), 23);
  const now = Number(BUSINESS_HOUR_FMT.format(new Date()));
  const max = today();
  const previousOpen = now < cutoff;
  return { min: previousOpen ? getPreviousBusinessDay(max) : max, max, cutoff, previousOpen };
}

function checkLaunchDate(date, role) {
  const d = String(date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return 'Data inválida.';
  if (d > today()) return 'Não é permitido lançar em data futura.';
  if (isAdminRole(role)) return '';
  const w = launchDateWindow();
  if (d < w.min) {
    return w.cutoff > 0
      ? `Lançamento do dia anterior só até as ${String(w.cutoff).padStart(2, '0')}h de hoje. Para outras datas, fale com o administrador.`
      : 'Só é permitido lançar na data de hoje. Para outras datas, fale com o administrador.';
  }
  return '';
}

function launchDateAttrs(role) {
  if (isAdminRole(role)) return `max="${today()}"`;
  const w = launchDateWindow();
  return `min="${w.min}" max="${w.max}"`;
}

function launchDateHint(role) {
  const w = launchDateWindow();
  if (isAdminRole(role) || !w.previousOpen) return '';
  return `<small class="hint">Até as ${String(w.cutoff).padStart(2, '0')}h dá para lançar no dia anterior (${formatDatePtBr(w.min)}).</small>`;
}

function periodStartDay() { return Math.min(Math.max(Math.round(numParam('period_start_day')), 1), 28); }
function periodLabel() { const s = periodStartDay(); return s === 1 ? 'mês civil' : `${s} → ${s - 1}`; }

function getAppSetting(key, fallback = '') {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ? LIMIT 1').get(String(key || '').trim());
  return String(row?.value || fallback || '').trim();
}

function getCompanyName() {
  return getAppSetting('company_name', DEFAULT_COMPANY_NAME) || DEFAULT_COMPANY_NAME;
}

function getHolidayDateSet() {
  return buildHolidaySet(
    getAppSetting('holiday_dates', ''),
    getAppSetting('holiday_recurring_mmdd', ''),
    getAppSetting('worked_holiday_dates', '')
  );
}

function setAppSetting(key, value) {
  invalidateParams();
  db.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
  `).run(String(key || '').trim(), String(value || '').trim());
}

function isActiveOpCondition(alias = 'o') {
  return `${alias}.is_reversed = 0`;
}

function isActiveProductionCondition(alias = 'p') {
  return `${alias}.is_reversed = 0`;
}

function isActiveShipmentCondition(alias = 's') {
  return `${alias}.is_reversed = 0`;
}

function safeJson(value) {
  try {
    return JSON.stringify(value ?? null);
  } catch {
    return null;
  }
}

function logAuditEntry(targetType, targetId, actionType, reason, beforeValue, afterValue = null) {
  db.prepare(`
    INSERT INTO reversal_audit_log (target_type, target_id, action_type, reason, before_json, after_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `).run(targetType, targetId, actionType, String(reason || '').trim(), safeJson(beforeValue), safeJson(afterValue));
}

function getRecentAuditEntries(limit = 30) {
  return db.prepare(`
    SELECT *
    FROM reversal_audit_log
    ORDER BY created_at DESC, id DESC
    LIMIT ?
  `).all(limit);
}

function getAuditLabel(entry) {
  const item = REVERSAL_TYPES[entry.target_type] || entry.target_type;
  return `${entry.action_type === 'estorno' ? 'Estorno' : 'Correção'} · ${item}`;
}

function normalizeReason(value) {
  return String(value || '').trim();
}

function renderRoleSwitcher(role) {
  const auth = getRequestAuth();
  if (!auth) return '';
  return `
    <div class="role-switcher">
      <div><strong>${escapeHtml(auth.company.name)}</strong></div>
      <div class="hint">Usuário: ${escapeHtml(auth.user.full_name || auth.user.username)}</div>
      <div class="hint">Perfil: ${escapeHtml(ROLE_LABELS[role] || role)}</div>
      <a class="hint" href="/conta/senha">Trocar minha senha</a>
      <form method="post" action="/logout" style="margin-top:12px;">
        <button class="btn secondary" type="submit">Sair</button>
      </form>
    </div>
  `;
}

// T1.7 — Menu agrupado (Produção, Expedição, Financeiro, Pessoas, Configurações), grupos recolhíveis
const NAV_GROUPS = [
  { key: 'producao', label: 'Produção', hrefs: ['/', '/acompanhamento/diario', '/productions/hourly', '/productions/hourly/quadro', '/productions/new', '/productions/extra', '/ops/new', '/ops', '/labels/entry', '/op-extra-times'] },
  { key: 'expedicao', label: 'Expedição', hrefs: ['/shipments/new', '/shipments', '/labels/shipment'] },
  { key: 'financeiro', label: 'Financeiro', hrefs: ['/billing-reconciliation', '/closures', '/ausencias/importar', '/premios/producao', '/cells/report', '/cells/closures'] },
  { key: 'pessoas', label: 'Pessoas', hrefs: ['/employees'] },
  { key: 'config', label: 'Configurações', hrefs: ['/cadastros', '/parametros', '/admin/access', '/estornos'] }
];

function renderNavLink(item) {
  return `<a href="${item.href}" ${item.active ? 'class="active"' : ''}><span class="nav-icon">${item.icon}</span><span class="nav-label">${escapeHtml(item.label)}</span></a>`;
}

function renderGroupedNav(navItems) {
  if (navItems.length <= 6) return navItems.map(renderNavLink).join('');
  const used = new Set();
  const groups = NAV_GROUPS.map(group => {
    const items = group.hrefs.map(href => navItems.find(item => item.href === href)).filter(Boolean);
    items.forEach(item => used.add(item.href));
    return { ...group, items };
  }).filter(group => group.items.length);
  const rest = navItems.filter(item => !used.has(item.href));
  if (rest.length) groups.push({ key: 'outros', label: 'Outros', items: rest });
  return groups.map(group => `
    <details class="nav-group" data-nav-group="${group.key}" open>
      <summary>${escapeHtml(group.label)}</summary>
      ${group.items.map(renderNavLink).join('')}
    </details>`).join('') + `<script>
    (() => {
      let state = {};
      try { state = JSON.parse(localStorage.getItem('agilfac_nav') || '{}'); } catch (_) {}
      document.querySelectorAll('[data-nav-group]').forEach(el => {
        const key = el.dataset.navGroup;
        if (state[key] === false && !el.querySelector('a.active')) el.open = false;
        el.addEventListener('toggle', () => { state[key] = el.open; try { localStorage.setItem('agilfac_nav', JSON.stringify(state)); } catch (_) {} });
      });
    })();
  </script>`;
}

function pageLayout({ title, content, notice = '', error = '', role = 'adm' }) {
  const navItems = isLancadorRole(role)
    ? [
        { href: '/productions/new', label: 'Lançamentos', icon: '🧵', active: title === 'Novo lançamento' },
        { href: '/productions/hourly', label: 'Lanç. hora', icon: '⏰', active: title === 'Lançamento por hora' },
        { href: '/productions/hourly/quadro', label: 'Quadro hora', icon: '🗓️', active: title === 'Quadro por hora' },
        { href: '/ops', label: 'Consulta OP', icon: '📦', active: title.startsWith('OPs') || title.startsWith('OP ') },
        { href: '/labels/entry', label: 'Etiq. entrada', icon: '🏷️', active: title.startsWith('Etiquetas de entrada') }
      ]
    : isHourlyLauncherRole(role)
    ? [
        { href: '/', label: 'Dashboard', icon: '🏠', active: title === 'Dashboard' },
        { href: '/productions/hourly', label: 'Lanç. hora', icon: '⏰', active: title === 'Lançamento por hora' },
        { href: '/productions/hourly/quadro', label: 'Quadro hora', icon: '🗓️', active: title === 'Quadro por hora' }
      ]
    : [
        { href: '/', label: 'Dashboard', icon: '🏠', active: title === 'Dashboard' },
        { href: '/acompanhamento/diario', label: 'Acomp. diário', icon: '📈', active: title.startsWith('Acompanhamento diário') },
        { href: '/productions/hourly', label: 'Lanç. hora', icon: '⏰', active: title === 'Lançamento por hora' },
        { href: '/productions/hourly/quadro', label: 'Quadro hora', icon: '🗓️', active: title === 'Quadro por hora' },
        { href: '/productions/new', label: 'Lançamentos', icon: '🧵', active: title === 'Novo lançamento' },
        { href: '/productions/extra', label: 'Hora extra', icon: '🌙', active: title === 'Lançamento hora extra' },
        { href: '/ops/new', label: 'Cadastro OP', icon: '📝', active: title === 'Nova OP' },
        { href: '/labels/entry', label: 'Etiq. entrada', icon: '🏷️', active: title.startsWith('Etiquetas de entrada') },
        { href: '/ops', label: 'Consulta OP', icon: '📦', active: title.startsWith('OPs') },
        { href: '/billing-reconciliation', label: 'Cobrança', icon: '💵', active: title.startsWith('Conciliação de cobrança') },
        { href: '/shipments/new', label: 'Embarque', icon: '🚚', active: title === 'Novo embarque' },
        { href: '/shipments', label: 'Consulta emb.', icon: '📋', active: title.startsWith('Embarques') },
        { href: '/labels/shipment', label: 'Etiq. emb.', icon: '🧾', active: title.startsWith('Etiquetas de embarque') },
        { href: '/employees', label: 'Colaboradores', icon: '👥', active: title === 'Novo colaborador' || title.startsWith('Colaboradores') },
        { href: '/closures', label: 'Fechamento', icon: '📊', active: title.startsWith('Fechamento') || title === 'Importar ausências' },
        { href: '/premios/producao', label: 'Prêmio prod.', icon: '💰', active: title.startsWith('Prêmio de produção') },
        { href: '/cells/report', label: 'Célula', icon: '🩷', active: title.startsWith('Célula') },
        { href: '/cells/closures', label: 'Fech. células', icon: '🧮', active: title.startsWith('Fechamento de células') }
      ];

  if (canAccessCadastros(role)) {
    navItems.push({ href: '/op-extra-times', label: 'Tempo extra', icon: '⏱️', active: title.startsWith('Tempo extra de OP') });
    navItems.push({ href: '/cadastros', label: 'Cadastros', icon: '⚙️', active: title.startsWith('Cadastros') });
  }
  if (isAdminRole(role)) {
    navItems.push({ href: '/parametros', label: 'Parâmetros', icon: '🎛️', active: title === 'Parâmetros' });
    navItems.push({ href: '/admin/access', label: 'Acessos', icon: '🔐', active: title.startsWith('Usuários e acessos') });
    navItems.push({ href: '/estornos', label: 'Estornos', icon: '↩️', active: title.startsWith('Estornos') });
  }

  return `<!doctype html>
  <html lang="pt-BR">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)} - AgilFac</title>
    <link rel="stylesheet" href="/public/styles.css" />
    <link rel="manifest" href="/manifest.webmanifest" />
    <meta name="theme-color" content="#0f172a" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-title" content="AgilFac" />
    <link rel="apple-touch-icon" href="/public/icons/apple-touch-icon.png" />
    <script>if ('serviceWorker' in navigator) window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));</script>
  </head>
  <body class="sidebar-collapsed">
    <div class="layout app-layout">
      <aside class="sidebar app-sidebar" id="app-sidebar">
        <div class="sidebar-brand">AgilFac</div>
        <nav>
          ${renderGroupedNav(navItems)}
        </nav>
      </aside>
      <main class="content app-content">
        <div class="top-bar">
          <button class="btn secondary menu-toggle" type="button" id="menu-toggle">☰ Menu</button>
          <div class="top-meta top-meta-actions">
            <span class="role-badge">${escapeHtml(getRequestAuth()?.company?.name || 'AgilFac')} · ${escapeHtml(ROLE_LABELS[role] || role)}</span>
            <form method="post" action="/logout">
              <button class="btn secondary" type="submit">Sair</button>
            </form>
          </div>
        </div>
        ${notice ? `<div class="alert success">${escapeHtml(notice)}</div>` : ''}
        ${error ? `<div class="alert error">${escapeHtml(error)}</div>` : ''}
        ${content}
      </main>
    </div>
    <script>
      (() => {
        const storageKey = 'agilfac-sidebar-hidden';
        const mobileBreakpoint = 1100;
        const body = document.body;
        const toggle = document.getElementById('menu-toggle');
        const navLinks = Array.from(document.querySelectorAll('#app-sidebar nav a'));
        if (!toggle) return;

        const applyState = hidden => {
          body.classList.toggle('sidebar-collapsed', hidden);
          toggle.textContent = hidden ? '☰ Menu' : '✕ Fechar';
          toggle.setAttribute('aria-expanded', hidden ? 'false' : 'true');
        };

        const saveState = hidden => {
          localStorage.setItem(storageKey, hidden ? 'true' : 'false');
          applyState(hidden);
        };

        const saved = localStorage.getItem(storageKey);
        applyState(saved !== 'false');

        toggle.addEventListener('click', () => {
          const hidden = !body.classList.contains('sidebar-collapsed');
          saveState(hidden);
        });

        navLinks.forEach(link => {
          link.addEventListener('click', () => {
            if (window.innerWidth <= mobileBreakpoint) {
              saveState(true);
            }
          });
        });
      })();
    </script>
  </body>
  </html>`;
}

function getDashboardBrands(opType = '') {
  if (!opType) return getBrandList().map(item => item.name);
  return db.prepare(`
    SELECT DISTINCT b.name AS brand
    FROM brands b
    JOIN ops o ON LOWER(TRIM(o.brand)) = LOWER(TRIM(b.name))
    WHERE b.is_active = 1 AND o.is_reversed = 0 AND o.op_type = ?
    ORDER BY b.name COLLATE NOCASE
  `).all(opType).map(r => r.brand);
}

function getDashboardData(period = 'day', date = today(), opType = 'mostruario', brand = '', startDate = '', endDate = '', filterByShipmentDate = false) {
  const dailyRange = getPeriodRange(period, date);
  const effectiveStartDate = startDate || '';
  const effectiveEndDate = endDate || '';
  const hasExplicitRange = Boolean(effectiveStartDate && effectiveEndDate);

  const companyWideWhere = ["COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')"];
  const companyWideParams = [];
  if (opType) {
    companyWideWhere.push('o.op_type = ?');
    companyWideParams.push(opType);
  }
  const companyWideWhereSql = companyWideWhere.length ? `WHERE ${companyWideWhere.join(' AND ')}` : '';

  const filteredWhere = ["COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')"];
  const filteredParams = [];
  if (opType) {
    filteredWhere.push('o.op_type = ?');
    filteredParams.push(opType);
  }
  if (brand) {
    filteredWhere.push('o.brand = ?');
    filteredParams.push(brand);
  }
  if (hasExplicitRange) {
    const rangeStart = effectiveStartDate <= effectiveEndDate ? effectiveStartDate : effectiveEndDate;
    const rangeEnd = effectiveStartDate <= effectiveEndDate ? effectiveEndDate : effectiveStartDate;
    filteredWhere.push(filterByShipmentDate ? 'o.shipped_at BETWEEN ? AND ?' : 'o.entry_date BETWEEN ? AND ?');
    filteredParams.push(rangeStart, rangeEnd);
    dailyRange.start = rangeStart;
    dailyRange.end = rangeEnd;
    dailyRange.label = filterByShipmentDate ? 'Período de embarque' : 'Período filtrado';
  }
  const whereSql = filteredWhere.length ? `WHERE ${filteredWhere.join(' AND ')}` : '';

  const companyWideSummary = db.prepare(`
    SELECT
      COUNT(*) AS total_ops,
      COALESCE(SUM(total_pieces), 0) AS total_pieces,
      COALESCE(SUM(total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0))), 0) AS total_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'verde' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS green_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'amarelo' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS yellow_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'azul' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS blue_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'rosa' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS pink_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'verde' THEN 1 ELSE 0 END), 0) AS green_ops,
      COALESCE(SUM(CASE WHEN status_color = 'amarelo' THEN 1 ELSE 0 END), 0) AS yellow_ops,
      COALESCE(SUM(CASE WHEN status_color = 'azul' THEN 1 ELSE 0 END), 0) AS blue_ops,
      COALESCE(SUM(CASE WHEN status_color = 'rosa' THEN 1 ELSE 0 END), 0) AS pink_ops
    FROM ops o
    ${companyWideWhereSql}
  `).get(...companyWideParams);

  const filteredSummary = db.prepare(`
    SELECT
      COUNT(*) AS total_ops,
      COALESCE(SUM(total_pieces), 0) AS total_pieces,
      COALESCE(SUM(total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0))), 0) AS total_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'verde' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS green_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'amarelo' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS yellow_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'azul' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS blue_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'rosa' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS pink_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'vermelho' THEN total_pieces * (COALESCE(minutes_f21,0) + COALESCE(minutes_f22,0)) ELSE 0 END), 0) AS red_sewing_minutes,
      COALESCE(SUM(CASE WHEN status_color = 'verde' THEN 1 ELSE 0 END), 0) AS green_ops,
      COALESCE(SUM(CASE WHEN status_color = 'amarelo' THEN 1 ELSE 0 END), 0) AS yellow_ops,
      COALESCE(SUM(CASE WHEN status_color = 'azul' THEN 1 ELSE 0 END), 0) AS blue_ops,
      COALESCE(SUM(CASE WHEN status_color = 'rosa' THEN 1 ELSE 0 END), 0) AS pink_ops,
      COALESCE(SUM(CASE WHEN status_color = 'vermelho' THEN 1 ELSE 0 END), 0) AS red_ops
    FROM ops o
    ${whereSql}
  `).get(...filteredParams);

  const launchWhere = ['o.is_reversed = 0', 'p.is_reversed = 0', "COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')"];
  const launchParams = [];
  if (opType) {
    launchWhere.push('o.op_type = ?');
    launchParams.push(opType);
  }
  if (brand) {
    launchWhere.push('o.brand = ?');
    launchParams.push(brand);
  }
  const launchWhereSql = launchWhere.length ? `WHERE ${launchWhere.join(' AND ')}` : '';

  const productionTotals = db.prepare(`
    SELECT
      COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity,
      COALESCE(SUM(p.produced_minutes), 0) AS produced_minutes
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    ${launchWhereSql}
    ${launchWhere.length ? 'AND' : 'WHERE'} p.production_date BETWEEN ? AND ?
  `).get(...launchParams, dailyRange.start, dailyRange.end);

  // Eficiência das colaboradoras: regra oficial única, todas as OPs, até o corte
  // (último dia útil anterior a hoje), igual ao Acompanhamento diário.
  const efficiencyCutoff = [dailyRange.end, getPreviousBusinessDay(today())].sort()[0];
  const allEmployees = db.prepare(`
    SELECT id, registration_code, full_name, start_date, termination_date, is_active
    FROM employees
  `).all();
  const countedMap = efficiencyCutoff >= dailyRange.start
    ? getCountedProductionByEmployee(dailyRange.start, efficiencyCutoff, allEmployees)
    : new Map();
  const employees = allEmployees
    .map(employee => {
      const counted = countedMap.get(employee.id);
      const producedMinutes = round2(counted?.minutes || 0);
      const eff = calculateEmployeeEfficiency(employee, producedMinutes, dailyRange.start, dailyRange.end, efficiencyCutoff);
      return {
        ...employee,
        produced_minutes: producedMinutes,
        produced_quantity: Number(counted?.qty || 0),
        active_days: eff.business_days,
        available_minutes: eff.available_minutes,
        efficiency_percent: eff.efficiency_percent
      };
    })
    .filter(employee => getEmployeeBusinessDaysInRange(employee, dailyRange.start, dailyRange.end).length > 0)
    .sort((x, y) => (y.produced_minutes - x.produced_minutes) || String(x.full_name).localeCompare(String(y.full_name)));

  const opRows = db.prepare(`
    SELECT
      o.id,
      o.op_number,
      o.product_name,
      o.brand,
      o.total_pieces,
      o.status_color,
      (SELECT c.name FROM op_cell_transfers t JOIN sewing_cells c ON c.id = t.cell_id WHERE t.op_id = o.id AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0) ORDER BY t.id DESC LIMIT 1) AS active_cell_name,
      ROUND(o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)), 2) AS sewing_minutes,
      COALESCE(SUM(p.produced_quantity), 0) AS total_produced,
      o.total_pieces - COALESCE(SUM(p.produced_quantity), 0) AS remaining
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    ${whereSql}
    GROUP BY o.id
    ORDER BY o.entry_date DESC, o.created_at DESC
    LIMIT 12
  `).all(...filteredParams);

  const pinkWhere = [...filteredWhere, "o.status_color = 'rosa'"];
  const pinkWhereSql = pinkWhere.length ? `WHERE ${pinkWhere.join(' AND ')}` : '';
  const pinkOpRows = db.prepare(`
    SELECT
      o.id,
      o.op_number,
      o.product_name,
      o.brand,
      o.status_color,
      (SELECT c.name FROM op_cell_transfers t JOIN sewing_cells c ON c.id = t.cell_id WHERE t.op_id = o.id AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0) ORDER BY t.id DESC LIMIT 1) AS active_cell_name,
      COALESCE(SUM(p.produced_quantity), 0) AS total_produced,
      o.total_pieces - COALESCE(SUM(p.produced_quantity), 0) AS remaining,
      ROUND((o.total_pieces - COALESCE(SUM(p.produced_quantity), 0)) * MAX(COALESCE(o.minutes_f21,0) - COALESCE(o.minutes_f22,0), 0), 3) AS remaining_minutes
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    ${pinkWhereSql}
    GROUP BY o.id
    ORDER BY o.entry_date DESC, o.created_at DESC
    LIMIT 12
  `).all(...filteredParams);

  const companyWideBrands = db.prepare(`
    SELECT
      COALESCE(NULLIF(TRIM(o.brand), ''), 'Sem marca') AS brand,
      COUNT(*) AS total_ops,
      ROUND(COALESCE(SUM(o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0))), 0), 2) AS sewing_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'verde' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS green_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'amarelo' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS yellow_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'azul' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS blue_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'rosa' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS pink_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'vermelho' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS red_minutes
    FROM ops o
    ${companyWideWhereSql}
    GROUP BY COALESCE(NULLIF(TRIM(o.brand), ''), 'Sem marca')
    ORDER BY sewing_minutes DESC, brand ASC
  `).all(...companyWideParams);

  const filteredBrands = db.prepare(`
    SELECT
      COALESCE(NULLIF(TRIM(o.brand), ''), 'Sem marca') AS brand,
      COUNT(*) AS total_ops,
      ROUND(COALESCE(SUM(o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0))), 0), 2) AS sewing_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'verde' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS green_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'amarelo' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS yellow_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'azul' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS blue_minutes,
      ROUND(COALESCE(SUM(CASE WHEN o.status_color = 'vermelho' THEN o.total_pieces * (COALESCE(o.minutes_f21,0) + COALESCE(o.minutes_f22,0)) ELSE 0 END), 0), 2) AS red_minutes
    FROM ops o
    ${whereSql}
    GROUP BY COALESCE(NULLIF(TRIM(o.brand), ''), 'Sem marca')
    ORDER BY sewing_minutes DESC, brand ASC
  `).all(...filteredParams);

  const brands = filterByShipmentDate
    ? companyWideBrands.map(item => {
        const filteredMatch = filteredBrands.find(entry => entry.brand === item.brand);
        return {
          ...item,
          red_minutes: Number(filteredMatch?.red_minutes || 0)
        };
      })
    : filteredBrands;

  const cardSource = filterByShipmentDate ? companyWideSummary : filteredSummary;

  return {
    period,
    range: dailyRange,
    filters: { opType, brand, startDate: dailyRange.start, endDate: dailyRange.end },
    cards: {
      producedQuantity: productionTotals.produced_quantity || 0,
      producedMinutes: round2(productionTotals.produced_minutes || 0),
      totalOps: cardSource.total_ops || 0,
      totalSewingMinutes: round2(cardSource.total_sewing_minutes || 0),
      greenSewingMinutes: round2(cardSource.green_sewing_minutes || 0),
      yellowSewingMinutes: round2(cardSource.yellow_sewing_minutes || 0),
      blueSewingMinutes: round2(cardSource.blue_sewing_minutes || 0),
      pinkSewingMinutes: round2(cardSource.pink_sewing_minutes || 0),
      redSewingMinutes: round2(filteredSummary.red_sewing_minutes || 0)
    },
    employees,
    opRows,
    pinkOpRows,
    brands,
    efficiencyCutoff,
    status: {
      ...cardSource,
      pink_sewing_minutes: cardSource.pink_sewing_minutes || 0,
      pink_ops: cardSource.pink_ops || 0,
      red_sewing_minutes: filteredSummary.red_sewing_minutes || 0,
      red_ops: filteredSummary.red_ops || 0
    }
  };
}


function getEmployeeDailyResultRows(rangeStart, rangeEnd, employeeId = '') {
  const employees = db.prepare(`
    SELECT id, registration_code, full_name, start_date, termination_date, is_active
    FROM employees
    ORDER BY full_name ASC
  `).all();
  const selectedId = Number(employeeId || 0);
  const filteredEmployees = selectedId ? employees.filter(employee => employee.id === selectedId) : employees;
  const productionRows = db.prepare(`
    SELECT p.employee_id, p.production_date, ROUND(SUM(p.produced_minutes), 3) AS produced_minutes, SUM(p.produced_quantity) AS produced_quantity
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    WHERE ${COUNTED_PRODUCTION_WHERE}
      AND p.production_date BETWEEN ? AND ?
    GROUP BY p.employee_id, p.production_date
  `).all(rangeStart, rangeEnd);
  const productionMap = new Map(productionRows.map(row => [`${row.employee_id}:${row.production_date}`, row]));
  const rows = [];
  for (const employee of filteredEmployees) {
    const businessDays = getEmployeeBaseDays(employee, rangeStart, rangeEnd);
    for (const day of businessDays) {
      const item = productionMap.get(`${employee.id}:${day}`);
      const producedMinutes = Number(item?.produced_minutes || 0);
      rows.push({
        employee_id: employee.id,
        registration_code: employee.registration_code,
        full_name: employee.full_name,
        production_date: day,
        produced_quantity: Number(item?.produced_quantity || 0),
        produced_minutes: producedMinutes,
        available_minutes: baseMinutesDay(),
        result_percent: round2((producedMinutes / baseMinutesDay()) * 100)
      });
    }
  }
  return rows.sort((a, b) => `${a.production_date}-${a.full_name}`.localeCompare(`${b.production_date}-${b.full_name}`));
}

function getPeriodRange(period, refDate) {
  const date = new Date(`${refDate}T00:00:00Z`);
  if (period === 'week') {
    const day = date.getUTCDay() || 7;
    const start = new Date(date);
    start.setUTCDate(date.getUTCDate() - day + 1);
    const end = new Date(start);
    end.setUTCDate(start.getUTCDate() + 6);
    return { label: 'Semana', start: iso(start), end: iso(end) };
  }
  if (period === 'month') {
    const y = date.getUTCFullYear();
    const m = date.getUTCMonth();
    const d = date.getUTCDate();
    let start;
    let end;
    const startDay = periodStartDay();
    if (d >= startDay) {
      start = new Date(Date.UTC(y, m, startDay));
      end = new Date(Date.UTC(y, m + 1, startDay - 1));
    } else {
      start = new Date(Date.UTC(y, m - 1, startDay));
      end = new Date(Date.UTC(y, m, startDay - 1));
    }
    return { label: 'Mês operacional', start: iso(start), end: iso(end) };
  }
  if (period === 'general') {
    const bounds = db.prepare(`
      SELECT MIN(ref_date) AS start_date, MAX(ref_date) AS end_date
      FROM (
        SELECT MIN(entry_date) AS ref_date FROM ops WHERE is_reversed = 0
        UNION ALL
        SELECT MIN(production_date) AS ref_date FROM op_daily_productions WHERE is_reversed = 0
        UNION ALL
        SELECT MIN(work_date) AS ref_date FROM employee_daily_closures
        UNION ALL
        SELECT MIN(absence_date) AS ref_date FROM employee_absences
        UNION ALL
        SELECT MAX(entry_date) AS ref_date FROM ops WHERE is_reversed = 0
        UNION ALL
        SELECT MAX(production_date) AS ref_date FROM op_daily_productions WHERE is_reversed = 0
        UNION ALL
        SELECT MAX(work_date) AS ref_date FROM employee_daily_closures
        UNION ALL
        SELECT MAX(absence_date) AS ref_date FROM employee_absences
      ) refs
      WHERE ref_date IS NOT NULL
    `).get() || {};
    const start = bounds.start_date || refDate;
    const end = bounds.end_date || refDate;
    return { label: 'Geral', start, end };
  }
  return { label: 'Dia', start: refDate, end: refDate };
}

function getClosureReportRange(period = 'month', baseDate = today(), startDate = '', endDate = '') {
  if (period === 'custom' && startDate && endDate) {
    return {
      label: 'Período personalizado',
      start: startDate <= endDate ? startDate : endDate,
      end: startDate <= endDate ? endDate : startDate
    };
  }
  if (period === 'general') return getPeriodRange('general', baseDate);
  if (period === 'week') return getPeriodRange('week', baseDate);
  if (period === 'day') return getPeriodRange('day', baseDate);
  return getPeriodRange('month', baseDate);
}

function iso(date) {
  return date.toISOString().slice(0, 10);
}

function parseIsoDate(value) {
  if (!value) return null;
  return new Date(`${value}T00:00:00Z`);
}

function getEmployeeActiveDaysInRange(employee, rangeStart, rangeEnd) {
  const start = parseIsoDate(rangeStart);
  const end = parseIsoDate(rangeEnd);
  const employeeStart = parseIsoDate(employee.start_date) || start;
  const employeeEnd = parseIsoDate(employee.termination_date) || end;

  const effectiveStart = employeeStart > start ? employeeStart : start;
  const effectiveEnd = employeeEnd < end ? employeeEnd : end;

  if (effectiveStart > effectiveEnd) return 0;
  const diffDays = Math.round((effectiveEnd - effectiveStart) / 86400000) + 1;
  return diffDays > 0 ? diffDays : 0;
}

function formatDateInput(value) {
  return value ? escapeHtml(value) : '';
}


// T0.7 — formatação pt-BR única para a interface
const NUMBER_FORMATTERS = new Map();
function fmtNum(value, decimals = 2) {
  if (!NUMBER_FORMATTERS.has(decimals)) {
    NUMBER_FORMATTERS.set(decimals, new Intl.NumberFormat('pt-BR', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }));
  }
  const n = Number(value);
  return NUMBER_FORMATTERS.get(decimals).format(Number.isFinite(n) ? n : 0);
}

const MONEY_FORMATTER = new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' });
function fmtMoney(value) {
  const n = Number(value);
  return MONEY_FORMATTER.format(Number.isFinite(n) ? n : 0);
}

function formatDatePtBr(value) {
  if (!value) return '-';
  const [year, month, day] = String(value).split('-');
  if (!year || !month || !day) return escapeHtml(value);
  return `${day}/${month}/${year}`;
}

function round2(value) {
  return Math.round((Number(value || 0) + Number.EPSILON) * 100) / 100;
}

function formatMoneyBr(value) {
  return round2(value).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

function parseOpNumbersInput(value) {
  return Array.from(new Set(String(value || '')
    .split(/[\n,;]+/)
    .map(item => item.trim())
    .filter(Boolean)));
}

function getCellClosureList() {
  return db.prepare(`
    SELECT
      cc.*,
      c.name AS cell_name
    FROM cell_closures cc
    JOIN sewing_cells c ON c.id = cc.cell_id
    ORDER BY cc.created_at DESC, cc.id DESC
  `).all().map(item => ({
    ...item,
    total_ops: Number(item.total_ops || 0),
    total_pieces: Number(item.total_pieces || 0),
    total_minutes: Number(item.total_minutes || 0),
    total_received_amount: Number(item.total_received_amount || 0),
    total_paid_amount: Number(item.total_paid_amount || 0),
    total_profit_amount: Number(item.total_profit_amount || 0)
  }));
}

function getCellClosureById(id) {
  const closure = db.prepare(`
    SELECT
      cc.*,
      c.name AS cell_name
    FROM cell_closures cc
    JOIN sewing_cells c ON c.id = cc.cell_id
    WHERE cc.id = ?
    LIMIT 1
  `).get(Number(id));
  if (!closure) return null;
  const items = db.prepare(`
    SELECT *
    FROM cell_closure_items
    WHERE closure_id = ?
    ORDER BY op_number COLLATE NOCASE, id
  `).all(Number(id)).map(item => ({
    ...item,
    total_pieces: Number(item.total_pieces || 0),
    minutes_per_piece: Number(item.minutes_per_piece || 0),
    total_minutes: Number(item.total_minutes || 0),
    supplier_rate_per_minute: Number(item.supplier_rate_per_minute || 0),
    cell_rate_per_minute: Number(item.cell_rate_per_minute || 0),
    received_amount: Number(item.received_amount || 0),
    paid_amount: Number(item.paid_amount || 0),
    profit_amount: Number(item.profit_amount || 0)
  }));
  return {
    closure: {
      ...closure,
      total_ops: Number(closure.total_ops || 0),
      total_pieces: Number(closure.total_pieces || 0),
      total_minutes: Number(closure.total_minutes || 0),
      supplier_rate_per_minute: Number(closure.supplier_rate_per_minute || 0),
      cell_rate_per_minute: Number(closure.cell_rate_per_minute || 0),
      total_received_amount: Number(closure.total_received_amount || 0),
      total_paid_amount: Number(closure.total_paid_amount || 0),
      total_profit_amount: Number(closure.total_profit_amount || 0)
    },
    items
  };
}

function toArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

function parseRateInput(value, fallback = NaN) {
  const raw = String(value ?? '').trim();
  if (!raw) return fallback;
  return Number(raw.replace(',', '.'));
}

function parseCellClosureRateRows(form, opNumbers, defaultSupplierRate, defaultCellRate) {
  const rowOpNumbers = toArray(form.item_op_number).map(item => String(item || '').trim()).filter(Boolean);
  const supplierInputs = toArray(form.item_supplier_rate_per_minute);
  const cellInputs = toArray(form.item_cell_rate_per_minute);
  const hasRows = rowOpNumbers.length > 0;
  const rateMap = new Map();

  if (hasRows) {
    rowOpNumbers.forEach((opNumber, index) => {
      const supplierRate = parseRateInput(supplierInputs[index], defaultSupplierRate);
      const cellRate = parseRateInput(cellInputs[index], defaultCellRate);
      if (!Number.isFinite(supplierRate) || supplierRate < 0) throw new Error(`Informe um valor por minuto válido para o fornecedor na OP ${opNumber}.`);
      if (!Number.isFinite(cellRate) || cellRate < 0) throw new Error(`Informe um valor por minuto válido para a célula na OP ${opNumber}.`);
      rateMap.set(opNumber, { supplierRate, cellRate });
    });
  }

  return opNumbers.map(opNumber => {
    const row = rateMap.get(opNumber);
    if (row) return { op_number: opNumber, supplier_rate_per_minute: row.supplierRate, cell_rate_per_minute: row.cellRate };
    if (!Number.isFinite(defaultSupplierRate) || defaultSupplierRate < 0) throw new Error(`Informe um valor por minuto válido para o fornecedor na OP ${opNumber}.`);
    if (!Number.isFinite(defaultCellRate) || defaultCellRate < 0) throw new Error(`Informe um valor por minuto válido para a célula na OP ${opNumber}.`);
    return { op_number: opNumber, supplier_rate_per_minute: defaultSupplierRate, cell_rate_per_minute: defaultCellRate };
  });
}

function buildCellClosureItems(itemRates) {
  const items = [];
  for (const row of itemRates) {
    const opNumber = String(row.op_number || '').trim();
    const supplierRate = Number(row.supplier_rate_per_minute || 0);
    const cellRate = Number(row.cell_rate_per_minute || 0);
    const op = getOpByNumber(opNumber);
    if (!op) throw new Error(`OP não encontrada: ${opNumber}`);
    const totalPieces = Number(op.total_pieces || 0);
    const minutesPerPiece = Number(op.minutes_f21 || 0);
    const totalMinutes = round2(totalPieces * minutesPerPiece);
    const receivedAmount = round2(totalMinutes * supplierRate);
    const paidAmount = round2(totalMinutes * cellRate);
    const profitAmount = round2(receivedAmount - paidAmount);
    items.push({
      op_id: Number(op.id),
      op_number: op.op_number,
      product_name: op.product_name,
      brand: op.brand || '',
      total_pieces: totalPieces,
      minutes_per_piece: minutesPerPiece,
      total_minutes: totalMinutes,
      supplier_rate_per_minute: supplierRate,
      cell_rate_per_minute: cellRate,
      received_amount: receivedAmount,
      paid_amount: paidAmount,
      profit_amount: profitAmount,
      active_cell_name: op.active_cell_name || ''
    });
  }
  return items;
}

function summarizeCellClosureRates(items, key) {
  const rates = Array.from(new Set(items.map(item => Number(item[key] || 0).toFixed(4))));
  if (!rates.length) return '-';
  if (rates.length === 1) return `${fmtNum(Number(rates[0]), 4)} por min.`;
  return `${fmtNum(Number(rates[0]), 4)} a ${fmtNum(Number(rates[rates.length - 1]), 4)} por min.`;
}

function validateCellClosureForm(form) {
  const title = String(form.title || '').trim();
  const startDate = String(form.start_date || '').trim();
  const endDate = String(form.end_date || '').trim();
  const cellId = Number(form.cell_id || 0);
  const supplierRate = parseRateInput(form.supplier_rate_per_minute, NaN);
  const cellRate = parseRateInput(form.cell_rate_per_minute, NaN);
  const notes = String(form.notes || '').trim();
  const opNumbers = parseOpNumbersInput(form.op_numbers);

  if (!title) throw new Error('Informe o título do fechamento.');
  if (!startDate || !endDate) throw new Error('Informe o período inicial e final.');
  if (startDate > endDate) throw new Error('O período inicial não pode ser maior que o final.');
  const cell = getCellById(cellId);
  if (!cell) throw new Error('Selecione uma célula válida.');
  if (!opNumbers.length) throw new Error('Informe pelo menos uma OP para o fechamento.');

  const itemRates = parseCellClosureRateRows(form, opNumbers, supplierRate, cellRate);
  const items = buildCellClosureItems(itemRates);
  const totals = items.reduce((acc, item) => {
    acc.total_ops += 1;
    acc.total_pieces += Number(item.total_pieces || 0);
    acc.total_minutes += Number(item.total_minutes || 0);
    acc.total_received_amount += Number(item.received_amount || 0);
    acc.total_paid_amount += Number(item.paid_amount || 0);
    acc.total_profit_amount += Number(item.profit_amount || 0);
    return acc;
  }, { total_ops: 0, total_pieces: 0, total_minutes: 0, total_received_amount: 0, total_paid_amount: 0, total_profit_amount: 0 });

  totals.total_minutes = round2(totals.total_minutes);
  totals.total_received_amount = round2(totals.total_received_amount);
  totals.total_paid_amount = round2(totals.total_paid_amount);
  totals.total_profit_amount = round2(totals.total_profit_amount);

  const headerSupplierRate = Number.isFinite(supplierRate) && supplierRate >= 0 ? supplierRate : Number(items[0]?.supplier_rate_per_minute || 0);
  const headerCellRate = Number.isFinite(cellRate) && cellRate >= 0 ? cellRate : Number(items[0]?.cell_rate_per_minute || 0);

  return { title, startDate, endDate, cell, supplierRate: headerSupplierRate, cellRate: headerCellRate, notes, opNumbers, items, totals };
}

function renderCellClosureForm(values = {}, previewItems = [], error = '') {
  const cells = getCellList();
  const hasPreview = previewItems.length > 0;
  const previewTotals = previewItems.reduce((acc, item) => {
    acc.total_ops += 1;
    acc.total_pieces += Number(item.total_pieces || 0);
    acc.total_minutes += Number(item.total_minutes || 0);
    acc.total_received_amount += Number(item.received_amount || 0);
    acc.total_paid_amount += Number(item.paid_amount || 0);
    acc.total_profit_amount += Number(item.profit_amount || 0);
    return acc;
  }, { total_ops: 0, total_pieces: 0, total_minutes: 0, total_received_amount: 0, total_paid_amount: 0, total_profit_amount: 0 });
  const defaultSupplierRate = escapeHtml(values.supplier_rate_per_minute || '');
  const defaultCellRate = escapeHtml(values.cell_rate_per_minute || '');
  const initialRowsJson = escapeHtml(JSON.stringify(previewItems.map(item => ({
    op_number: item.op_number,
    product_name: item.product_name,
    active_cell_name: item.active_cell_name || '',
    total_pieces: Number(item.total_pieces || 0),
    minutes_per_piece: Number(item.minutes_per_piece || 0),
    total_minutes: Number(item.total_minutes || 0),
    supplier_rate_per_minute: Number(item.supplier_rate_per_minute || 0),
    cell_rate_per_minute: Number(item.cell_rate_per_minute || 0),
    received_amount: Number(item.received_amount || 0),
    paid_amount: Number(item.paid_amount || 0),
    profit_amount: Number(item.profit_amount || 0)
  }))));

  return `
    <section class="panel">
      <div class="panel-header"><h3>Novo fechamento de células</h3><span class="hint">Múltiplas OPs no mesmo lançamento, com preço por minuto individual.</span></div>
      ${error ? `<div class="alert error">${escapeHtml(error)}</div>` : ''}
      <form class="form-grid" method="post" action="/cells/closures" id="cell-closure-form">
        <label>Título<input name="title" required value="${escapeHtml(values.title || '')}" placeholder="Ex.: Fechamento Célula A · Junho/2026" /></label>
        <label>Célula<select name="cell_id" required><option value="">Selecione</option>${cells.map(cell => `<option value="${cell.id}" ${String(values.cell_id || '') === String(cell.id) ? 'selected' : ''}>${escapeHtml(cell.name)}</option>`).join('')}</select></label>
        <label>Período inicial<input type="date" name="start_date" required value="${escapeHtml(values.start_date || '')}" /></label>
        <label>Período final<input type="date" name="end_date" required value="${escapeHtml(values.end_date || '')}" /></label>
        <label>Valor/min. fornecedor (padrão)<input type="number" step="0.0001" min="0" name="supplier_rate_per_minute" value="${defaultSupplierRate}" placeholder="0,0000" /></label>
        <label>Valor/min. célula (padrão)<input type="number" step="0.0001" min="0" name="cell_rate_per_minute" value="${defaultCellRate}" placeholder="0,0000" /></label>
        <label class="full">OPs do fechamento<textarea name="op_numbers" rows="5" required placeholder="Uma OP por linha ou separadas por vírgula">${escapeHtml(values.op_numbers || '')}</textarea></label>
        <label class="full">Observação<textarea name="notes" rows="3" placeholder="Opcional">${escapeHtml(values.notes || '')}</textarea></label>
        <div class="full">
          <div class="panel" style="margin:0">
            <div class="panel-header"><h3>Grade das OPs</h3><span class="hint">Ajuste o valor/min. de cada OP antes de salvar.</span></div>
            <div id="cell-closure-grid" data-initial-items="${initialRowsJson}"></div>
          </div>
        </div>
        <div class="full actions"><button class="btn" type="submit">Salvar fechamento</button></div>
      </form>
      <p class="hint">Cálculo por linha: minutos da OP = F21 × quantidade total da OP. Recebido = minutos × valor/min. do fornecedor. Pago = minutos × valor/min. da célula. Lucro = recebido - pago.</p>
    </section>
    ${hasPreview ? `
      <section class="panel">
        <div class="panel-header"><h3>Prévia dos itens que serão salvos</h3><span class="hint">${previewTotals.total_ops} OP(s)</span></div>
        <table><thead><tr><th>OP</th><th>Produto</th><th>Célula atual</th><th>Peças</th><th>Min/pç</th><th>Minutos</th><th>Fornecedor/min.</th><th>Célula/min.</th><th>Recebido</th><th>Pago</th><th>Lucro</th></tr></thead><tbody>
          ${previewItems.map(item => `<tr><td>${escapeHtml(item.op_number)}</td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(item.active_cell_name || '-')}</td><td>${item.total_pieces}</td><td>${fmtNum(Number(item.minutes_per_piece || 0), 3)}</td><td>${fmtNum(Number(item.total_minutes || 0), 2)}</td><td>${fmtNum(Number(item.supplier_rate_per_minute || 0), 4)}</td><td>${fmtNum(Number(item.cell_rate_per_minute || 0), 4)}</td><td>${escapeHtml(formatMoneyBr(item.received_amount))}</td><td>${escapeHtml(formatMoneyBr(item.paid_amount))}</td><td>${escapeHtml(formatMoneyBr(item.profit_amount))}</td></tr>`).join('')}
        </tbody><tfoot><tr><th colspan="3">Totais</th><th>${previewTotals.total_pieces}</th><th>-</th><th>${fmtNum(round2(previewTotals.total_minutes), 2)}</th><th>-</th><th>-</th><th>${escapeHtml(formatMoneyBr(previewTotals.total_received_amount))}</th><th>${escapeHtml(formatMoneyBr(previewTotals.total_paid_amount))}</th><th>${escapeHtml(formatMoneyBr(previewTotals.total_profit_amount))}</th></tr></tfoot></table>
      </section>
    ` : ''}
    <script>
      (() => {
        const form = document.getElementById('cell-closure-form');
        const mount = document.getElementById('cell-closure-grid');
        if (!form || !mount) return;
        const opInput = form.querySelector('textarea[name="op_numbers"]');
        const defaultSupplierInput = form.querySelector('input[name="supplier_rate_per_minute"]');
        const defaultCellInput = form.querySelector('input[name="cell_rate_per_minute"]');
        const initialItems = (() => {
          try { return JSON.parse(mount.dataset.initialItems || '[]'); } catch (_error) { return []; }
        })();
        const initialMap = new Map(initialItems.map(item => [String(item.op_number || '').trim(), item]));
        const previewCache = new Map(initialItems.map(item => [String(item.op_number || '').trim(), item]));
        const loadingOps = new Set();
        const parseOps = value => Array.from(new Set(String(value || '').split(/[\n,;]+/).map(item => item.trim()).filter(Boolean)));
        const parseRate = value => {
          const normalized = String(value ?? '').trim().replace(',', '.');
          if (!normalized) return NaN;
          const number = Number(normalized);
          return Number.isFinite(number) ? number : NaN;
        };
        const formatMoney = value => Number(value || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
        const numberOrZero = value => Number.isFinite(value) ? value : 0;

        const render = () => {
          const currentValues = new Map(Array.from(mount.querySelectorAll('tbody tr')).map(tr => {
            const op = tr.querySelector('input[name="item_op_number"]')?.value || '';
            const supplier = tr.querySelector('input[name="item_supplier_rate_per_minute"]')?.value || '';
            const cell = tr.querySelector('input[name="item_cell_rate_per_minute"]')?.value || '';
            return [op, { supplier_rate_per_minute: supplier, cell_rate_per_minute: cell }];
          }));
          const ops = parseOps(opInput.value);
          const defaultSupplier = parseRate(defaultSupplierInput.value);
          const defaultCell = parseRate(defaultCellInput.value);
          if (!ops.length) {
            mount.innerHTML = '<p class="hint">Informe as OPs acima para montar a grade de fechamento.</p>';
            return;
          }
          const rows = ops.map(op => {
            const preview = previewCache.get(op) || initialMap.get(op) || {};
            const current = currentValues.get(op) || {};
            const supplier = Number.isFinite(parseRate(current.supplier_rate_per_minute))
              ? parseRate(current.supplier_rate_per_minute)
              : (Number.isFinite(parseRate(preview.supplier_rate_per_minute)) ? parseRate(preview.supplier_rate_per_minute) : defaultSupplier);
            const cell = Number.isFinite(parseRate(current.cell_rate_per_minute))
              ? parseRate(current.cell_rate_per_minute)
              : (Number.isFinite(parseRate(preview.cell_rate_per_minute)) ? parseRate(preview.cell_rate_per_minute) : defaultCell);
            const totalMinutes = numberOrZero(Number(preview.total_minutes || 0));
            const received = totalMinutes * numberOrZero(supplier);
            const paid = totalMinutes * numberOrZero(cell);
            const profit = received - paid;
            return [
              '<tr>',
              '<td>',
              op,
              '<input type="hidden" name="item_op_number" value="' + op.replace(/"/g, '&quot;') + '" />',
              '</td>',
              '<td>' + (preview.product_name || '-') + '</td>',
              '<td>' + (preview.active_cell_name || '-') + '</td>',
              '<td>' + Number(preview.total_pieces || 0) + '</td>',
              '<td>' + Number(preview.minutes_per_piece || preview.minutes_f21 || 0).toFixed(3) + '</td>',
              '<td>' + totalMinutes.toFixed(2) + '</td>',
              '<td><input type="number" step="0.0001" min="0" name="item_supplier_rate_per_minute" value="' + (Number.isFinite(supplier) ? supplier.toFixed(4) : '') + '" placeholder="0,0000" /></td>',
              '<td><input type="number" step="0.0001" min="0" name="item_cell_rate_per_minute" value="' + (Number.isFinite(cell) ? cell.toFixed(4) : '') + '" placeholder="0,0000" /></td>',
              '<td>' + formatMoney(received) + '</td>',
              '<td>' + formatMoney(paid) + '</td>',
              '<td>' + formatMoney(profit) + '</td>',
              '</tr>'
            ].join('');
          }).join('');
          mount.innerHTML = '<table><thead><tr><th>OP</th><th>Produto</th><th>Célula atual</th><th>Peças</th><th>Min/pç</th><th>Minutos</th><th>Fornecedor/min.</th><th>Célula/min.</th><th>Recebido</th><th>Pago</th><th>Lucro</th></tr></thead><tbody>' + rows + '</tbody></table>';
          ops.forEach(async op => {
            if (previewCache.has(op) || loadingOps.has(op)) return;
            loadingOps.add(op);
            try {
              const response = await fetch('/api/op-preview?op_number=' + encodeURIComponent(op), { headers: { Accept: 'application/json' } });
              const data = await response.json().catch(() => null);
              if (response.ok && data?.found) {
                previewCache.set(op, {
                  ...data,
                  minutes_per_piece: Number(data.minutes_f21 || 0),
                  total_minutes: Number(data.total_pieces || 0) * Number(data.minutes_f21 || 0)
                });
                render();
              }
            } catch (_error) {
            } finally {
              loadingOps.delete(op);
            }
          });
        };

        const triggerRender = () => setTimeout(render, 0);
        opInput.addEventListener('input', triggerRender);
        opInput.addEventListener('change', triggerRender);
        opInput.addEventListener('blur', triggerRender);
        defaultSupplierInput.addEventListener('input', triggerRender);
        defaultCellInput.addEventListener('input', triggerRender);
        mount.addEventListener('input', event => {
          if (event.target?.name === 'item_supplier_rate_per_minute' || event.target?.name === 'item_cell_rate_per_minute') render();
        });
        if (opInput.value && opInput.value.trim()) {
          triggerRender();
        } else {
          render();
        }
      })();
    </script>
  `;
}

function renderCellClosuresPage(query = {}, values = {}, error = '', role = 'adm') {
  const list = getCellClosureList();
  const previewItems = String(values.op_numbers || '').trim() ? (() => {
    try {
      return validateCellClosureForm(values).items;
    } catch (_error) {
      return [];
    }
  })() : [];

  const content = `
    <section class="page-header">
      <div><h2>Fechamento de células</h2><p>Cadastro de fechamento com várias OPs no mesmo lançamento e cálculo financeiro individual por OP.</p></div>
    </section>

    <div class="two-columns">
      <div>${renderCellClosureForm(values, previewItems, error)}</div>
      <section class="panel">
        <div class="panel-header"><h3>Fechamentos salvos</h3><span class="hint">${list.length} registro(s)</span></div>
        <table><thead><tr><th>Título</th><th>Período</th><th>Célula</th><th>OPs</th><th>Lucro</th><th></th></tr></thead><tbody>
          ${list.map(item => `<tr><td>${escapeHtml(item.title)}</td><td>${formatDatePtBr(item.start_date)} até ${formatDatePtBr(item.end_date)}</td><td>${escapeHtml(item.cell_name)}</td><td>${item.total_ops}</td><td>${escapeHtml(formatMoneyBr(item.total_profit_amount))}</td><td><a class="btn secondary" href="/cells/closures/${item.id}">Abrir</a></td></tr>`).join('') || '<tr><td colspan="6">Nenhum fechamento salvo ainda.</td></tr>'}
        </tbody></table>
      </section>
    </div>
  `;

  return pageLayout({ title: 'Fechamento de células', content, notice: query.notice || '', error: query.error || '', role });
}

function renderCellClosureDetailPage(id, query = {}, role = 'adm') {
  const data = getCellClosureById(id);
  if (!data) return pageLayout({ title: 'Fechamento de células', content: '<section class="panel"><p>Fechamento não encontrado.</p></section>', error: 'Fechamento não encontrado.', role });
  const { closure, items } = data;
  const content = `
    <section class="page-header">
      <div><h2>Fechamento de células · ${escapeHtml(closure.title)}</h2><p>${formatDatePtBr(closure.start_date)} até ${formatDatePtBr(closure.end_date)} · ${escapeHtml(closure.cell_name)}</p></div>
      <div class="top-meta"><a class="btn secondary" href="/cells/closures">Voltar</a></div>
    </section>

    <div class="cards">
      <article class="card"><span>OPs</span><strong>${closure.total_ops}</strong><small>${closure.total_pieces} peças</small></article>
      <article class="card"><span>Minutos</span><strong>${fmtNum(closure.total_minutes, 2)}</strong><small>F21 × quantidade total</small></article>
      <article class="card status-card bg-yellow"><span>Recebido</span><strong>${escapeHtml(formatMoneyBr(closure.total_received_amount))}</strong><small>${escapeHtml(summarizeCellClosureRates(items, 'supplier_rate_per_minute'))}</small></article>
      <article class="card status-card bg-blue"><span>Pago</span><strong>${escapeHtml(formatMoneyBr(closure.total_paid_amount))}</strong><small>${escapeHtml(summarizeCellClosureRates(items, 'cell_rate_per_minute'))}</small></article>
      <article class="card status-card bg-green"><span>Lucro</span><strong>${escapeHtml(formatMoneyBr(closure.total_profit_amount))}</strong><small>Observação salva no detalhe</small></article>
    </div>

    <section class="panel">
      <div class="panel-header"><h3>Dados do fechamento</h3><span class="hint">Criado em ${escapeHtml(nowPt(closure.created_at))}</span></div>
      <dl class="detail-grid">
        <div><dt>Título</dt><dd>${escapeHtml(closure.title)}</dd></div>
        <div><dt>Célula</dt><dd>${escapeHtml(closure.cell_name)}</dd></div>
        <div><dt>Período</dt><dd>${formatDatePtBr(closure.start_date)} até ${formatDatePtBr(closure.end_date)}</dd></div>
        <div><dt>Fornecedor/min.</dt><dd>${escapeHtml(summarizeCellClosureRates(items, 'supplier_rate_per_minute'))}</dd></div>
        <div><dt>Célula/min.</dt><dd>${escapeHtml(summarizeCellClosureRates(items, 'cell_rate_per_minute'))}</dd></div>
        <div><dt>Observação</dt><dd>${escapeHtml(closure.notes || '-')}</dd></div>
      </dl>
    </section>

    <section class="panel">
      <div class="panel-header"><h3>OPs do fechamento</h3><span class="hint">Cada linha guarda seu próprio preço por minuto</span></div>
      <table><thead><tr><th>OP</th><th>Produto</th><th>Marca</th><th>Peças</th><th>Min/pç</th><th>Minutos</th><th>Fornecedor/min.</th><th>Célula/min.</th><th>Recebido</th><th>Pago</th><th>Lucro</th></tr></thead><tbody>
        ${items.map(item => `<tr><td><a href="/ops/${item.op_id}">${escapeHtml(item.op_number)}</a></td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(item.brand || '-')}</td><td>${item.total_pieces}</td><td>${fmtNum(item.minutes_per_piece, 3)}</td><td>${fmtNum(item.total_minutes, 2)}</td><td>${fmtNum(item.supplier_rate_per_minute, 4)}</td><td>${fmtNum(item.cell_rate_per_minute, 4)}</td><td>${escapeHtml(formatMoneyBr(item.received_amount))}</td><td>${escapeHtml(formatMoneyBr(item.paid_amount))}</td><td>${escapeHtml(formatMoneyBr(item.profit_amount))}</td></tr>`).join('') || '<tr><td colspan="11">Nenhuma OP encontrada neste fechamento.</td></tr>'}
      </tbody></table>
    </section>
  `;
  return pageLayout({ title: 'Fechamento de células', content, notice: query.notice || '', error: query.error || '', role });
}

function handleCreateCellClosure(form, res, role) {
  if (!canAccessCadastros(role)) return requireAdmin(null, res, role);
  try {
    const payload = validateCellClosureForm(form);
    db.exec('BEGIN');
    const result = db.prepare(`
      INSERT INTO cell_closures (
        title, start_date, end_date, cell_id, supplier_rate_per_minute, cell_rate_per_minute, notes,
        total_ops, total_pieces, total_minutes, total_received_amount, total_paid_amount, total_profit_amount, created_by_user_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `).run(
      payload.title, payload.startDate, payload.endDate, payload.cell.id, payload.supplierRate, payload.cellRate, payload.notes || null,
      payload.totals.total_ops, payload.totals.total_pieces, payload.totals.total_minutes, payload.totals.total_received_amount, payload.totals.total_paid_amount, payload.totals.total_profit_amount
    );
    const closureId = Number(result.lastInsertRowid);
    const stmt = db.prepare(`
      INSERT INTO cell_closure_items (
        closure_id, op_id, op_number, product_name, brand, total_pieces, minutes_per_piece, total_minutes,
        supplier_rate_per_minute, cell_rate_per_minute, received_amount, paid_amount, profit_amount, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `);
    for (const item of payload.items) {
      stmt.run(closureId, item.op_id, item.op_number, item.product_name, item.brand || null, item.total_pieces, item.minutes_per_piece, item.total_minutes, item.supplier_rate_per_minute, item.cell_rate_per_minute, item.received_amount, item.paid_amount, item.profit_amount);
    }
    db.exec('COMMIT');
    return redirect(res, `/cells/closures/${closureId}?notice=${encodeURIComponent('Fechamento de células salvo com sucesso.')}`);
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch (_error) {}
    return sendHtml(res, renderCellClosuresPage({}, form, error.message, role), 422);
  }
}

function enumerateDates(start, end) {
  const dates = [];
  const cursor = parseIsoDate(start);
  const limit = parseIsoDate(end);
  if (!cursor || !limit) return dates;
  while (cursor <= limit) {
    dates.push(iso(cursor));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }
  return dates;
}

function isBusinessDay(dateValue) {
  const date = typeof dateValue === 'string' ? parseIsoDate(dateValue) : dateValue;
  if (!date) return false;
  const isoDate = typeof dateValue === 'string' ? dateValue : iso(date);
  const holidays = getHolidayDateSet();
  const day = date.getUTCDay();
  return workdaySet().has(day) && !holidays.has(isoDate);
}

function getPreviousBusinessDay(referenceDate) {
  const base = parseIsoDate(referenceDate) || parseIsoDate(today());
  if (!base) return today();
  const cursor = new Date(base);
  cursor.setUTCDate(cursor.getUTCDate() - 1);
  while (!isBusinessDay(cursor)) {
    cursor.setUTCDate(cursor.getUTCDate() - 1);
  }
  return iso(cursor);
}

function getEmployeeEffectiveRange(employee, rangeStart, rangeEnd) {
  const start = parseIsoDate(rangeStart);
  const end = parseIsoDate(rangeEnd);
  const employeeStart = parseIsoDate(employee.start_date) || start;
  const employeeEnd = parseIsoDate(employee.termination_date) || end;
  const effectiveStart = employeeStart > start ? employeeStart : start;
  const effectiveEnd = employeeEnd < end ? employeeEnd : end;
  if (effectiveStart > effectiveEnd) return null;
  return { start: iso(effectiveStart), end: iso(effectiveEnd) };
}

function getEmployeeBusinessDaysInRange(employee, rangeStart, rangeEnd) {
  const effective = getEmployeeEffectiveRange(employee, rangeStart, rangeEnd);
  if (!effective) return [];
  return enumerateDates(effective.start, effective.end).filter(isBusinessDay);
}

// ===================== REGRA OFICIAL DE EFICIÊNCIA (T0.3) =====================
// Usada por Dashboard, Acompanhamento diário, Fechamento e Prêmio. Não duplicar.
// Minutos que contam: lançamento ativo, marcado "conta para prêmio", em OP não estornada
// e industrializada, de qualquer tipo de OP, dentro do período ativo da colaboradora.
// Base: 528 min × dias úteis (seg–sex, sem feriado) do período ativo da colaboradora.
const COUNTED_PRODUCTION_WHERE = `
  p.is_reversed = 0
  AND COALESCE(p.counts_for_prize, 1) = 1
  AND COALESCE(o.is_reversed, 0) = 0
  AND COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')
`;

function getCountedProductionByEmployee(rangeStart, rangeEnd, employees) {
  const rows = db.prepare(`
    SELECT p.employee_id, p.production_date,
      SUM(p.produced_quantity) AS qty,
      SUM(p.normal_minutes) AS normal_minutes,
      SUM(p.extra_minutes) AS extra_minutes,
      SUM(p.produced_minutes) AS minutes
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    WHERE ${COUNTED_PRODUCTION_WHERE}
      AND p.production_date BETWEEN ? AND ?
    GROUP BY p.employee_id, p.production_date
  `).all(rangeStart, rangeEnd);
  const employeeById = new Map((employees || []).map(employee => [employee.id, employee]));
  const result = new Map();
  for (const row of rows) {
    const employee = employeeById.get(row.employee_id);
    if (employee) {
      const effective = getEmployeeEffectiveRange(employee, rangeStart, rangeEnd);
      if (!effective || row.production_date < effective.start || row.production_date > effective.end) continue;
    }
    const acc = result.get(row.employee_id) || { qty: 0, normal_minutes: 0, extra_minutes: 0, minutes: 0, last_production_date: '' };
    acc.qty += Number(row.qty || 0);
    acc.normal_minutes += Number(row.normal_minutes || 0);
    acc.extra_minutes += Number(row.extra_minutes || 0);
    acc.minutes += Number(row.minutes || 0);
    if (row.production_date > acc.last_production_date) acc.last_production_date = row.production_date;
    result.set(row.employee_id, acc);
  }
  for (const acc of result.values()) {
    acc.normal_minutes = round2(acc.normal_minutes);
    acc.extra_minutes = round2(acc.extra_minutes);
    acc.minutes = round2(acc.minutes);
  }
  return result;
}

// T1.5 — Ausências que tiram o dia da base de 528 min (decisão do dono, 26/10/2026).
// Falta e "outro" continuam na base. Configurável por empresa em app_settings.
const DEFAULT_BASE_EXCLUDED_ABSENCES = 'atestado,ferias,folga,afastamento';

function getBaseExcludedAbsenceTypes() {
  return new Set(String(getParams().absence_types_excluded_from_base || '')
    .split(',').map(item => item.trim()).filter(Boolean));
}

function getExcludedAbsenceDates(employeeId, rangeStart, rangeEnd) {
  const types = [...getBaseExcludedAbsenceTypes()];
  if (!types.length) return new Set();
  const rows = db.prepare(`
    SELECT absence_date FROM employee_absences
    WHERE employee_id = ? AND absence_date BETWEEN ? AND ? AND absence_type IN (${types.map(() => '?').join(',')})
  `).all(employeeId, rangeStart, rangeEnd, ...types);
  return new Set(rows.map(row => row.absence_date));
}

// Dias que entram na base: dias úteis do período ativo, menos ausências justificadas
function getEmployeeBaseDays(employee, rangeStart, rangeEnd) {
  if (rangeEnd < rangeStart) return [];
  const businessDays = getEmployeeBusinessDaysInRange(employee, rangeStart, rangeEnd);
  if (!businessDays.length) return businessDays;
  const excluded = getExcludedAbsenceDates(employee.id, rangeStart, rangeEnd);
  return excluded.size ? businessDays.filter(day => !excluded.has(day)) : businessDays;
}

// Eficiência de uma colaboradora. cutoff informado = "até o corte"; vazio = período cheio.
function calculateEmployeeEfficiency(employee, producedMinutes, rangeStart, rangeEnd, cutoff = '') {
  const end = cutoff && cutoff < rangeEnd ? cutoff : rangeEnd;
  const businessDays = end >= rangeStart ? getEmployeeBaseDays(employee, rangeStart, end) : [];
  const availableMinutes = round2(businessDays.length * baseMinutesDay());
  return {
    business_days: businessDays.length,
    available_minutes: availableMinutes,
    efficiency_percent: availableMinutes > 0 ? round2((Number(producedMinutes || 0) / availableMinutes) * 100) : 0
  };
}
// =============================================================================

function getClosureStatusLabel(item) {
  if (item.has_production) return 'Com lançamento';
  if (item.absence_type) return `Ausência: ${item.absence_type}`;
  if (item.closure_status_type) return 'Resolvido';
  return 'Pendente';
}

function getClosureStatusBadgeClass(item) {
  if (item.has_production || item.absence_type || item.closure_status_type) return 'ok';
  return 'pending';
}

function getClosureActionLabel(item) {
  if (item.absence_type) return 'Ausência lançada';
  if (item.closure_status_type) return 'Justificado';
  return 'Sem tratamento';
}

function getClosureResolvedTypeLabel(item) {
  if (item.absence_type) return `Ausência · ${item.absence_type}`;
  if (item.closure_status_type) return item.closure_status_type.replaceAll('_', ' ');
  return 'Sem tratamento';
}

function getMonthlyClosureData(baseDate = today(), period = 'month', employeeId = '', startDate = '', endDate = '') {
  const range = getClosureReportRange(period, baseDate, startDate, endDate);
  const employees = db.prepare(`
    SELECT id, registration_code, full_name, start_date, termination_date, is_active, notes
    FROM employees
    ORDER BY full_name ASC
  `).all();

  const employeeFilterId = Number(employeeId || 0);
  const filteredEmployees = employeeFilterId
    ? employees.filter(employee => employee.id === employeeFilterId)
    : employees;

  // Presença no dia considera qualquer lançamento; minutos consideram só o que conta (regra oficial)
  const productionRows = db.prepare(`
    SELECT p.employee_id, p.production_date, COUNT(*) AS launches,
      SUM(CASE WHEN ${COUNTED_PRODUCTION_WHERE} THEN p.produced_quantity ELSE 0 END) AS qty,
      ROUND(SUM(CASE WHEN ${COUNTED_PRODUCTION_WHERE} THEN p.normal_minutes ELSE 0 END), 2) AS normal_minutes,
      ROUND(SUM(CASE WHEN ${COUNTED_PRODUCTION_WHERE} THEN p.extra_minutes ELSE 0 END), 2) AS extra_minutes,
      ROUND(SUM(CASE WHEN ${COUNTED_PRODUCTION_WHERE} THEN p.produced_minutes ELSE 0 END), 2) AS minutes
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    WHERE p.is_reversed = 0 AND p.production_date BETWEEN ? AND ?
    GROUP BY p.employee_id, p.production_date
  `).all(range.start, range.end);
  const countedMap = getCountedProductionByEmployee(range.start, range.end, employees);
  const baseExcludedTypes = getBaseExcludedAbsenceTypes();

  const closureRows = db.prepare(`
    SELECT employee_id, work_date, status_type, justification, notes, updated_at
    FROM employee_daily_closures
    WHERE work_date BETWEEN ? AND ?
  `).all(range.start, range.end);

  const absenceRows = db.prepare(`
    SELECT employee_id, absence_date, absence_type, justification, notes, updated_at
    FROM employee_absences
    WHERE absence_date BETWEEN ? AND ?
  `).all(range.start, range.end);

  const productionMap = new Map(productionRows.map(row => [`${row.employee_id}:${row.production_date}`, row]));
  const closureMap = new Map(closureRows.map(row => [`${row.employee_id}:${row.work_date}`, row]));
  const absenceMap = new Map(absenceRows.map(row => [`${row.employee_id}:${row.absence_date}`, row]));

  const employeeSummaries = [];
  const pendingItems = [];
  const resolvedItems = [];
  const dailyMap = new Map();
  const rankingRows = [];

  for (const employee of filteredEmployees) {
    const businessDays = getEmployeeBusinessDaysInRange(employee, range.start, range.end);
    if (!businessDays.length) continue;

    let withProduction = 0;
    let pending = 0;
    let resolved = 0;
    let absenceDays = 0;
    let justifiedDays = 0;
    let producedQuantity = 0;
    let producedNormalMinutes = 0;
    let producedExtraMinutes = 0;
    let producedMinutes = 0;

    for (const day of businessDays) {
      const key = `${employee.id}:${day}`;
      const production = productionMap.get(key);
      const closure = closureMap.get(key);
      const absence = absenceMap.get(key);
      const item = {
        employee_id: employee.id,
        registration_code: employee.registration_code,
        full_name: employee.full_name,
        work_date: day,
        has_production: Boolean(production),
        production_count: Number(production?.launches || 0),
        produced_quantity: Number(production?.qty || 0),
        normal_minutes: Number(production?.normal_minutes || 0),
        extra_minutes: Number(production?.extra_minutes || 0),
        produced_minutes: Number(production?.minutes || 0),
        closure_status_type: closure?.status_type || '',
        closure_justification: closure?.justification || '',
        closure_notes: closure?.notes || '',
        absence_type: absence?.absence_type || '',
        absence_justification: absence?.justification || '',
        absence_notes: absence?.notes || ''
      };

      if (!dailyMap.has(day)) {
        dailyMap.set(day, {
          work_date: day,
          employees_active: 0,
          with_production: 0,
          pending: 0,
          resolved: 0,
          absences: 0,
          base_excluded: 0,
          produced_quantity: 0,
          normal_minutes: 0,
          extra_minutes: 0,
          produced_minutes: 0
        });
      }
      const daily = dailyMap.get(day);
      daily.employees_active += 1;
      if (item.absence_type && baseExcludedTypes.has(item.absence_type)) daily.base_excluded += 1;
      daily.produced_quantity += item.produced_quantity;
      daily.normal_minutes = round2(daily.normal_minutes + item.normal_minutes);
      daily.extra_minutes = round2(daily.extra_minutes + item.extra_minutes);
      daily.produced_minutes = round2(daily.produced_minutes + item.produced_minutes);

      producedQuantity += item.produced_quantity;
      producedNormalMinutes = round2(producedNormalMinutes + item.normal_minutes);
      producedExtraMinutes = round2(producedExtraMinutes + item.extra_minutes);
      producedMinutes = round2(producedMinutes + item.produced_minutes);

      if (item.has_production) {
        withProduction += 1;
        daily.with_production += 1;
      } else if (item.absence_type || item.closure_status_type) {
        resolved += 1;
        daily.resolved += 1;
        if (item.absence_type) {
          absenceDays += 1;
          daily.absences += 1;
        } else {
          justifiedDays += 1;
        }
        resolvedItems.push(item);
      } else {
        pending += 1;
        daily.pending += 1;
        pendingItems.push(item);
      }
    }

    // Totais da colaboradora pela regra oficial (inclui sábado/feriado marcado "conta para prêmio")
    const counted = countedMap.get(employee.id);
    producedQuantity = Number(counted?.qty || 0);
    producedNormalMinutes = round2(counted?.normal_minutes || 0);
    producedExtraMinutes = round2(counted?.extra_minutes || 0);
    producedMinutes = round2(counted?.minutes || 0);
    const { available_minutes: availableMinutes, efficiency_percent: efficiencyPercent } =
      calculateEmployeeEfficiency(employee, producedMinutes, range.start, range.end);

    const summary = {
      ...employee,
      business_days: businessDays.length,
      with_production: withProduction,
      pending_days: pending,
      resolved_days: resolved,
      justified_days: justifiedDays,
      absence_days: absenceDays,
      produced_quantity: producedQuantity,
      normal_minutes: producedNormalMinutes,
      extra_minutes: producedExtraMinutes,
      produced_minutes: producedMinutes,
      available_minutes: availableMinutes,
      efficiency_percent: efficiencyPercent,
      effective_range: getEmployeeEffectiveRange(employee, range.start, range.end)
    };

    employeeSummaries.push(summary);
    rankingRows.push(summary);
  }

  employeeSummaries.sort((a, b) => {
    if (b.pending_days !== a.pending_days) return b.pending_days - a.pending_days;
    if (b.produced_minutes !== a.produced_minutes) return b.produced_minutes - a.produced_minutes;
    return String(a.full_name).localeCompare(String(b.full_name));
  });

  rankingRows.sort((a, b) => {
    if (b.efficiency_percent !== a.efficiency_percent) return b.efficiency_percent - a.efficiency_percent;
    return String(a.full_name).localeCompare(String(b.full_name));
  });

  resolvedItems.sort((a, b) => `${a.work_date}-${a.full_name}`.localeCompare(`${b.work_date}-${b.full_name}`));
  pendingItems.sort((a, b) => `${a.work_date}-${a.full_name}`.localeCompare(`${b.work_date}-${b.full_name}`));

  const dailyRows = Array.from(dailyMap.values()).sort((a, b) => a.work_date.localeCompare(b.work_date)).map(item => {
    const availableMinutes = round2(Math.max(item.employees_active - item.base_excluded, 0) * baseMinutesDay());
    return {
      ...item,
      available_minutes: availableMinutes,
      efficiency_percent: availableMinutes > 0 ? round2((item.produced_minutes / availableMinutes) * 100) : 0
    };
  });

  const totals = employeeSummaries.reduce((acc, item) => {
    acc.employees += 1;
    acc.businessDays += Number(item.business_days || 0);
    acc.withProduction += Number(item.with_production || 0);
    acc.pending += Number(item.pending_days || 0);
    acc.resolved += Number(item.resolved_days || 0);
    acc.absences += Number(item.absence_days || 0);
    acc.justified += Number(item.justified_days || 0);
    acc.producedQuantity += Number(item.produced_quantity || 0);
    acc.normalMinutes = round2(acc.normalMinutes + Number(item.normal_minutes || 0));
    acc.extraMinutes = round2(acc.extraMinutes + Number(item.extra_minutes || 0));
    acc.producedMinutes = round2(acc.producedMinutes + Number(item.produced_minutes || 0));
    acc.availableMinutes = round2(acc.availableMinutes + Number(item.available_minutes || 0));
    return acc;
  }, {
    employees: 0,
    businessDays: 0,
    withProduction: 0,
    pending: 0,
    resolved: 0,
    absences: 0,
    justified: 0,
    producedQuantity: 0,
    normalMinutes: 0,
    extraMinutes: 0,
    producedMinutes: 0,
    availableMinutes: 0
  });
  totals.efficiencyPercent = totals.availableMinutes > 0 ? round2((totals.producedMinutes / totals.availableMinutes) * 100) : 0;

  return {
    range,
    filters: {
      base_date: baseDate,
      period,
      employee_id: employeeFilterId ? String(employeeFilterId) : '',
      start_date: startDate || '',
      end_date: endDate || ''
    },
    employeeOptions: employees,
    selectedEmployee: employeeFilterId ? employees.find(employee => employee.id === employeeFilterId) || null : null,
    employeeSummaries,
    pendingItems,
    resolvedItems,
    dailyRows,
    rankingRows,
    totals
  };
}

function getClosureQueryString(filters = {}) {
  const params = new URLSearchParams();
  if (filters.base_date) params.set('base_date', filters.base_date);
  if (filters.period && filters.period !== 'month') params.set('period', filters.period);
  if (filters.employee_id) params.set('employee_id', filters.employee_id);
  if (filters.start_date) params.set('start_date', filters.start_date);
  if (filters.end_date) params.set('end_date', filters.end_date);
  const query = params.toString();
  return query ? `?${query}` : '';
}

function renderClosureFilters(data) {
  const filters = data.filters;
  return `
    <section class="panel">
      <form class="inline-form" method="get" action="/closures">
        <label>Relatório / visão
          <select name="period" onchange="this.form.submit()">
            <option value="day" ${filters.period === 'day' ? 'selected' : ''}>Diário</option>
            <option value="week" ${filters.period === 'week' ? 'selected' : ''}>Semanal</option>
            <option value="month" ${filters.period === 'month' ? 'selected' : ''}>Mensal operacional</option>
            <option value="general" ${filters.period === 'general' ? 'selected' : ''}>Geral</option>
            <option value="custom" ${filters.period === 'custom' ? 'selected' : ''}>Personalizado</option>
          </select>
        </label>
        <label>Data base
          <input type="date" name="base_date" value="${escapeHtml(filters.base_date)}" />
        </label>
        <label>Colaborador
          <select name="employee_id">
            <option value="">Todos</option>
            ${data.employeeOptions.map(employee => `<option value="${employee.id}" ${String(filters.employee_id) === String(employee.id) ? 'selected' : ''}>${escapeHtml(employee.registration_code)} · ${escapeHtml(employee.full_name)}</option>`).join('')}
          </select>
        </label>
        <label>Início personalizado
          <input type="date" name="start_date" value="${escapeHtml(filters.start_date)}" />
        </label>
        <label>Fim personalizado
          <input type="date" name="end_date" value="${escapeHtml(filters.end_date)}" />
        </label>
        <button class="btn" type="submit">Atualizar</button>
        <a class="btn secondary" href="/closures/export${getClosureQueryString(filters)}" target="_blank" rel="noopener">Abrir versão para impressão / PDF</a>
      </form>
      <p class="hint"><strong>Período analisado:</strong> ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)} · <strong>modo:</strong> ${escapeHtml(data.range.label)}${data.selectedEmployee ? ` · <strong>colaborador:</strong> ${escapeHtml(data.selectedEmployee.full_name)}` : ''}.</p>
      <p class="subtle-note">Fechamento considera dias úteis de segunda a sexta. O link de impressão já deixa a visualização preparada para salvar como PDF no navegador.</p>
    </section>
  `;
}

function renderClosureCards(data) {
  return `
    <div class="cards closure-cards">
      <article class="card"><span>Colaboradores no período</span><strong>${data.totals.employees}</strong><small>Ativos dentro do intervalo filtrado</small></article>
      <article class="card"><span>Dias úteis monitorados</span><strong>${data.totals.businessDays}</strong><small>Soma por colaborador</small></article>
      <article class="card"><span>Dias pendentes</span><strong>${data.totals.pending}</strong><small>Sem lançamento e sem tratamento</small></article>
      <article class="card"><span>Dias resolvidos</span><strong>${data.totals.resolved}</strong><small>Justificados ou como ausência</small></article>
      <article class="card"><span>Ausências no período</span><strong>${data.totals.absences}</strong><small>Faltas, atestados, férias etc.</small></article>
      <article class="card"><span>Peças lançadas</span><strong>${data.totals.producedQuantity}</strong><small>Total produzido no período</small></article>
      <article class="card"><span>Min. normais</span><strong>${fmtNum(data.totals.normalMinutes, 2)}</strong><small>Base sem tempo extra</small></article>
      <article class="card"><span>Min. extras</span><strong>${fmtNum(data.totals.extraMinutes, 2)}</strong><small>Tempo extra aplicado no período</small></article>
      <article class="card"><span>Minutos produzidos</span><strong>${fmtNum(data.totals.producedMinutes, 2)}</strong><small>Total de costura lançada</small></article>
      <article class="card"><span>Eficiência do período cheio</span><strong>${fmtNum(data.totals.efficiencyPercent, 2)}%</strong><small>Minutos que contam para prêmio ÷ base do período inteiro</small></article>
    </div>
  `;
}

function getProductionPrizeTier(efficiencyPercent) {
  const tiers = [3, 2, 1].map(i => ({ pct: numParam(`prize_tier${i}_percent`), value: numParam(`prize_tier${i}_value`) }))
    .filter(t => t.pct > 0).sort((a, b) => b.pct - a.pct);
  for (const tier of tiers) if (efficiencyPercent >= tier.pct) return tier.value;
  return 0;
}

function getProductionPrizeQueryString(filters = {}) {
  const params = new URLSearchParams();
  if (filters.base_date) params.set('base_date', filters.base_date);
  if (filters.period && filters.period !== 'month') params.set('period', filters.period);
  if (filters.employee_id) params.set('employee_id', filters.employee_id);
  if (filters.start_date) params.set('start_date', filters.start_date);
  if (filters.end_date) params.set('end_date', filters.end_date);
  const query = params.toString();
  return query ? `?${query}` : '';
}

function getDailyTrackingQueryString(filters = {}) {
  const params = new URLSearchParams();
  if (filters.base_date) params.set('base_date', filters.base_date);
  if (filters.period && filters.period !== 'month') params.set('period', filters.period);
  if (filters.employee_id) params.set('employee_id', filters.employee_id);
  if (filters.start_date) params.set('start_date', filters.start_date);
  if (filters.end_date) params.set('end_date', filters.end_date);
  const query = params.toString();
  return query ? `?${query}` : '';
}

function getDailyTrackingStatusMeta(percent = 0, target = targetPercent()) {
  if (percent >= target) return { key: 'hit', label: `Acima de ${fmtPct(target)}%`, badgeClass: 'status-pill ok', rowClass: 'tracking-row-hit', cardClass: 'tracking-status-good', textClass: 'perf-high' };
  return { key: 'below', label: `Abaixo de ${fmtPct(target)}%`, badgeClass: 'status-pill pending', rowClass: 'tracking-row-below', cardClass: 'tracking-status-risk', textClass: 'perf-low' };
}

function getDailyTrackingData(baseDate = today(), period = 'month', employeeId = '', startDate = '', endDate = '') {
  const range = getClosureReportRange(period, baseDate, startDate, endDate);
  const cutoffReference = baseDate || today();
  const previousBusinessDay = getPreviousBusinessDay(cutoffReference);
  const progressEnd = range.end < previousBusinessDay ? range.end : previousBusinessDay;
  const employees = db.prepare(`
    SELECT id, registration_code, full_name, start_date, termination_date, is_active
    FROM employees
    ORDER BY full_name ASC
  `).all();

  const employeeFilterId = Number(employeeId || 0);
  const filteredEmployees = employeeFilterId
    ? employees.filter(employee => employee.id === employeeFilterId)
    : employees;

  const accumulatedMap = progressEnd >= range.start
    ? getCountedProductionByEmployee(range.start, progressEnd, employees)
    : new Map();

  const employeeSummaries = [];
  for (const employee of filteredEmployees) {
    const businessDaysTotal = getEmployeeBusinessDaysInRange(employee, range.start, range.end);
    if (!businessDaysTotal.length) continue;

    const businessDaysElapsed = progressEnd >= range.start
      ? getEmployeeBusinessDaysInRange(employee, range.start, progressEnd)
      : [];
    const accumulated = accumulatedMap.get(employee.id);
    const producedMinutes = round2(Number(accumulated?.minutes || 0));
    const normalMinutes = round2(Number(accumulated?.normal_minutes || 0));
    const extraMinutes = round2(Number(accumulated?.extra_minutes || 0));
    const producedQuantity = Number(accumulated?.qty || 0);
    const elapsedAvailableMinutes = round2((progressEnd >= range.start ? getEmployeeBaseDays(employee, range.start, progressEnd).length : 0) * baseMinutesDay());
    const totalAvailableMinutes = round2(getEmployeeBaseDays(employee, range.start, range.end).length * baseMinutesDay());
    const employeeTarget = employeeTargetPercent(employee);
    const currentTargetMinutes = round2(elapsedAvailableMinutes * (employeeTarget / 100));
    const currentPercent = elapsedAvailableMinutes > 0 ? round2((producedMinutes / elapsedAvailableMinutes) * 100) : 0;
    const fullPeriodPercent = totalAvailableMinutes > 0 ? round2((producedMinutes / totalAvailableMinutes) * 100) : 0;
    const minutesToCurrentTarget = Math.max(round2(currentTargetMinutes - producedMinutes), 0);
    const aboveTargetMinutes = Math.max(round2(producedMinutes - currentTargetMinutes), 0);
    const statusMeta = getDailyTrackingStatusMeta(currentPercent, employeeTarget);

    employeeSummaries.push({
      ...employee,
      business_days_elapsed: businessDaysElapsed.length,
      business_days_total: businessDaysTotal.length,
      produced_quantity: producedQuantity,
      normal_minutes: normalMinutes,
      extra_minutes: extraMinutes,
      produced_minutes: producedMinutes,
      elapsed_available_minutes: elapsedAvailableMinutes,
      total_available_minutes: totalAvailableMinutes,
      current_target_minutes: currentTargetMinutes,
      minutes_to_current_target: minutesToCurrentTarget,
      above_target_minutes: aboveTargetMinutes,
      current_percent: currentPercent,
      full_period_percent: fullPeriodPercent,
      last_production_date: accumulated?.last_production_date || '',
      status_meta: statusMeta,
      target_percent: employeeTarget
    });
  }

  employeeSummaries.sort((a, b) => {
    if (b.current_percent !== a.current_percent) return b.current_percent - a.current_percent;
    if (b.produced_minutes !== a.produced_minutes) return b.produced_minutes - a.produced_minutes;
    return String(a.full_name).localeCompare(String(b.full_name));
  });

  employeeSummaries.forEach((item, index) => {
    item.ranking_position = index + 1;
  });

  const totals = employeeSummaries.reduce((acc, item) => {
    acc.employees += 1;
    acc.businessDaysElapsed += Number(item.business_days_elapsed || 0);
    acc.businessDaysTotal += Number(item.business_days_total || 0);
    acc.producedQuantity += Number(item.produced_quantity || 0);
    acc.normalMinutes = round2(acc.normalMinutes + Number(item.normal_minutes || 0));
    acc.extraMinutes = round2(acc.extraMinutes + Number(item.extra_minutes || 0));
    acc.producedMinutes = round2(acc.producedMinutes + Number(item.produced_minutes || 0));
    acc.elapsedAvailableMinutes = round2(acc.elapsedAvailableMinutes + Number(item.elapsed_available_minutes || 0));
    acc.totalAvailableMinutes = round2(acc.totalAvailableMinutes + Number(item.total_available_minutes || 0));
    acc.currentTargetMinutes = round2(acc.currentTargetMinutes + Number(item.current_target_minutes || 0));
    acc.minutesToCurrentTarget = round2(acc.minutesToCurrentTarget + Number(item.minutes_to_current_target || 0));
    acc.aboveTargetMinutes = round2(acc.aboveTargetMinutes + Number(item.above_target_minutes || 0));
    if (item.current_percent >= item.target_percent) acc.reachedCurrentTarget += 1;
    else acc.belowCurrentTarget += 1;
    return acc;
  }, {
    employees: 0,
    reachedCurrentTarget: 0,
    belowCurrentTarget: 0,
    businessDaysElapsed: 0,
    businessDaysTotal: 0,
    producedQuantity: 0,
    normalMinutes: 0,
    extraMinutes: 0,
    producedMinutes: 0,
    elapsedAvailableMinutes: 0,
    totalAvailableMinutes: 0,
    currentTargetMinutes: 0,
    minutesToCurrentTarget: 0,
    aboveTargetMinutes: 0
  });
  totals.currentPercent = totals.elapsedAvailableMinutes > 0 ? round2((totals.producedMinutes / totals.elapsedAvailableMinutes) * 100) : 0;
  totals.fullPeriodPercent = totals.totalAvailableMinutes > 0 ? round2((totals.producedMinutes / totals.totalAvailableMinutes) * 100) : 0;

  const leader = employeeSummaries[0] || null;
  const lastPlace = employeeSummaries.length ? employeeSummaries[employeeSummaries.length - 1] : null;
  const attentionRows = employeeSummaries.filter(item => item.current_percent < item.target_percent).slice(0, 3);
  const management = {
    leader,
    lastPlace,
    attentionRows,
    hitRatePercent: totals.employees > 0 ? round2((totals.reachedCurrentTarget / totals.employees) * 100) : 0,
    nextActionLabel: attentionRows.length
      ? `Priorizar ${attentionRows[0].full_name} (${fmtNum(attentionRows[0].current_percent, 2)}%) · faltam ${fmtNum(attentionRows[0].minutes_to_current_target, 2)} min para ${fmtPct(attentionRows[0].target_percent)}%.`
      : `Time inteiro acima de ${tp()}% no corte atual.`
  };

  return {
    range,
    progressEnd,
    filters: {
      base_date: baseDate,
      period,
      employee_id: employeeFilterId ? String(employeeFilterId) : '',
      start_date: startDate || '',
      end_date: endDate || ''
    },
    employeeOptions: employees,
    selectedEmployee: employeeFilterId ? employees.find(employee => employee.id === employeeFilterId) || null : null,
    employeeSummaries,
    totals,
    management
  };
}

function renderDailyTrackingFilters(data) {
  const filters = data.filters;
  return `
    <section class="panel">
      <form class="inline-form" method="get" action="/acompanhamento/diario">
        <label>Visão
          <select name="period" onchange="this.form.submit()">
            <option value="month" ${filters.period === 'month' ? 'selected' : ''}>Mês operacional ${periodLabel()}</option>
            <option value="custom" ${filters.period === 'custom' ? 'selected' : ''}>Período personalizado</option>
          </select>
        </label>
        <label>Data base
          <input type="date" name="base_date" value="${escapeHtml(filters.base_date)}" />
        </label>
        <label>Colaborador
          <select name="employee_id">
            <option value="">Todos</option>
            ${data.employeeOptions.map(employee => `<option value="${employee.id}" ${String(filters.employee_id) === String(employee.id) ? 'selected' : ''}>${escapeHtml(employee.registration_code)} · ${escapeHtml(employee.full_name)}</option>`).join('')}
          </select>
        </label>
        <label>Início personalizado
          <input type="date" name="start_date" value="${escapeHtml(filters.start_date)}" />
        </label>
        <label>Fim personalizado
          <input type="date" name="end_date" value="${escapeHtml(filters.end_date)}" />
        </label>
        <button class="btn" type="submit">Atualizar</button>
        <a class="btn secondary" href="/acompanhamento/diario/export${getDailyTrackingQueryString(filters)}" target="_blank" rel="noopener">Abrir versão para impressão / PDF</a>
      </form>
      <p class="hint"><strong>Período de apuração:</strong> ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)} · <strong>modo:</strong> ${escapeHtml(data.range.label)}${data.selectedEmployee ? ` · <strong>colaborador:</strong> ${escapeHtml(data.selectedEmployee.full_name)}` : ''}.</p>
      <p class="subtle-note">Percentual atual = minutos acumulados ÷ minutos úteis decorridos no período. A base respeita os mesmos dias úteis/feriados já usados no fechamento.</p>
      <p class="subtle-note"><strong>Corte do acumulado:</strong> último dia útil anterior (${formatDatePtBr(data.progressEnd)}).</p>
    </section>
  `;
}

function renderDailyTrackingCards(data) {
  return `
    <div class="cards closure-cards">
      <article class="card"><span>Colaboradores no painel</span><strong>${data.totals.employees}</strong><small>Ativos no período filtrado</small></article>
      <article class="card"><span>Dias úteis decorridos</span><strong>${data.totals.businessDaysElapsed}</strong><small>Soma por colaboradora</small></article>
      <article class="card"><span>Dias úteis do período</span><strong>${data.totals.businessDaysTotal}</strong><small>Faixa total ${periodLabel()} ou personalizada</small></article>
      <article class="card"><span>Minutos acumulados</span><strong>${fmtNum(data.totals.producedMinutes, 2)}</strong><small>Total lançado até o corte atual</small></article>
      <article class="card tracking-status-good"><span>Já em ${tp()}%+</span><strong>${data.totals.reachedCurrentTarget}</strong><small>${fmtNum(data.management.hitRatePercent, 2)}% do time no alvo</small></article>
      <article class="card tracking-status-risk"><span>Abaixo de ${tp()}%</span><strong>${data.totals.belowCurrentTarget}</strong><small>Quem ainda pede reação no período</small></article>
      <article class="card"><span>Eficiência até o corte (${formatDatePtBr(data.progressEnd)})</span><strong>${fmtNum(data.totals.currentPercent, 2)}%</strong><small>Contra os minutos úteis já decorridos</small></article>
      <article class="card"><span>Faltam para ${tp()}%</span><strong>${fmtNum(data.totals.minutesToCurrentTarget, 2)}</strong><small>Gap consolidado até a meta atual</small></article>
      <article class="card"><span>Eficiência do período cheio</span><strong>${fmtNum(data.totals.fullPeriodPercent, 2)}%</strong><small>Minutos até o corte ÷ base do período inteiro</small></article>
    </div>
  `;
}

function renderDailyTrackingRankingTable(data) {
  return `
    <table>
      <thead><tr><th>Rank</th><th>Colaboradora</th><th>Status</th><th>Dias úteis</th><th>Minutos acumulados</th><th>Base atual</th><th>% até o corte</th><th>Meta atual</th><th>Faltam p/ meta</th><th>% período cheio</th><th>Último lançamento</th></tr></thead>
      <tbody>
        ${data.employeeSummaries.map(emp => `<tr class="${emp.status_meta.rowClass}"><td><strong>#${emp.ranking_position}</strong></td><td><strong>${escapeHtml(emp.full_name)}</strong><br /><span class="hint">${escapeHtml(emp.registration_code)}</span></td><td><span class="${emp.status_meta.badgeClass}">${emp.status_meta.label}</span></td><td>${emp.business_days_elapsed}/${emp.business_days_total}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.elapsed_available_minutes, 2)}</td><td class="${emp.status_meta.textClass}">${fmtNum(emp.current_percent, 2)}%</td><td>${fmtNum(emp.current_target_minutes, 2)}</td><td>${fmtNum(emp.minutes_to_current_target, 2)}</td><td>${fmtNum(emp.full_period_percent, 2)}%</td><td>${emp.last_production_date ? formatDatePtBr(emp.last_production_date) : '-'}</td></tr>`).join('') || '<tr><td colspan="11">Nenhum colaborador ativo nesse período.</td></tr>'}
      </tbody>
    </table>
  `;
}

function renderDailyTrackingPrintTable(data) {
  return `
    <table>
      <thead><tr><th>Rank</th><th>Registro</th><th>Colaboradora</th><th>Status</th><th>Dias úteis</th><th>Peças</th><th>Min. normais</th><th>Min. extras</th><th>Min. acumulados</th><th>Base atual</th><th>% até o corte</th><th>Meta</th><th>Gap meta</th><th>% período cheio</th><th>Último lançamento</th></tr></thead>
      <tbody>
        ${data.employeeSummaries.map(emp => `<tr class="${emp.status_meta.rowClass}"><td><strong>#${emp.ranking_position}</strong></td><td>${escapeHtml(emp.registration_code)}</td><td><strong>${escapeHtml(emp.full_name)}</strong></td><td><span class="${emp.status_meta.badgeClass}">${emp.status_meta.label}</span></td><td>${emp.business_days_elapsed}/${emp.business_days_total}</td><td>${emp.produced_quantity}</td><td>${fmtNum(emp.normal_minutes, 2)}</td><td>${fmtNum(emp.extra_minutes, 2)}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.elapsed_available_minutes, 2)}</td><td class="${emp.status_meta.textClass}">${fmtNum(emp.current_percent, 2)}%</td><td>${fmtNum(emp.current_target_minutes, 2)}</td><td>${fmtNum(emp.minutes_to_current_target, 2)}</td><td>${fmtNum(emp.full_period_percent, 2)}%</td><td>${emp.last_production_date ? formatDatePtBr(emp.last_production_date) : '-'}</td></tr>`).join('') || '<tr><td colspan="15">Nenhum colaborador ativo nesse período.</td></tr>'}
      </tbody>
    </table>
  `;
}

function renderDailyTrackingPage(query = {}, role = 'adm') {
  const period = ['month', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = query.employee_id || '';
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const data = getDailyTrackingData(baseDate, period, employeeId, startDate, endDate);

  const content = `
    <section class="page-header">
      <div>
        <h2>Acompanhamento diário de resultado</h2>
        <p>Visão gerencial do período, com ranking ${periodLabel()}, status visual de ${tp()}% e leitura rápida do que já pede ação.</p>
      </div>
      <div class="header-actions">
        <a class="btn secondary" href="/acompanhamento/diario/export${getDailyTrackingQueryString(data.filters)}" target="_blank" rel="noopener">Imprimir / Salvar PDF</a>
      </div>
    </section>

    ${renderDailyTrackingFilters(data)}
    ${renderDailyTrackingCards(data)}

    <section class="panel section-gap">
      <div class="panel-header"><h3>Legenda visual do status</h3><span class="hint">Leitura imediata da meta mínima.</span></div>
      <div class="actions tracking-inline-actions">
        <span class="status-pill ok">Acima de ${tp()}%</span>
        <span class="status-pill pending">Abaixo de ${tp()}%</span>
      </div>
      <p class="subtle-note">O ranking e o resumo gerencial usam essa mesma régua visual para deixar evidente quem já bateu a meta mínima e quem ainda precisa de reação.</p>
    </section>

    <section class="two-columns section-gap tracking-management-grid">
      <article class="panel tracking-management-panel">
        <div class="panel-header"><h3>Resumo gerencial do período</h3><span class="hint">Leitura pronta para decisão rápida.</span></div>
        <div class="tracking-kpi-stack">
          <div class="tracking-kpi-item">
            <span>Líder do período</span>
            <strong>${data.management.leader ? `${escapeHtml(data.management.leader.full_name)} · ${fmtNum(data.management.leader.current_percent, 2)}%` : 'Sem líder no filtro'}</strong>
            <small>${data.management.leader ? `Ranking #${data.management.leader.ranking_position} · ${escapeHtml(data.management.leader.registration_code)}` : 'Ajuste o filtro para visualizar um ranking válido.'}</small>
          </div>
          <div class="tracking-kpi-item">
            <span>Última colocação</span>
            <strong>${data.management.lastPlace ? `${escapeHtml(data.management.lastPlace.full_name)} · ${fmtNum(data.management.lastPlace.current_percent, 2)}%` : 'Sem dados'}</strong>
            <small>${data.management.lastPlace ? `Gap atual: ${fmtNum(data.management.lastPlace.minutes_to_current_target, 2)} min para chegar em ${fmtPct(data.management.lastPlace.target_percent)}%.` : 'Nenhum colaborador ativo no período.'}</small>
          </div>
          <div class="tracking-kpi-item tracking-kpi-next-step">
            <span>Atalhos do período</span>
            <strong>Ver prêmio e fechamento deste período</strong>
            <small>${escapeHtml(data.management.nextActionLabel)}</small>
            <div class="actions tracking-inline-actions">
              <a class="btn secondary" href="/premios/producao${getProductionPrizeQueryString(data.filters)}">Ver prêmio de produção</a>
              <a class="btn secondary" href="/closures${getClosureQueryString(data.filters)}">Ver fechamento</a>
            </div>
          </div>
        </div>
      </article>

      <article class="panel tracking-management-panel">
        <div class="panel-header"><h3>Radar abaixo da meta</h3><span class="hint">Quem está pedindo atenção primeiro.</span></div>
        <div class="tracking-alert-list">
          ${data.management.attentionRows.map(emp => `<div class="tracking-alert-item ${emp.status_meta.cardClass}"><strong>${escapeHtml(emp.full_name)}</strong><span>${escapeHtml(emp.registration_code)} · ${fmtNum(emp.current_percent, 2)}%</span><small>Faltam ${fmtNum(emp.minutes_to_current_target, 2)} minutos para alcançar ${fmtPct(emp.target_percent)}%.</small></div>`).join('') || `<p class="hint">Nenhuma colaboradora abaixo de ${tp()}% no recorte atual.</p>`}
        </div>
      </article>
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Ranking gerencial ${periodLabel()}</h3><span class="hint">Ordenado por desempenho atual no período.</span></div>
      ${renderDailyTrackingRankingTable(data)}
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Leitura desta versão</h3><span class="hint">Foco em acompanhamento do mês operacional.</span></div>
      <ul>
        <li>O período padrão usa o <strong>mês operacional (${periodLabel()})</strong>.</li>
        <li><strong>Minutos acumulados</strong> consideram somente lançamentos até o <strong>último dia útil anterior</strong> à data base exibida.</li>
        <li><strong>% até o corte</strong> compara o acumulado com os <strong>dias úteis já decorridos</strong> para cada colaboradora.</li>
        <li>O ranking já destaca visualmente quem <strong>bateu ${tp()}%</strong> e quem ainda está <strong>abaixo</strong>.</li>
        <li>A contagem de dias úteis respeita <strong>feriados configurados</strong> e também datas de início/rescisão do cadastro.</li>
        <li>Os atalhos abrem o <strong>Prêmio de produção</strong> e o <strong>Fechamento</strong> com o mesmo filtro.</li>
      </ul>
    </section>
  `;

  return pageLayout({ title: 'Acompanhamento diário de resultado', content, notice: query.notice || '', error: query.error || '', role });
}


function renderDailyTrackingExportPage(query = {}, role = 'adm') {
  const period = ['month', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = query.employee_id || '';
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const data = getDailyTrackingData(baseDate, period, employeeId, startDate, endDate);
  const subtitle = `${data.range.label}: ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)} · corte no último dia útil anterior ${formatDatePtBr(data.progressEnd)}${data.selectedEmployee ? ` · ${data.selectedEmployee.registration_code} · ${data.selectedEmployee.full_name}` : ''}`;

  const content = `
    <section class="page-header print-header">
      <div>
        <h2>Relatório gerencial · acompanhamento diário</h2>
        <p>${escapeHtml(subtitle)}</p>
      </div>
      <div class="header-actions no-print">
        <button class="btn" type="button" onclick="window.print()">Imprimir / Salvar PDF</button>
      </div>
    </section>

    ${renderDailyTrackingCards(data)}

    <section class="two-columns section-gap tracking-management-grid">
      <article class="panel tracking-management-panel">
        <div class="panel-header"><h3>Resumo gerencial do período</h3><span class="hint">Leitura pronta para impressão/PDF.</span></div>
        <div class="tracking-kpi-stack">
          <div class="tracking-kpi-item">
            <span>Líder do período</span>
            <strong>${data.management.leader ? `${escapeHtml(data.management.leader.full_name)} · ${fmtNum(data.management.leader.current_percent, 2)}%` : 'Sem líder no filtro'}</strong>
            <small>${data.management.leader ? `Ranking #${data.management.leader.ranking_position} · ${escapeHtml(data.management.leader.registration_code)}` : 'Ajuste o filtro para visualizar um ranking válido.'}</small>
          </div>
          <div class="tracking-kpi-item">
            <span>Última colocação</span>
            <strong>${data.management.lastPlace ? `${escapeHtml(data.management.lastPlace.full_name)} · ${fmtNum(data.management.lastPlace.current_percent, 2)}%` : 'Sem dados'}</strong>
            <small>${data.management.lastPlace ? `Gap atual: ${fmtNum(data.management.lastPlace.minutes_to_current_target, 2)} min para chegar em ${fmtPct(data.management.lastPlace.target_percent)}%.` : 'Nenhum colaborador ativo no período.'}</small>
          </div>
          <div class="tracking-kpi-item tracking-kpi-next-step">
            <span>Próxima ação gerencial</span>
            <strong>${data.totals.reachedCurrentTarget === data.totals.employees && data.totals.employees > 0 ? 'Time inteiro acima do corte mínimo' : `Foco em quem ainda não atingiu ${tp()}%`}</strong>
            <small>${escapeHtml(data.management.nextActionLabel)}</small>
          </div>
        </div>
      </article>

      <article class="panel tracking-management-panel">
        <div class="panel-header"><h3>Radar abaixo da meta</h3><span class="hint">Prioridade rápida para conferência.</span></div>
        <div class="tracking-alert-list">
          ${data.management.attentionRows.map(emp => `<div class="tracking-alert-item ${emp.status_meta.cardClass}"><strong>${escapeHtml(emp.full_name)}</strong><span>${escapeHtml(emp.registration_code)} · ${fmtNum(emp.current_percent, 2)}%</span><small>Faltam ${fmtNum(emp.minutes_to_current_target, 2)} minutos para alcançar ${fmtPct(emp.target_percent)}%.</small></div>`).join('') || `<p class="hint">Nenhuma colaboradora abaixo de ${tp()}% no recorte atual.</p>`}
        </div>
      </article>
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Ranking gerencial ${periodLabel()}</h3><span class="hint">Ordenado por desempenho atual no período.</span></div>
      ${renderDailyTrackingRankingTable(data)}
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Tabela principal do acompanhamento</h3><span class="hint">Versão completa para impressão/PDF com o mesmo filtro aplicado na tela.</span></div>
      ${renderDailyTrackingPrintTable(data)}
    </section>
  `;

  return pageLayout({ title: 'Acompanhamento diário de resultado', content, role });
}

function getProductionPrizeData(baseDate = today(), period = 'month', employeeId = '', startDate = '', endDate = '') {
  const range = getClosureReportRange(period, baseDate, startDate, endDate);
  const employees = db.prepare(`
    SELECT id, registration_code, full_name, start_date, termination_date, is_active
    FROM employees
    ORDER BY full_name ASC
  `).all();

  const employeeFilterId = Number(employeeId || 0);
  const filteredEmployees = employeeFilterId
    ? employees.filter(employee => employee.id === employeeFilterId)
    : employees;

  const productionMap = getCountedProductionByEmployee(range.start, range.end, employees);

  const employeeSummaries = [];
  for (const employee of filteredEmployees) {
    const businessDays = getEmployeeBusinessDaysInRange(employee, range.start, range.end);
    if (!businessDays.length) continue;

    const producedQuantity = Number(productionMap.get(employee.id)?.qty || 0);
    const normalMinutes = round2(Number(productionMap.get(employee.id)?.normal_minutes || 0));
    const producedExtraMinutes = round2(Number(productionMap.get(employee.id)?.extra_minutes || 0));
    const producedMinutes = round2(Number(productionMap.get(employee.id)?.minutes || 0));
    const availableMinutes = round2(getEmployeeBaseDays(employee, range.start, range.end).length * baseMinutesDay());
    // Prêmio: regra geral da empresa para todas (a meta individual é só de cobrança/acompanhamento)
    const targetMinutes60 = round2(availableMinutes * targetRatio());
    const efficiencyPercent = availableMinutes > 0 ? round2((producedMinutes / availableMinutes) * 100) : 0;
    const productionPrize = getProductionPrizeTier(efficiencyPercent);
    const sixtyPrize = efficiencyPercent >= targetPercent() ? numParam('prize_target_value') : 0;
    const extraMinutes = Math.max(round2(producedMinutes - targetMinutes60), 0);
    const extraBlocks = numParam('prize_extra_block_minutes') > 0 ? Math.floor(extraMinutes / numParam('prize_extra_block_minutes')) : 0;
    const extraPrize = extraBlocks * numParam('prize_extra_value');
    const totalPrize = productionPrize + sixtyPrize + extraPrize;

    employeeSummaries.push({
      ...employee,
      business_days: businessDays.length,
      produced_quantity: producedQuantity,
      normal_minutes: normalMinutes,
      produced_extra_minutes: producedExtraMinutes,
      produced_minutes: producedMinutes,
      available_minutes: availableMinutes,
      target_minutes_60: targetMinutes60,
      efficiency_percent: efficiencyPercent,
      production_prize: productionPrize,
      sixty_prize: sixtyPrize,
      extra_minutes: extraMinutes,
      extra_blocks: extraBlocks,
      extra_prize: extraPrize,
      total_prize: totalPrize,
      effective_range: getEmployeeEffectiveRange(employee, range.start, range.end)
    });
  }

  employeeSummaries.sort((a, b) => {
    if (b.total_prize !== a.total_prize) return b.total_prize - a.total_prize;
    if (b.efficiency_percent !== a.efficiency_percent) return b.efficiency_percent - a.efficiency_percent;
    return String(a.full_name).localeCompare(String(b.full_name));
  });

  const totals = employeeSummaries.reduce((acc, item) => {
    acc.employees += 1;
    acc.businessDays += Number(item.business_days || 0);
    acc.producedQuantity += Number(item.produced_quantity || 0);
    acc.normalMinutes = round2(acc.normalMinutes + Number(item.normal_minutes || 0));
    acc.producedExtraMinutes = round2(acc.producedExtraMinutes + Number(item.produced_extra_minutes || 0));
    acc.producedMinutes = round2(acc.producedMinutes + Number(item.produced_minutes || 0));
    acc.availableMinutes = round2(acc.availableMinutes + Number(item.available_minutes || 0));
    acc.targetMinutes60 = round2(acc.targetMinutes60 + Number(item.target_minutes_60 || 0));
    acc.productionPrize += Number(item.production_prize || 0);
    acc.sixtyPrize += Number(item.sixty_prize || 0);
    acc.extraPrize += Number(item.extra_prize || 0);
    acc.totalPrize += Number(item.total_prize || 0);
    if (item.sixty_prize > 0) acc.reachedSixty += 1;
    if (item.total_prize > 0) acc.awardedEmployees += 1;
    return acc;
  }, {
    employees: 0,
    awardedEmployees: 0,
    reachedSixty: 0,
    businessDays: 0,
    producedQuantity: 0,
    normalMinutes: 0,
    producedExtraMinutes: 0,
    producedMinutes: 0,
    availableMinutes: 0,
    targetMinutes60: 0,
    productionPrize: 0,
    sixtyPrize: 0,
    extraPrize: 0,
    totalPrize: 0
  });
  totals.efficiencyPercent = totals.availableMinutes > 0 ? round2((totals.producedMinutes / totals.availableMinutes) * 100) : 0;

  return {
    range,
    filters: {
      base_date: baseDate,
      period,
      employee_id: employeeFilterId ? String(employeeFilterId) : '',
      start_date: startDate || '',
      end_date: endDate || ''
    },
    employeeOptions: employees,
    employeeSummaries,
    selectedEmployee: employeeFilterId ? employees.find(employee => employee.id === employeeFilterId) || null : null,
    totals
  };
}

function renderProductionPrizeFilters(data) {
  const filters = data.filters;
  return `
    <section class="panel">
      <form class="inline-form" method="get" action="/premios/producao">
        <label>Relatório / visão
          <select name="period" onchange="this.form.submit()">
            <option value="day" ${filters.period === 'day' ? 'selected' : ''}>Diário</option>
            <option value="week" ${filters.period === 'week' ? 'selected' : ''}>Semanal</option>
            <option value="month" ${filters.period === 'month' ? 'selected' : ''}>Mensal operacional</option>
            <option value="general" ${filters.period === 'general' ? 'selected' : ''}>Geral</option>
            <option value="custom" ${filters.period === 'custom' ? 'selected' : ''}>Personalizado</option>
          </select>
        </label>
        <label>Data base
          <input type="date" name="base_date" value="${escapeHtml(filters.base_date)}" />
        </label>
        <label>Costureira / colaborador
          <select name="employee_id">
            <option value="">Todos</option>
            ${data.employeeOptions.map(employee => `<option value="${employee.id}" ${String(filters.employee_id) === String(employee.id) ? 'selected' : ''}>${escapeHtml(employee.registration_code)} · ${escapeHtml(employee.full_name)}</option>`).join('')}
          </select>
        </label>
        <label>Início personalizado
          <input type="date" name="start_date" value="${escapeHtml(filters.start_date)}" />
        </label>
        <label>Fim personalizado
          <input type="date" name="end_date" value="${escapeHtml(filters.end_date)}" />
        </label>
        <button class="btn" type="submit">Atualizar</button>
        <a class="btn secondary" href="/premios/producao/export${getProductionPrizeQueryString(filters)}" target="_blank" rel="noopener">Abrir versão para impressão / PDF</a>
      </form>
      <p class="hint"><strong>Período analisado:</strong> ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)} · <strong>modo:</strong> ${escapeHtml(data.range.label)}${data.selectedEmployee ? ` · <strong>colaborador:</strong> ${escapeHtml(data.selectedEmployee.full_name)}` : ''}.</p>
      <p class="subtle-note">Base do prêmio: minutos lançados no período ÷ minutos úteis monitorados. A meta de ${tp()}% usa os mesmos dias úteis/feriados já aplicados no fechamento.</p>
    </section>
  `;
}

function renderProductionPrizeCards(data) {
  return `
    <div class="cards closure-cards">
      <article class="card"><span>Colaboradores no período</span><strong>${data.totals.employees}</strong><small>Ativos dentro do intervalo filtrado</small></article>
      <article class="card"><span>Com prêmio</span><strong>${data.totals.awardedEmployees}</strong><small>Recebem alguma bonificação</small></article>
      <article class="card"><span>Atingiram ${tp()}%</span><strong>${data.totals.reachedSixty}</strong><small>Ganham prêmio fixo de ${fmtMoney(numParam('prize_target_value'))}</small></article>
      <article class="card"><span>Prêmio produção</span><strong>${fmtMoney(data.totals.productionPrize)}</strong><small>Faixas de 40%, 45% e 50%</small></article>
      <article class="card"><span>Prêmio ${tp()}%</span><strong>${fmtMoney(data.totals.sixtyPrize)}</strong><small>${fmtMoney(numParam('prize_target_value'))} por colaboradora que atinge a meta</small></article>
      <article class="card"><span>Prêmio extra</span><strong>${fmtMoney(data.totals.extraPrize)}</strong><small>10 a cada 100 min acima da meta</small></article>
      <article class="card"><span>Min. normais</span><strong>${fmtNum(data.totals.normalMinutes, 2)}</strong><small>Base sem o tempo extra</small></article>
      <article class="card"><span>Min. extras</span><strong>${fmtNum(data.totals.producedExtraMinutes, 2)}</strong><small>Tempo extra já incluído na eficiência</small></article>
      <article class="card"><span>Total previsto</span><strong>${fmtMoney(data.totals.totalPrize)}</strong><small>Soma das três colunas do relatório</small></article>
      <article class="card"><span>Eficiência do período cheio</span><strong>${fmtNum(data.totals.efficiencyPercent, 2)}%</strong><small>Minutos que contam para prêmio ÷ base do período inteiro</small></article>
    </div>
  `;
}

function renderProductionPrizePage(query = {}, role = 'adm') {
  const period = ['day', 'week', 'month', 'general', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = query.employee_id || '';
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const data = getProductionPrizeData(baseDate, period, employeeId, startDate, endDate);

  const content = `
    <section class="page-header">
      <div>
        <h2>Prêmio de produção</h2>
        <p>Cálculo do prêmio por costureira com base nos minutos que contam para prêmio e na meta de ${tp()}% do período.</p>
      </div>
    </section>

    ${renderProductionPrizeFilters(data)}
    ${renderProductionPrizeCards(data)}

    <section class="panel section-gap">
      <div class="panel-header"><h3>Relatório por colaboradora</h3><span class="hint">Prêmio produção, prêmio ${tp()}% e prêmio extra por colaboradora.</span></div>
      <table>
        <thead><tr><th>Nome</th><th>Prêmio produção</th><th>Prêmio ${tp()}%</th><th>Prêmio extra</th><th>Total</th><th>Normal</th><th>Extra</th><th>Minutos</th><th>Meta ${tp()}%</th><th>Base</th><th>Eficiência</th><th>Dias úteis</th></tr></thead>
        <tbody>
          ${data.employeeSummaries.map(emp => {
            const perfClass = emp.efficiency_percent < 40 ? 'perf-low' : (emp.efficiency_percent < 60 ? 'perf-mid' : 'perf-high');
            return `<tr><td><strong>${escapeHtml(emp.full_name)}</strong><br /><span class="hint">${escapeHtml(emp.registration_code)}</span></td><td>${fmtMoney(emp.production_prize)}</td><td>${fmtMoney(emp.sixty_prize)}</td><td>${fmtMoney(emp.extra_prize)}</td><td><strong>${fmtMoney(emp.total_prize)}</strong></td><td>${fmtNum(emp.normal_minutes, 2)}</td><td>${fmtNum(emp.produced_extra_minutes, 2)}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.target_minutes_60, 2)}</td><td>${fmtNum(emp.available_minutes, 2)}</td><td class="${perfClass}">${fmtNum(emp.efficiency_percent, 2)}%</td><td>${emp.business_days}</td></tr>`;
          }).join('') || '<tr><td colspan="12">Nenhum colaborador ativo nesse período.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Regras aplicadas</h3><span class="hint">Base alinhada ao fechamento atual.</span></div>
      <ul>
        <li>Meta do período = <strong>${tp()}% dos minutos úteis monitorados</strong> (base ${fmtNum(baseMinutesDay(), 0)} min por dia útil).</li>
        <li><strong>Prêmio produção</strong>: ${[1, 2, 3].filter(i => numParam(`prize_tier${i}_percent`) > 0).map(i => `${fmtNum(numParam(`prize_tier${i}_percent`), 0)}% = ${fmtMoney(numParam(`prize_tier${i}_value`))}`).join(', ')}.</li>
        <li><strong>Prêmio da meta</strong>: ao atingir ${tp()}%, soma <strong>${fmtMoney(numParam('prize_target_value'))}</strong>.</li>
        <li><strong>Prêmio extra</strong>: a cada ${fmtNum(numParam('prize_extra_block_minutes'), 0)} minutos acima da meta, soma <strong>${fmtMoney(numParam('prize_extra_value'))}</strong>.</li>
        <li>As regras são configuradas em <a href="/parametros">Parâmetros</a>.</li>
        <li>Os minutos do cálculo seguem os lançamentos já existentes no sistema e a base usa dias úteis/feriados conforme configuração atual.</li>
      </ul>
    </section>
  `;

  return pageLayout({ title: 'Prêmio de produção', content, notice: query.notice || '', error: query.error || '', role });
}

function renderProductionPrizeExportPage(query = {}, role = 'adm') {
  const period = ['day', 'week', 'month', 'general', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = query.employee_id || '';
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const data = getProductionPrizeData(baseDate, period, employeeId, startDate, endDate);
  const subtitle = `${data.range.label}: ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)}${data.selectedEmployee ? ` · ${data.selectedEmployee.registration_code} · ${data.selectedEmployee.full_name}` : ''}`;

  const content = `
    <section class="page-header print-header">
      <div>
        <h2>Relatório de prêmio de produção</h2>
        <p>${escapeHtml(subtitle)}</p>
      </div>
      <div class="header-actions no-print">
        <button class="btn" type="button" onclick="window.print()">Imprimir / Salvar PDF</button>
      </div>
    </section>

    ${renderProductionPrizeCards(data)}

    <section class="panel section-gap">
      <h3>Relatório por colaboradora</h3>
      <table>
        <thead><tr><th>Nome</th><th>Prêmio produção</th><th>Prêmio ${tp()}%</th><th>Prêmio extra</th><th>Total</th><th>Normal</th><th>Extra</th><th>Minutos</th><th>Meta ${tp()}%</th><th>Base</th><th>Eficiência</th></tr></thead>
        <tbody>
          ${data.employeeSummaries.map(emp => `<tr><td>${escapeHtml(emp.full_name)}</td><td>${fmtMoney(emp.production_prize)}</td><td>${fmtMoney(emp.sixty_prize)}</td><td>${fmtMoney(emp.extra_prize)}</td><td>${fmtMoney(emp.total_prize)}</td><td>${fmtNum(emp.normal_minutes, 2)}</td><td>${fmtNum(emp.produced_extra_minutes, 2)}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.target_minutes_60, 2)}</td><td>${fmtNum(emp.available_minutes, 2)}</td><td>${fmtNum(emp.efficiency_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="11">Sem dados para o filtro selecionado.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;

  return pageLayout({ title: 'Prêmio de produção', content, role });
}

function renderMonthlyClosurePage(query = {}, role = 'adm') {
  const period = ['day', 'week', 'month', 'general', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = query.employee_id || '';
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const data = getMonthlyClosureData(baseDate, period, employeeId, startDate, endDate);
  const content = `
    <section class="page-header">
      <div>
        <h2>Fechamento + relatórios</h2>
        <p>Visão operacional do fechamento com pendências, ausências, dias sem lançamento e relatórios básicos por período.</p>
      </div>
      ${isAdminRole(role) ? '<div class="actions"><a class="btn secondary" href="/ausencias/importar">Importar ausências (Pontomais)</a></div>' : ''}
    </section>

    ${renderClosureFilters(data)}
    ${renderClosureCards(data)}

    <section class="panel section-gap">
      <div class="panel-header"><h3>Resumo por colaborador</h3><span class="hint">Base pronta para leitura diária, semanal, mensal, geral e individual.</span></div>
      <table>
        <thead><tr><th>Registro</th><th>Colaborador</th><th>Período ativo</th><th>Dias úteis</th><th>Com lançamento</th><th>Justificados</th><th>Ausências</th><th>Pendentes</th><th>Peças</th><th>Minutos</th><th>Base</th><th>Eficiência</th></tr></thead>
        <tbody>
          ${data.employeeSummaries.map(emp => {
            const perfClass = emp.efficiency_percent < 50 ? 'perf-low' : (emp.efficiency_percent <= 60 ? 'perf-mid' : 'perf-high');
            const rangeLabel = emp.effective_range ? `${formatDatePtBr(emp.effective_range.start)} até ${formatDatePtBr(emp.effective_range.end)}` : '-';
            return `<tr><td>${escapeHtml(emp.registration_code)}</td><td>${escapeHtml(emp.full_name)}</td><td>${rangeLabel}</td><td>${emp.business_days}</td><td>${emp.with_production}</td><td>${emp.justified_days}</td><td>${emp.absence_days}</td><td><strong>${emp.pending_days}</strong></td><td>${emp.produced_quantity}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.available_minutes, 2)}</td><td class="${perfClass}">${fmtNum(emp.efficiency_percent, 2)}%</td></tr>`;
          }).join('') || '<tr><td colspan="12">Nenhum colaborador ativo nesse período.</td></tr>'}
        </tbody>
      </table>
    </section>

    <div class="two-columns closure-report-grid">
      <section class="panel section-gap">
        <div class="panel-header"><h3>Pendências do fechamento</h3><span class="hint">${data.pendingItems.length} dia(s) sem lançamento ainda sem tratamento.</span></div>
        <div class="closure-list">
          ${data.pendingItems.map(item => `
            <article class="closure-item pending">
              <div class="closure-item-head">
                <div>
                  <strong>${escapeHtml(item.registration_code)} · ${escapeHtml(item.full_name)}</strong>
                  <span>${formatDatePtBr(item.work_date)} · ${getClosureStatusLabel(item)}</span>
                </div>
                <span class="status-pill pending">Pendente</span>
              </div>
              <div class="closure-actions-grid">
                <form class="panel inset-panel stack-form compact" method="post" action="/closures/resolve">
                  <input type="hidden" name="employee_id" value="${item.employee_id}" />
                  <input type="hidden" name="work_date" value="${escapeHtml(item.work_date)}" />
                  <input type="hidden" name="base_date" value="${escapeHtml(baseDate)}" />
                  <input type="hidden" name="period" value="${escapeHtml(period)}" />
                  <input type="hidden" name="employee_id_filter" value="${escapeHtml(employeeId)}" />
                  <input type="hidden" name="start_date" value="${escapeHtml(startDate)}" />
                  <input type="hidden" name="end_date" value="${escapeHtml(endDate)}" />
                  <h4>Resolver com justificativa</h4>
                  <label>Status
                    <select name="status_type">
                      <option value="sem_lancamento_justificado">Sem lançamento justificado</option>
                      <option value="treinamento">Treinamento</option>
                      <option value="apoio_externo">Apoio externo</option>
                      <option value="folga">Folga</option>
                      <option value="afastamento">Afastamento</option>
                      <option value="outro">Outro</option>
                    </select>
                  </label>
                  <label>Justificativa<textarea name="justification" rows="3" placeholder="Ex.: colaboradora ficou em retrabalho interno e não lançou OP neste dia."></textarea></label>
                  <label>Observações<input name="notes" placeholder="Opcional" /></label>
                  <button class="btn" type="submit">Salvar justificativa</button>
                </form>
                <form class="panel inset-panel stack-form compact" method="post" action="/closures/absence">
                  <input type="hidden" name="employee_id" value="${item.employee_id}" />
                  <input type="hidden" name="work_date" value="${escapeHtml(item.work_date)}" />
                  <input type="hidden" name="base_date" value="${escapeHtml(baseDate)}" />
                  <input type="hidden" name="period" value="${escapeHtml(period)}" />
                  <input type="hidden" name="employee_id_filter" value="${escapeHtml(employeeId)}" />
                  <input type="hidden" name="start_date" value="${escapeHtml(startDate)}" />
                  <input type="hidden" name="end_date" value="${escapeHtml(endDate)}" />
                  <h4>Marcar como ausência</h4>
                  <label>Tipo de ausência
                    <select name="absence_type">
                      <option value="falta">Falta</option>
                      <option value="atestado">Atestado</option>
                      <option value="ferias">Férias</option>
                      <option value="folga">Folga</option>
                      <option value="afastamento">Afastamento</option>
                      <option value="outro">Outro</option>
                    </select>
                  </label>
                  <label>Justificativa<textarea name="justification" rows="3" placeholder="Ex.: atestado médico apresentado."></textarea></label>
                  <label>Observações<input name="notes" placeholder="Opcional" /></label>
                  <button class="btn secondary" type="submit">Salvar ausência</button>
                </form>
              </div>
            </article>
          `).join('') || '<p class="hint">Sem pendências abertas neste período. O fechamento está todo tratado para a visão atual.</p>'}
        </div>
      </section>

      <section class="panel section-gap">
        <div class="panel-header"><h3>Resumo diário do fechamento</h3><span class="hint">Leitura útil para diário de produção e conferência rápida.</span></div>
        <table>
          <thead><tr><th>Data</th><th>Ativos</th><th>Com lançamento</th><th>Resolvidos</th><th>Ausências</th><th>Pendentes</th><th>Peças</th><th>Normal</th><th>Extra</th><th>Total</th><th>Eficiência</th></tr></thead>
          <tbody>
            ${data.dailyRows.map(day => `<tr><td>${formatDatePtBr(day.work_date)}</td><td>${day.employees_active}</td><td>${day.with_production}</td><td>${day.resolved}</td><td>${day.absences}</td><td><strong>${day.pending}</strong></td><td>${day.produced_quantity}</td><td>${fmtNum(day.normal_minutes, 2)}</td><td>${fmtNum(day.extra_minutes, 2)}</td><td>${fmtNum(day.produced_minutes, 2)}</td><td>${fmtNum(day.efficiency_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="11">Sem dias úteis encontrados na faixa selecionada.</td></tr>'}
          </tbody>
        </table>
      </section>
    </div>

    <div class="two-columns closure-report-grid">
      <section class="panel section-gap">
        <div class="panel-header"><h3>Ranking de eficiência</h3><span class="hint">Versão mínima funcional para relatório individual e comparação operacional.</span></div>
        <table>
          <thead><tr><th>Registro</th><th>Colaborador</th><th>Minutos</th><th>Base</th><th>Eficiência</th><th>Pendências</th></tr></thead>
          <tbody>
            ${data.rankingRows.map(emp => {
              const perfClass = emp.efficiency_percent < 50 ? 'perf-low' : (emp.efficiency_percent <= 60 ? 'perf-mid' : 'perf-high');
              return `<tr><td>${escapeHtml(emp.registration_code)}</td><td>${escapeHtml(emp.full_name)}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.available_minutes, 2)}</td><td class="${perfClass}">${fmtNum(emp.efficiency_percent, 2)}%</td><td>${emp.pending_days}</td></tr>`;
            }).join('') || '<tr><td colspan="6">Sem dados de ranking para esse filtro.</td></tr>'}
          </tbody>
        </table>
      </section>

      <section class="panel section-gap">
        <div class="panel-header"><h3>Dias já resolvidos</h3><span class="hint">Justificativas e ausências já tratadas no fechamento.</span></div>
        <table>
          <thead><tr><th>Data</th><th>Registro</th><th>Colaborador</th><th>Status</th><th>Detalhe</th><th>Ação aplicada</th></tr></thead>
          <tbody>
            ${data.resolvedItems.map(item => `<tr><td>${formatDatePtBr(item.work_date)}</td><td>${escapeHtml(item.registration_code)}</td><td>${escapeHtml(item.full_name)}</td><td><span class="status-pill ${getClosureStatusBadgeClass(item)}">${escapeHtml(getClosureResolvedTypeLabel(item))}</span></td><td>${escapeHtml(item.absence_justification || item.closure_justification || '-')}</td><td>${escapeHtml(getClosureActionLabel(item))}</td></tr>`).join('') || '<tr><td colspan="6">Nenhum dia resolvido manualmente até agora.</td></tr>'}
          </tbody>
        </table>
      </section>

    </div>
  `;
  return pageLayout({ title: 'Fechamento e relatórios', content, notice: query.notice || '', error: query.error || '', role });
}

function renderClosureExportPage(query = {}, role = 'adm') {
  const period = ['day', 'week', 'month', 'general', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = query.employee_id || '';
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const data = getMonthlyClosureData(baseDate, period, employeeId, startDate, endDate);
  const subtitle = `${data.range.label}: ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)}${data.selectedEmployee ? ` · ${data.selectedEmployee.registration_code} · ${data.selectedEmployee.full_name}` : ''}`;

  const content = `
    <section class="page-header print-header">
      <div>
        <h2>Relatório de fechamento</h2>
        <p>${escapeHtml(subtitle)}</p>
      </div>
      <div class="header-actions no-print">
        <button class="btn" type="button" onclick="window.print()">Imprimir / Salvar PDF</button>
      </div>
    </section>
    ${renderClosureCards(data)}
    <section class="panel section-gap">
      <h3>Resumo por colaborador</h3>
      <table>
        <thead><tr><th>Registro</th><th>Colaborador</th><th>Dias úteis</th><th>Com lançamento</th><th>Justificados</th><th>Ausências</th><th>Pendentes</th><th>Peças</th><th>Normal</th><th>Extra</th><th>Total</th><th>Base</th><th>Eficiência</th></tr></thead>
        <tbody>
          ${data.employeeSummaries.map(emp => `<tr><td>${escapeHtml(emp.registration_code)}</td><td>${escapeHtml(emp.full_name)}</td><td>${emp.business_days}</td><td>${emp.with_production}</td><td>${emp.justified_days}</td><td>${emp.absence_days}</td><td>${emp.pending_days}</td><td>${emp.produced_quantity}</td><td>${fmtNum(emp.normal_minutes, 2)}</td><td>${fmtNum(emp.extra_minutes, 2)}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td>${fmtNum(emp.available_minutes, 2)}</td><td>${fmtNum(emp.efficiency_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="13">Sem dados para o filtro selecionado.</td></tr>'}
        </tbody>
      </table>
    </section>
    <section class="panel section-gap">
      <h3>Resumo diário</h3>
      <table>
        <thead><tr><th>Data</th><th>Ativos</th><th>Com lançamento</th><th>Resolvidos</th><th>Ausências</th><th>Pendentes</th><th>Peças</th><th>Normal</th><th>Extra</th><th>Total</th><th>Eficiência</th></tr></thead>
        <tbody>
          ${data.dailyRows.map(day => `<tr><td>${formatDatePtBr(day.work_date)}</td><td>${day.employees_active}</td><td>${day.with_production}</td><td>${day.resolved}</td><td>${day.absences}</td><td>${day.pending}</td><td>${day.produced_quantity}</td><td>${fmtNum(day.normal_minutes, 2)}</td><td>${fmtNum(day.extra_minutes, 2)}</td><td>${fmtNum(day.produced_minutes, 2)}</td><td>${fmtNum(day.efficiency_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="11">Sem dados diários no intervalo.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'Fechamento e relatórios', content, role });
}

function buildClosureRedirectUrl(form, noticeOrErrorKey, message) {
  const params = new URLSearchParams();
  params.set('base_date', form.base_date || today());
  if (form.period) params.set('period', form.period);
  if (form.employee_id_filter) params.set('employee_id', form.employee_id_filter);
  if (form.start_date) params.set('start_date', form.start_date);
  if (form.end_date) params.set('end_date', form.end_date);
  params.set(noticeOrErrorKey, message);
  return `/closures?${params.toString()}`;
}

function handleUpsertClosureJustification(form, res) {
  const employeeId = Number(form.employee_id || 0);
  const workDate = String(form.work_date || '').trim();
  const statusType = form.status_type || 'sem_lancamento_justificado';
  const justification = String(form.justification || '').trim();
  const notes = String(form.notes || '').trim() || null;

  if (!employeeId || !workDate || !justification) {
    return redirect(res, buildClosureRedirectUrl(form, 'error', 'Para resolver a pendência, informe uma justificativa.'));
  }

  db.prepare(`
    INSERT INTO employee_daily_closures (employee_id, work_date, status_type, justification, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT(employee_id, work_date) DO UPDATE SET
      status_type = excluded.status_type,
      justification = excluded.justification,
      notes = excluded.notes,
      updated_at = CURRENT_TIMESTAMP
  `).run(employeeId, workDate, statusType, justification, notes);

  db.prepare('DELETE FROM employee_absences WHERE employee_id = ? AND absence_date = ?').run(employeeId, workDate);

  redirect(res, buildClosureRedirectUrl(form, 'notice', 'Pendência do fechamento salva como resolvida.'));
}

function handleUpsertClosureAbsence(form, res) {
  const employeeId = Number(form.employee_id || 0);
  const workDate = String(form.work_date || '').trim();
  const absenceType = form.absence_type || 'falta';
  const justification = String(form.justification || '').trim();
  const notes = String(form.notes || '').trim() || null;

  if (!employeeId || !workDate || !justification) {
    return redirect(res, buildClosureRedirectUrl(form, 'error', 'Para marcar ausência, informe uma justificativa.'));
  }

  db.prepare(`
    INSERT INTO employee_absences (employee_id, absence_date, absence_type, justification, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT(employee_id, absence_date) DO UPDATE SET
      absence_type = excluded.absence_type,
      justification = excluded.justification,
      notes = excluded.notes,
      updated_at = CURRENT_TIMESTAMP
  `).run(employeeId, workDate, absenceType, justification, notes);

  db.prepare('DELETE FROM employee_daily_closures WHERE employee_id = ? AND work_date = ?').run(employeeId, workDate);

  redirect(res, buildClosureRedirectUrl(form, 'notice', 'Ausência registrada no fechamento.'));
}

// Máscara (47) 99999-9999 enquanto digita; aceita colar com +55
const PHONE_MASK_SCRIPT = `<script>
  (() => {
    const mask = v => {
      let d = String(v || '').replace(/\\D/g, '');
      if (d.length > 11 && d.startsWith('55')) d = d.slice(2);
      d = d.slice(0, 11);
      if (d.length <= 2) return d ? '(' + d : '';
      if (d.length <= 6) return '(' + d.slice(0, 2) + ') ' + d.slice(2);
      if (d.length <= 10) return '(' + d.slice(0, 2) + ') ' + d.slice(2, 6) + '-' + d.slice(6);
      return '(' + d.slice(0, 2) + ') ' + d.slice(2, 7) + '-' + d.slice(7);
    };
    document.querySelectorAll('[data-phone-mask]').forEach(el => {
      el.addEventListener('input', () => { el.value = mask(el.value); });
      el.value = mask(el.value);
    });
  })();
</script>`;

// Telefone/WhatsApp: guarda só dígitos com DDD (ex.: 47999998888)
function normalizePhone(value) {
  let digits = String(value || '').replace(/\D/g, '');
  if (digits.startsWith('55') && digits.length >= 12) digits = digits.slice(2);
  return digits || null;
}

function formatPhone(digits) {
  const d = String(digits || '');
  if (d.length === 11) return `(${d.slice(0, 2)}) ${d.slice(2, 7)}-${d.slice(7)}`;
  if (d.length === 10) return `(${d.slice(0, 2)}) ${d.slice(2, 6)}-${d.slice(6)}`;
  return d;
}

function renderWhatsAppLink(digits, message = '') {
  if (!digits) return '-';
  const text = message ? `?text=${encodeURIComponent(message)}` : '';
  const title = message ? ' title="Abre o WhatsApp com o resultado do período já escrito"' : '';
  return `<a class="whatsapp-link" href="https://wa.me/55${escapeHtml(digits)}${text}" target="_blank" rel="noopener"${title}>${escapeHtml(formatPhone(digits))}</a>`;
}

// Resultado do período vigente (até o corte) para a mensagem de WhatsApp.
// Se o período acabou de começar (nenhum dia útil decorrido), usa o período anterior fechado.
function getEmployeeResultContext(employees) {
  const lastBusinessDay = getPreviousBusinessDay(today());
  let range = getPeriodRange('month', today());
  if (lastBusinessDay < range.start) range = getPeriodRange('month', lastBusinessDay);
  const cutoff = lastBusinessDay < range.end ? lastBusinessDay : range.end;
  const counted = getCountedProductionByEmployee(range.start, cutoff, employees);
  return { range, cutoff, counted };
}

function buildEmployeeResultMessage(employee, context) {
  const { range, cutoff, counted } = context;
  const minutes = round2(counted.get(employee.id)?.minutes || 0);
  const eff = calculateEmployeeEfficiency(employee, minutes, range.start, range.end, cutoff);
  if (!eff.business_days) return '';
  const firstName = String(employee.full_name || '').trim().split(/\s+/)[0] || '';
  const name = firstName ? firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase() : '';
  const targetPct = employeeTargetPercent(employee);
  const target = round2(eff.available_minutes * (targetPct / 100));
  const gap = round2(target - minutes);
  const lines = [
    `Olá, ${name}! Segue seu resultado no período de ${formatDatePtBr(range.start)} a ${formatDatePtBr(range.end)}, até ${formatDatePtBr(cutoff)}:`,
    '',
    `• Minutos produzidos: ${fmtNum(minutes, 2)} min`,
    `• Eficiência: ${fmtNum(eff.efficiency_percent, 2)}%`,
    gap > 0
      ? `• Faltam ${fmtNum(gap, 2)} min para chegar na meta de ${fmtPct(targetPct)}%.`
      : `• Meta de ${fmtPct(targetPct)}% atingida! Parabéns!`,
    '',
    `Lembrando: a sua meta por dia é de ${fmtNum(round2(baseMinutesDay() * targetPct / 100), Number.isInteger(round2(baseMinutesDay() * targetPct / 100)) ? 0 : 1)} minutos para ${fmtPct(targetPct)}%.`
  ];
  return lines.join('\n');
}

function describeEmployeeStatus(employee) {
  if (employee.termination_date) return 'Desligado';
  if (employee.start_date) return 'Ativo';
  return employee.is_active ? 'Ativo' : 'Inativo';
}

// Busca a OP pelo número, pelo código de barras cadastrado ou por formas comuns de leitura
// (ex.: leitor que não envia o hífen: 1801138001 -> 1801138-001; 1801138 -> 1801138-001).
function getOpByNumber(opNumber) {
  const raw = String(opNumber || '').trim();
  if (!raw) return null;
  const candidates = [raw];
  const digits = raw.replace(/\D/g, '');
  if (/^\d{10}$/.test(raw)) candidates.push(`${raw.slice(0, 7)}-${raw.slice(7)}`);
  if (/^\d{7}$/.test(raw)) candidates.push(`${raw}-001`);
  if (digits && digits !== raw && /^\d{10}$/.test(digits)) candidates.push(`${digits.slice(0, 7)}-${digits.slice(7)}`);
  for (const candidate of candidates) {
    const found = findOpByExactNumber(candidate);
    if (found) return found;
  }
  const byBarcode = db.prepare('SELECT op_number FROM ops WHERE is_reversed = 0 AND TRIM(barcode) = ? ORDER BY created_at DESC LIMIT 1').get(raw);
  return byBarcode ? findOpByExactNumber(byBarcode.op_number) : null;
}

function findOpByExactNumber(opNumber) {
  const normalized = String(opNumber || '').trim();
  if (!normalized) return null;
  return db.prepare(`
    SELECT
      o.*,
      (SELECT c.name FROM op_cell_transfers t JOIN sewing_cells c ON c.id = t.cell_id WHERE t.op_id = o.id AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0) ORDER BY t.id DESC LIMIT 1) AS active_cell_name,
      COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity,
      COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) AS problem_quantity,
      COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS returned_from_cells_quantity,
      COALESCE((SELECT SUM(t.quantity_sent - t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS open_in_cells_quantity,
      COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS counted_quantity,
      o.total_pieces - (COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0)) AS remaining_quantity
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.is_reversed = 0 AND TRIM(o.op_number) = ? COLLATE NOCASE
    GROUP BY o.id
    ORDER BY o.created_at DESC
    LIMIT 1
  `).get(normalized);
}

function getOpQuickPreview(opNumber) {
  const op = getOpByNumber(opNumber);
  if (!op) return null;
  const extraConfig = getActiveOpExtraTimeForOp(op.id);
  const extraMinutesPerPiece = Number(extraConfig?.extra_minutes_per_piece || 0);
  return {
    id: op.id,
    op_number: op.op_number,
    product_name: op.product_name,
    brand: op.brand,
    status_color: op.status_color,
    produced_quantity: Number(op.produced_quantity || 0),
    remaining_quantity: Number(op.remaining_quantity || 0),
    total_pieces: Number(op.total_pieces || 0),
    minutes_f21: Number(op.minutes_f21 || 0),
    minutes_f22: Number(op.minutes_f22 || 0),
    effective_launch_minutes: Number(op.minutes_f21 || 0),
    launch_normal_minutes_per_piece: getEffectiveLaunchMinutes(op),
    extra_minutes_per_piece: extraMinutesPerPiece,
    total_launch_minutes_per_piece: round3(getEffectiveLaunchMinutes(op) + extraMinutesPerPiece),
    extra_reason: extraConfig?.reason || '',
    active_cell_name: op.active_cell_name || '',
    is_in_cell: op.status_color === 'rosa'
  };
}

// ===================== DATA DE ENTREGA (T1.3) =====================
function addDaysIso(isoDate, days) {
  const d = new Date(`${isoDate}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function isOpOpenForDelivery(op) {
  return !op.shipped_at && op.status_color !== 'vermelho' && !isReturnedWithoutProductionLifecycle(op.lifecycle_type);
}

// Badge: atrasada (vermelho), vence em até 3 dias (laranja), data normal
function deliveryBadge(op) {
  if (!op.delivery_date) return '<span class="hint">-</span>';
  const label = escapeHtml(formatDatePtBr(op.delivery_date));
  if (!isOpOpenForDelivery(op)) return label;
  const todayIso = today();
  if (op.delivery_date < todayIso) return `<span class="delivery-tag late" title="Atrasada">${label} · atrasada</span>`;
  const days = Math.round((new Date(`${op.delivery_date}T00:00:00Z`) - new Date(`${todayIso}T00:00:00Z`)) / 86400000);
  if (days === 0) return `<span class="delivery-tag soon">${label} · hoje</span>`;
  if (days <= 3) return `<span class="delivery-tag soon">${label} · ${days} dia${days > 1 ? 's' : ''}</span>`;
  return label;
}

function handleUpdateOpDeliveryDate(opId, form, res, role) {
  if (!canAccessCadastros(role)) return requireAdmin(null, res, role);
  const value = String(form.delivery_date || '').trim();
  if (value && !/^\d{4}-\d{2}-\d{2}$/.test(value)) return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Data de entrega inválida.')}`);
  const result = db.prepare('UPDATE ops SET delivery_date = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(value || null, opId);
  if (!result.changes) return redirect(res, `/ops?error=${encodeURIComponent('OP não encontrada.')}`);
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent(value ? 'Data de entrega atualizada.' : 'Data de entrega removida.')}`);
}

function getOpList(filters = {}) {
  let sql = `
    SELECT
      o.id,
      o.op_number,
      o.product_name,
      o.brand,
      o.collection_name,
      o.pilot_mode,
      o.appliance,
      o.op_type,
      o.notes,
      o.total_pieces,
      o.minutes_f21,
      o.minutes_f22,
      o.f23_mode,
      o.minutes_f23,
      o.status_color,
      o.lifecycle_type,
      o.entry_date,
      o.delivery_date,
      o.shipped_at,
      o.is_billed,
      o.billed_at,
      o.billing_notes,
      (SELECT c.name FROM op_cell_transfers t JOIN sewing_cells c ON c.id = t.cell_id WHERE t.op_id = o.id AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0) ORDER BY t.id DESC LIMIT 1) AS active_cell_name,
      COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity,
      COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) AS problem_quantity,
      COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS returned_from_cells_quantity,
      COALESCE((SELECT SUM(t.quantity_sent - t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS open_in_cells_quantity,
      CASE
        WHEN COALESCE(o.lifecycle_type, 'normal') IN ('nao_industrializada', 'devolvida_sem_producao') THEN o.total_pieces
        ELSE COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0)
      END AS counted_quantity,
      CASE
        WHEN COALESCE(o.lifecycle_type, 'normal') IN ('nao_industrializada', 'devolvida_sem_producao') THEN 0
        ELSE o.total_pieces - (COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0))
      END AS remaining_quantity,
      ROUND(COALESCE(SUM(p.normal_minutes), 0), 2) AS produced_normal_minutes,
      ROUND(COALESCE(SUM(p.extra_minutes), 0), 2) AS produced_extra_minutes,
      ROUND(COALESCE(SUM(p.produced_minutes), 0), 2) AS produced_minutes
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.is_reversed = 0
  `;
  const where = [];
  const params = [];
  if (filters.q) {
    where.push("(o.op_number LIKE ? OR COALESCE(o.barcode, '') LIKE ? OR o.product_name LIKE ? OR COALESCE(o.brand, '') LIKE ?)");
    params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
  }
  if (filters.opNumber) {
    where.push('o.op_number LIKE ?');
    params.push(`%${filters.opNumber}%`);
  }
  if (filters.entryDate) {
    where.push('o.entry_date = ?');
    params.push(filters.entryDate);
  }
  if (filters.status) {
    where.push('o.status_color = ?');
    params.push(filters.status);
  }
  if (filters.opType) {
    where.push('o.op_type = ?');
    params.push(filters.opType);
  }
  if (filters.brand) {
    where.push("COALESCE(o.brand, '') = ?");
    params.push(filters.brand);
  }
  if (filters.collectionName) {
    where.push("COALESCE(o.collection_name, '') = ?");
    params.push(filters.collectionName);
  }
  if (filters.billingStatus === 'billed') {
    where.push('COALESCE(o.is_billed, 0) = 1');
    where.push("COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')");
  }
  if (filters.billingStatus === 'not_billed') {
    where.push('COALESCE(o.is_billed, 0) = 0');
    where.push("COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')");
  }
  if (filters.billingStatus === 'returned') {
    where.push("COALESCE(o.lifecycle_type, 'normal') IN ('nao_industrializada', 'devolvida_sem_producao')");
  }
  if (filters.onlyEligibleShipment) {
    where.push('o.status_color = ?');
    params.push('azul');
    where.push('o.shipped_at IS NULL');
    where.push("COALESCE(o.lifecycle_type, 'normal') IN ('normal', 'nao_industrializada', 'devolvida_sem_producao')");
  }
  // Prazo de entrega (só OPs ainda não embarcadas e não devolvidas)
  const openForDelivery = "o.shipped_at IS NULL AND o.status_color <> 'vermelho' AND COALESCE(o.lifecycle_type, 'normal') = 'normal'";
  if (filters.deadline === 'atrasadas') {
    where.push(`${openForDelivery} AND o.delivery_date IS NOT NULL AND o.delivery_date < ?`);
    params.push(today());
  } else if (filters.deadline === 'vencem3') {
    where.push(`${openForDelivery} AND o.delivery_date BETWEEN ? AND ?`);
    params.push(today(), addDaysIso(today(), 3));
  } else if (filters.deadline === 'sem_data') {
    where.push(`${openForDelivery} AND (o.delivery_date IS NULL OR o.delivery_date = '')`);
  }
  if (where.length) sql += ` AND ${where.join(' AND ')}`;
  sql += filters.deadline === 'atrasadas' || filters.deadline === 'vencem3' || filters.sort === 'entrega'
    ? " GROUP BY o.id ORDER BY CASE WHEN o.delivery_date IS NULL OR o.delivery_date = '' THEN 1 ELSE 0 END, o.delivery_date ASC, o.entry_date DESC"
    : ' GROUP BY o.id ORDER BY o.entry_date DESC, o.created_at DESC';
  return db.prepare(sql).all(...params).map(op => ({ ...op, ...calculateOpShipmentMinutes(op) }));
}

function calculateOpShipmentMinutes(op) {
  if (isReturnedWithoutProductionLifecycle(op.lifecycle_type)) {
    return {
      sewing_minutes: 0,
      post_sewing_minutes: 0,
      total_shipment_minutes: 0
    };
  }
  const problemQuantity = op?.problem_quantity !== undefined
    ? Number(op.problem_quantity || 0)
    : Number(db.prepare('SELECT COALESCE(SUM(quantity), 0) AS total FROM op_problem_items WHERE op_id = ?').get(Number(op.id))?.total || 0);
  const shipmentBaseQuantity = Math.max(Number(op.total_pieces || 0) - problemQuantity, 0);
  const sewingMinutes = round2(shipmentBaseQuantity * Number(op.minutes_f21 || 0));
  const postSewingMinutes = op.f23_mode === 'interno'
    ? round2(shipmentBaseQuantity * Number(op.minutes_f23 || 0))
    : 0;
  return {
    shipment_base_quantity: shipmentBaseQuantity,
    sewing_minutes: sewingMinutes,
    post_sewing_minutes: postSewingMinutes,
    total_shipment_minutes: round2(sewingMinutes + postSewingMinutes)
  };
}

function getEligibleShipmentOps(filters = {}) {
  let sql = `
    SELECT
      o.id,
      o.op_number,
      o.product_name,
      o.brand,
      o.collection_name,
      o.pilot_mode,
      o.appliance,
      o.op_type,
      o.total_pieces,
      o.status_color,
      o.minutes_f21,
      o.minutes_f22,
      o.f23_mode,
      o.minutes_f23,
      o.entry_date,
      COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.is_reversed = 0
      AND o.status_color = 'azul'
      AND o.shipped_at IS NULL
      AND COALESCE(o.lifecycle_type, 'normal') IN ('normal', 'nao_industrializada', 'devolvida_sem_producao')
  `;
  const params = [];
  if (filters.q) {
    sql += " AND (o.op_number LIKE ? OR COALESCE(o.barcode, '') LIKE ? OR o.product_name LIKE ? OR COALESCE(o.brand, '') LIKE ?)";
    params.push(`%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`, `%${filters.q}%`);
  }
  if (filters.opNumber) {
    sql += ' AND o.op_number LIKE ?';
    params.push(`%${filters.opNumber}%`);
  }
  if (filters.entryDate) {
    sql += ' AND o.entry_date = ?';
    params.push(filters.entryDate);
  }
  sql += ' GROUP BY o.id ORDER BY o.entry_date DESC, o.created_at DESC';
  return db.prepare(sql).all(...params).map(op => ({ ...op, ...calculateOpShipmentMinutes(op) }));
}

function getOpDetail(id) {
  const op = db.prepare(`
    SELECT
      o.*,
      COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity,
      COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) AS problem_quantity,
      COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS returned_from_cells_quantity,
      COALESCE((SELECT SUM(t.quantity_sent - t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS open_in_cells_quantity,
      CASE
        WHEN COALESCE(o.lifecycle_type, 'normal') IN ('nao_industrializada', 'devolvida_sem_producao') THEN o.total_pieces
        ELSE COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0)
      END AS counted_quantity,
      ROUND(COALESCE(SUM(p.normal_minutes), 0), 2) AS produced_normal_minutes,
      ROUND(COALESCE(SUM(p.extra_minutes), 0), 2) AS produced_extra_minutes,
      ROUND(COALESCE(SUM(p.produced_minutes), 0), 2) AS produced_minutes,
      CASE
        WHEN COALESCE(o.lifecycle_type, 'normal') IN ('nao_industrializada', 'devolvida_sem_producao') THEN 0
        ELSE o.total_pieces - (COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0))
      END AS remaining_quantity
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.id = ?
    GROUP BY o.id
  `).get(id);
  if (!op) return null;

  const history = db.prepare(`
    SELECT p.*, e.registration_code, e.full_name
    FROM op_daily_productions p
    JOIN employees e ON e.id = p.employee_id
    WHERE p.op_id = ? AND p.is_reversed = 0
    ORDER BY p.production_date DESC, p.created_at DESC
  `).all(id);

  const occurrences = db.prepare(`
    SELECT *
    FROM op_occurrences
    WHERE op_id = ?
    ORDER BY opened_at DESC
  `).all(id);

  const problemHistory = db.prepare(`
    SELECT pi.*, u.full_name AS created_by_name
    FROM op_problem_items pi
    LEFT JOIN users u ON u.id = pi.created_by_user_id
    WHERE pi.op_id = ?
    ORDER BY pi.problem_date DESC, pi.created_at DESC, pi.id DESC
  `).all(id);

  const shipmentHistory = db.prepare(`
    SELECT
      si.id,
      s.id AS shipment_id,
      s.shipment_number,
      s.shipment_date,
      si.total_minutes,
      si.sewing_minutes,
      si.post_sewing_minutes
    FROM shipment_items si
    JOIN shipments s ON s.id = si.shipment_id
    WHERE si.op_id = ? AND s.is_reversed = 0
    ORDER BY s.shipment_date DESC, s.created_at DESC
  `).all(id);

  const extraTimes = db.prepare(`
    SELECT et.*, o.op_number, o.product_name
    FROM op_extra_times et
    JOIN ops o ON o.id = et.op_id
    WHERE et.op_id = ?
    ORDER BY et.effective_date DESC, et.id DESC
  `).all(id);

  const billingHistory = db.prepare(`
    SELECT bh.*, u.full_name AS billed_by_name
    FROM op_billing_history bh
    LEFT JOIN users u ON u.id = bh.created_by_user_id
    WHERE bh.op_id = ?
    ORDER BY bh.billed_at DESC, bh.id DESC
  `).all(id);

  const cellTransfers = getOpCellTransfers(id);
  const openCellTransfers = cellTransfers.filter(item => getOpenQuantityFromCellTransfer(item) > 0);
  const activeCellTransfer = openCellTransfers[0] || null;
  const cellBalance = getOpCellBalance(id);

  return { op: { ...op, ...calculateOpShipmentMinutes(op) }, history, occurrences, problemHistory, shipmentHistory, extraTimes, billingHistory, cellTransfers, openCellTransfers, activeCellTransfer, cellBalance };
}

function recalculateOpStatus(opId) {
  const summary = db.prepare(`
    SELECT
      o.id,
      o.total_pieces,
      o.minutes_f21,
      o.minutes_f22,
      o.shipped_at,
      o.lifecycle_type,
      EXISTS(SELECT 1 FROM op_occurrences oc WHERE oc.op_id = o.id AND oc.is_concluded = 0) AS has_open_occurrence,
      COALESCE(SUM(p.produced_quantity), 0) AS total_produced,
      COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) AS total_problem,
      COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS total_returned_from_cells,
      COALESCE((SELECT SUM(t.quantity_sent - t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS total_open_in_cells,
      COALESCE(SUM(p.produced_quantity), 0) + COALESCE((SELECT SUM(pi.quantity) FROM op_problem_items pi WHERE pi.op_id = o.id), 0) + COALESCE((SELECT SUM(t.quantity_returned) FROM op_cell_transfers t WHERE t.op_id = o.id), 0) AS total_counted,
      COALESCE(SUM(p.produced_minutes), 0) AS total_produced_minutes
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.id = ?
    GROUP BY o.id
  `).get(opId);
  if (!summary) return;

  const requiredMinutes = round3(Number(summary.total_pieces || 0) * getEffectiveLaunchMinutes(summary));
  const openInCells = Math.max(Number(summary.total_open_in_cells || 0), 0);
  let status = 'verde';
  if (summary.shipped_at) {
    status = 'vermelho';
  } else if (openInCells > 0) {
    status = 'rosa';
  } else if (isReturnedWithoutProductionLifecycle(summary.lifecycle_type)) {
    status = 'azul';
  } else if (Number(summary.total_counted || 0) >= Number(summary.total_pieces || 0) && Number(summary.total_pieces || 0) > 0) {
    status = 'azul';
  } else if (summary.has_open_occurrence) {
    status = 'amarelo';
  }

  db.prepare('UPDATE ops SET status_color = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(status, opId);
}

function validateOp(form) {
  const errors = [];
  const f23Mode = form.f23_mode || 'externo';
  const brandName = String(form.brand || '').trim();
  const collectionName = String(form.collection_name || '').trim();
  if (!form.op_number) errors.push('Informe o número da OP.');
  else if (!/^\d{7}-\d{3}$/.test(String(form.op_number).trim())) errors.push('Número da OP fora do padrão: use 7 dígitos + "-" + 3 dígitos (ex.: 1801772-001).');
  if (!form.product_name) errors.push('Informe o produto.');
  if (!brandName) errors.push('Selecione uma marca cadastrada.');
  if (brandName && !findBrandByName(brandName)) errors.push('Marca inválida: cadastre a marca antes no módulo Cadastros.');
  if (!collectionName) errors.push('Informe a coleção da OP.');
  if (collectionName && !findCollectionByName(collectionName)) errors.push('Coleção inválida: cadastre a coleção antes no módulo Cadastros.');
  if (!form.total_pieces || Number(form.total_pieces) <= 0) errors.push('Quantidade total inválida.');
  if (form.minutes_f21 === undefined || form.minutes_f21 === '' || Number(form.minutes_f21) < 0) errors.push('Minutos F21 inválidos.');
  if (f23Mode === 'interno' && (form.minutes_f23 === undefined || form.minutes_f23 === '')) errors.push('Minutos F23 são obrigatórios quando F23 é interno.');
  return errors;
}

function handleCreateOp(form, res) {
  // Padrão do número: 7 dígitos ganham "-001" (ex.: 1801772 -> 1801772-001)
  if (form.op_number) {
    const digits = String(form.op_number).replace(/\D/g, '');
    form.op_number = digits.length === 10 ? `${digits.slice(0, 7)}-${digits.slice(7)}` : normalizeOpNumberInput(form.op_number);
  }
  const errors = validateOp(form);
  if (errors.length) {
    return sendHtml(res, renderOpForm(form, errors.join(' '), form._role || 'adm'), 422);
  }

  try {
    const matchedBrand = findBrandByName(form.brand);
    const matchedCollection = findCollectionByName(form.collection_name);
    db.prepare(`
      INSERT INTO ops (
        barcode, op_number, product_name, op_type, brand, collection_name, pilot_mode, appliance, total_pieces,
        minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, notes, delivery_date
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      form.barcode || null,
      form.op_number.trim(),
      form.product_name.trim(),
      form.op_type || 'producao',
      matchedBrand.name,
      matchedCollection?.name || null,
      String(form.pilot_mode || '').trim() || null,
      String(form.appliance || '').trim() || null,
      Number(form.total_pieces),
      Number(form.minutes_f21),
      Number(form.minutes_f22 || 0),
      form.f23_mode || 'externo',
      form.f23_mode === 'interno' ? Number(form.minutes_f23) : null,
      form.entry_date || today(),
      form.notes || null,
      /^\d{4}-\d{2}-\d{2}$/.test(String(form.delivery_date || '')) ? form.delivery_date : null
    );
    const id = db.prepare('SELECT last_insert_rowid() AS id').get().id;
    recalculateOpStatus(id);
    redirect(res, `/ops/${id}?notice=${encodeURIComponent('OP cadastrada com sucesso.')}`);
  } catch (error) {
    sendHtml(res, renderOpForm(form, `Erro ao salvar OP: ${error.message}`, form._role || 'adm'), 422);
  }
}

function sanitizeEmployeeDates(form) {
  return {
    startDate: form.start_date || null,
    terminationDate: form.termination_date || null
  };
}

function validateEmployee(form) {
  if (!String(form.registration_code || '').trim() || !String(form.full_name || '').trim()) return 'Informe registro e nome completo.';
  const { startDate, terminationDate } = sanitizeEmployeeDates(form);
  // Colaboradora ativa (sem rescisão): cadastro completo obrigatório
  if (!terminationDate) {
    const missing = [];
    if (!startDate) missing.push('data de admissão');
    if (!form.birth_date) missing.push('data de nascimento');
    if (!String(form.job_role || '').trim()) missing.push('função');
    if (!Number(form.work_schedule_id || 0)) missing.push('jornada');
    if (!normalizePhone(form.phone)) missing.push('telefone (WhatsApp)');
    if (missing.length) return `Preencha: ${missing.join(', ')}.`;
  }
  if (startDate && terminationDate && terminationDate < startDate) {
    return 'A data de rescisão não pode ser anterior à data de início.';
  }
  const phone = normalizePhone(form.phone);
  if (phone && (phone.length < 10 || phone.length > 11)) return 'Telefone inválido: informe DDD + número (ex.: (47) 99999-9999).';
  return '';
}

function handleCreateEmployee(form, res) {
  const validationError = validateEmployee(form);
  if (validationError) {
    return sendHtml(res, renderEmployeeList({}, form, validationError), 422);
  }

  const { startDate, terminationDate } = sanitizeEmployeeDates(form);

  const birthDate = form.birth_date || null;
  const jobRole = form.job_role || null;
  try {
    db.prepare('INSERT INTO employees (registration_code, full_name, birth_date, start_date, termination_date, job_role, notes, work_schedule_id, phone, target_percent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(form.registration_code.trim(), form.full_name.trim(), birthDate, startDate, terminationDate, jobRole, form.notes || null, Number(form.work_schedule_id || 0) || null, normalizePhone(form.phone), parseEmployeeTarget(form.target_percent));
    employeeTargetCache.delete(getActiveDb());
    redirect(res, `/employees?notice=${encodeURIComponent('Colaborador cadastrado com sucesso.')}`);
  } catch (error) {
    const msg = error.message.includes('UNIQUE')
      ? 'Já existe um colaborador cadastrado com esse código de registro.'
      : `Erro ao salvar colaborador: ${error.message}`;
    sendHtml(res, renderEmployeeList({}, form, msg), 422);
  }
}

function handleUpdateEmployee(employeeId, form, res) {
  const validationError = validateEmployee(form);
  if (validationError) {
    const query = `?error=${encodeURIComponent(validationError)}&edit=${employeeId}`;
    return redirect(res, `/employees${query}`);
  }

  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  if (!employee) {
    return redirect(res, `/employees?error=${encodeURIComponent('Colaborador não encontrado.')}`);
  }

  const birthDate = form.birth_date || null;
  const jobRole = form.job_role || null;
  const { startDate, terminationDate } = sanitizeEmployeeDates(form);

  try {
    db.prepare(`
      UPDATE employees
      SET registration_code = ?,
          full_name = ?,
          birth_date = ?,
          start_date = ?,
          termination_date = ?,
          job_role = ?,
          notes = ?,
          work_schedule_id = ?,
          phone = ?,
          target_percent = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(form.registration_code.trim(), form.full_name.trim(), birthDate, startDate, terminationDate, jobRole, form.notes || null, Number(form.work_schedule_id || 0) || null, normalizePhone(form.phone), parseEmployeeTarget(form.target_percent), employeeId);
    employeeTargetCache.delete(getActiveDb());
    redirect(res, `/employees?notice=${encodeURIComponent('Colaborador atualizado com sucesso.')}`);
  } catch (error) {
    const msg = error.message.includes('UNIQUE')
      ? 'Já existe um colaborador cadastrado com esse código de registro.'
      : `Erro ao atualizar colaborador: ${error.message}`;
    redirect(res, `/employees?error=${encodeURIComponent(msg)}&edit=${employeeId}`);
  }
}

function handleCreateProduction(form, res) {
  const mode = form.mode === 'quick' ? 'quick' : 'default';
  const keepEmployee = form.keep_employee === '1' ? '1' : '0';
  const employeeId = Number(form.employee_id);
  const producedQuantity = Number(form.produced_quantity);
  const productionDate = form.production_date || today();
  const typedOpNumber = String(form.op_number || '').trim();
  const opId = mode === 'quick' ? Number(getOpByNumber(typedOpNumber)?.id || 0) : Number(form.op_id);

  const redirectQuery = new URLSearchParams({
    mode: mode === 'quick' ? 'quick' : 'lista',
    production_date: productionDate
  });
  if (keepEmployee === '1') redirectQuery.set('keep_employee', '1');
  if (employeeId) redirectQuery.set('employee_id', String(employeeId));

  if (!employeeId || !opId || !producedQuantity || producedQuantity <= 0) {
    return sendHtml(res, renderProductionForm(form, 'Preencha colaborador, OP e quantidade produzida.', '', getRequestRole()), 422);
  }
  const dateError = checkLaunchDate(productionDate, getRequestRole());
  if (dateError) return sendHtml(res, renderProductionForm(form, dateError, '', getRequestRole()), 422);

  const op = db.prepare('SELECT * FROM ops WHERE id = ?').get(opId);
  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  if (!op || !employee) {
    return sendHtml(res, renderProductionForm(form, 'OP ou colaborador não encontrado.'), 404);
  }

  if (getCurrentCellTransfer(opId)) {
    return sendHtml(res, renderProductionForm(form, 'Esta OP está em célula. Faça o retorno da célula antes de lançar produção normal.'), 422);
  }

  const totals = db.prepare(`
    SELECT
      COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0), 0) AS produced_total,
      COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS problem_total
  `).get(opId, opId);
  const futureTotal = Number(totals.produced_total || 0) + Number(totals.problem_total || 0) + producedQuantity;
  const defaultLaunchMinutes = round3(Number(op.minutes_f21 || 0));
  const enteredLaunchMinutes = String(form.used_minutes_f21 || '').trim();
  const effectiveLaunchMinutes = enteredLaunchMinutes !== '' ? round3(Number(enteredLaunchMinutes)) : defaultLaunchMinutes;
  const metrics = calculateProductionLaunchMetrics(op, producedQuantity, effectiveLaunchMinutes, productionDate);

  if (Number.isNaN(effectiveLaunchMinutes) || effectiveLaunchMinutes <= 0) {
    return sendHtml(res, renderProductionForm(form, 'Informe um minuto F21 válido para o lançamento.'), 422);
  }

  if (futureTotal > op.total_pieces) {
    const excess = futureTotal - op.total_pieces;
    return sendHtml(
      res,
      renderProductionForm(
        { ...form, op_id: opId, op_number: op.op_number },
        `Lançamento bloqueado: a OP ultrapassaria o limite em ${excess} peça(s). O sistema não permite saldo negativo nem quantidade acima do total da OP.`
      ),
      422
    );
  }

  const remainingPieces = Math.max(Number(op.total_pieces || 0) - futureTotal, 0);

  let message = `Lançamento salvo para ${op.op_number}. Normal: ${fmtNum(metrics.normalMinutes, 3)} min · Extra: ${fmtNum(metrics.extraMinutes, 3)} min · Total: ${fmtNum(metrics.totalMinutes, 3)} min.`;
  if (futureTotal >= Number(op.total_pieces || 0) && Number(op.total_pieces || 0) > 0) {
    message += ' A OP atingiu o total de peças consideradas e ficou azul.';
  } else {
    message += ` Faltam ${remainingPieces} peça(s) para concluir a OP.`;
  }

  db.prepare(`
    INSERT INTO op_daily_productions (
      op_id, employee_id, production_date, produced_quantity, used_minutes_f21, normal_minutes, extra_minutes, produced_minutes,
      extra_time_id, extra_reason_snapshot, extra_description_snapshot, extra_effective_date_snapshot, extra_minutes_per_piece_snapshot,
      counts_for_prize
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    opId,
    employeeId,
    productionDate,
    producedQuantity,
    effectiveLaunchMinutes,
    metrics.normalMinutes,
    metrics.extraMinutes,
    metrics.totalMinutes,
    metrics.extraSnapshot.extra_time_id,
    metrics.extraSnapshot.extra_reason_snapshot,
    metrics.extraSnapshot.extra_description_snapshot,
    metrics.extraSnapshot.extra_effective_date_snapshot,
    metrics.extraSnapshot.extra_minutes_per_piece_snapshot,
    resolveCountsForPrize(form, employee, productionDate)
  );

  recalculateOpStatus(opId);
  redirectQuery.set('notice', message);
  redirect(res, `/productions/new?${redirectQuery.toString()}`);
}

function handleOpenOccurrence(opId, form, res) {
  if (!form.description) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Descreva a ocorrência.')}`);
  }
  db.prepare('INSERT INTO op_occurrences (op_id, description) VALUES (?, ?)').run(opId, form.description.trim());
  recalculateOpStatus(opId);
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent('Ocorrência registrada. Status da OP alterado para amarelo, se ainda não estava concluída.')}`);
}

function handleCreateOpProblemItem(opId, form, res) {
  const op = db.prepare('SELECT * FROM ops WHERE id = ? AND is_reversed = 0').get(Number(opId));
  if (!op) return redirect(res, `/ops?error=${encodeURIComponent('OP não encontrada.')}`);

  const quantity = Number(form.quantity || 0);
  const reason = String(form.reason || '').trim();
  const notes = String(form.notes || '').trim();
  const problemDate = form.problem_date || today();

  if (!quantity || quantity <= 0 || !Number.isInteger(quantity)) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe uma quantidade inteira válida para peça com problema.')}`);
  }
  if (!reason) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe o motivo da peça com problema.')}`);
  }

  const totals = db.prepare(`
    SELECT
      COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0), 0) AS produced_total,
      COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS problem_total
  `).get(opId, opId);

  const futureTotal = Number(totals.produced_total || 0) + Number(totals.problem_total || 0) + quantity;
  if (futureTotal > Number(op.total_pieces || 0)) {
    const excess = futureTotal - Number(op.total_pieces || 0);
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent(`Registro bloqueado: a OP ultrapassaria o limite em ${excess} peça(s).`)}`);
  }

  db.prepare(`
    INSERT INTO op_problem_items (op_id, problem_date, quantity, reason, notes)
    VALUES (?, ?, ?, ?, ?)
  `).run(opId, problemDate, quantity, reason, notes || null);

  recalculateOpStatus(opId);
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent('Peça com problema registrada com sucesso.')}`);
}

function handleReturnRemainingWithoutSewing(opId, form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const op = getOpDetail(Number(opId))?.op;
  if (!op) return redirect(res, `/ops?error=${encodeURIComponent('OP não encontrada.')}`);
  const remaining = Number(op.remaining_quantity || 0);
  const reason = String(form.reason || '').trim();
  const notes = String(form.notes || '').trim();
  const problemDate = form.problem_date || today();
  const billingDecision = String(form.billing_decision || '').trim();

  if (remaining <= 0) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Essa OP já está sem saldo para devolução sem costura.')}`);
  }
  if (!reason) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe o motivo da devolução sem costurar.')}`);
  }
  if (!['bill', 'return'].includes(billingDecision)) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe se essa devolução gera cobrança ou não.')}`);
  }

  db.prepare(`
    INSERT INTO op_problem_items (op_id, problem_date, quantity, reason, notes)
    VALUES (?, ?, ?, ?, ?)
  `).run(Number(opId), problemDate, remaining, `Devolução sem costurar: ${reason}`, notes || null);

  if (billingDecision === 'return') {
    db.prepare(`
      UPDATE ops
      SET lifecycle_type = 'devolvida_sem_producao',
          returned_without_production_at = CURRENT_TIMESTAMP,
          return_reason = ?,
          is_billed = 0,
          billed_at = NULL,
          billing_notes = COALESCE(NULLIF(billing_notes, ''), ?),
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(reason, notes || null, Number(opId));
  } else {
    db.prepare(`
      UPDATE ops
      SET lifecycle_type = 'normal',
          is_billed = 0,
          billed_at = NULL,
          billing_notes = COALESCE(NULLIF(billing_notes, ''), ?),
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).run(notes || null, Number(opId));
  }

  recalculateOpStatus(Number(opId));
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent(`Saldo restante da OP devolvido sem costura (${remaining} peça(s)).`)}`);
}

function getCurrentUser() {
  const auth = getRequestAuth();
  if (!auth?.user?.username) return null;
  return db.prepare('SELECT id, username, full_name, role FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1').get(auth.user.username) || null;
}

function parseOpBatchText(value) {
  const rawItems = String(value || '')
    .split(/\r?\n|,|;|\t|\s+/)
    .map(item => item.trim())
    .filter(Boolean);
  const seen = new Set();
  const duplicates = new Set();
  const opNumbers = [];
  for (const item of rawItems) {
    const normalized = item.toUpperCase();
    if (seen.has(normalized)) {
      duplicates.add(normalized);
      continue;
    }
    seen.add(normalized);
    opNumbers.push(normalized);
  }
  return { opNumbers, duplicates: Array.from(duplicates) };
}

function findOpsByNumbers(opNumbers = []) {
  const normalized = Array.from(new Set(opNumbers.map(item => String(item || '').trim().toUpperCase()).filter(Boolean)));
  if (!normalized.length) return [];
  const placeholders = normalized.map(() => '?').join(', ');
  return db.prepare(`
    SELECT id, op_number, product_name, status_color, shipped_at, is_billed, billed_at, billing_notes, lifecycle_type, is_reversed
    FROM ops
    WHERE UPPER(op_number) IN (${placeholders})
    ORDER BY op_number COLLATE NOCASE
  `).all(...normalized);
}

function markOpsAsBilled(opIds = [], billedAt = today(), notes = '', userId = null) {
  const ids = Array.from(new Set(opIds.map(Number).filter(Boolean)));
  const batchReference = `COBR-${Date.now()}`;
  if (!ids.length) return { batchReference };
  const updateStmt = db.prepare(`
    UPDATE ops
    SET is_billed = 1,
        billed_at = ?,
        billing_notes = ?,
        billed_by_user_id = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `);
  const historyStmt = db.prepare(`
    INSERT INTO op_billing_history (op_id, billed_at, notes, batch_reference, created_by_user_id)
    VALUES (?, ?, ?, ?, ?)
  `);
  db.exec('BEGIN');
  try {
    for (const id of ids) {
      updateStmt.run(billedAt, notes || null, userId, id);
      historyStmt.run(id, billedAt, notes || null, batchReference, userId);
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  return { batchReference };
}

function handleBillingReconciliation(form, res, role) {
  if (!canAccessCadastros(role)) {
    return sendHtml(res, renderBillingReconciliationPage(form, 'Acesso restrito ao perfil Administrador e Operacional.', null, role), 403);
  }
  const billedAt = String(form.billed_at || today()).trim() || today();
  const notes = String(form.notes || '').trim();
  const parsed = parseOpBatchText(form.op_numbers || '');
  if (!parsed.opNumbers.length) {
    return sendHtml(res, renderBillingReconciliationPage(form, 'Informe pelo menos uma OP para conciliar.', null, role), 422);
  }

  const foundRows = findOpsByNumbers(parsed.opNumbers);
  const foundMap = new Map(foundRows.map(item => [String(item.op_number || '').toUpperCase(), item]));
  const result = {
    billedAt,
    notes,
    batchReference: '',
    submittedCount: parsed.opNumbers.length,
    duplicateNumbers: parsed.duplicates,
    processed: [],
    alreadyBilled: [],
    invalid: []
  };

  for (const opNumber of parsed.opNumbers) {
    const row = foundMap.get(opNumber);
    if (!row || Number(row.is_reversed || 0)) {
      result.invalid.push({ op_number: opNumber, reason: 'OP não encontrada.' });
      continue;
    }
    if (isReturnedWithoutProductionLifecycle(row.lifecycle_type)) {
      result.invalid.push({ op_number: row.op_number, reason: 'OP devolvida sem produção.' });
      continue;
    }
    if (Number(row.is_billed || 0)) {
      result.alreadyBilled.push({ op_number: row.op_number, billed_at: row.billed_at || '', notes: row.billing_notes || '' });
      continue;
    }
    result.processed.push({ id: row.id, op_number: row.op_number, product_name: row.product_name, status_color: row.status_color });
  }

  if (!result.processed.length) {
    return sendHtml(res, renderBillingReconciliationPage(form, 'Nenhuma OP nova pôde ser marcada como cobrada.', result, role), 422);
  }

  const user = getCurrentUser();
  const batch = markOpsAsBilled(result.processed.map(item => item.id), billedAt, notes, user?.id || null);
  result.batchReference = batch.batchReference;
  return sendHtml(res, renderBillingReconciliationPage({ billed_at: billedAt, notes, op_numbers: '' }, '', result, role));
}

function renderBillingReconciliationPage(values = {}, error = '', result = null, role = 'adm') {
  const recent = db.prepare(`
    SELECT bh.id, bh.billed_at, bh.notes, bh.batch_reference, o.id AS op_id, o.op_number, o.product_name
    FROM op_billing_history bh
    JOIN ops o ON o.id = bh.op_id
    ORDER BY bh.id DESC
    LIMIT 20
  `).all();
  const resultSummary = result ? `
    <section class="panel">
      <div class="panel-header"><h3>Resultado da conciliação</h3><span class="hint">Lote ${escapeHtml(result.batchReference || '-')}</span></div>
      <div class="shipment-summary-grid">
        <article class="mini-card"><span>Recebidas</span><strong>${result.submittedCount}</strong></article>
        <article class="mini-card"><span>Marcadas</span><strong>${result.processed.length}</strong></article>
        <article class="mini-card"><span>Já cobradas</span><strong>${result.alreadyBilled.length}</strong></article>
        <article class="mini-card"><span>Inválidas</span><strong>${result.invalid.length}</strong></article>
        <article class="mini-card"><span>Duplicadas</span><strong>${result.duplicateNumbers.length}</strong></article>
        <article class="mini-card"><span>Data</span><strong>${escapeHtml(result.billedAt)}</strong></article>
      </div>
      <div class="two-columns">
        <section>
          <h4>Marcadas como cobradas</h4>
          <table>
            <thead><tr><th>OP</th><th>Produto</th><th>Status atual</th></tr></thead>
            <tbody>
              ${result.processed.map(item => `<tr><td><a href="/ops/${item.id}">${escapeHtml(item.op_number)}</a></td><td>${escapeHtml(item.product_name)}</td><td>${statusBadge(item.status_color)}</td></tr>`).join('') || '<tr><td colspan="3">Nenhuma OP marcada.</td></tr>'}
            </tbody>
          </table>
        </section>
        <section>
          <h4>Não processadas</h4>
          <table>
            <thead><tr><th>OP</th><th>Motivo</th></tr></thead>
            <tbody>
              ${[
                ...result.alreadyBilled.map(item => `<tr><td>${escapeHtml(item.op_number)}</td><td>Já cobrada em ${escapeHtml(nowPt(item.billed_at))}</td></tr>`),
                ...result.invalid.map(item => `<tr><td>${escapeHtml(item.op_number)}</td><td>${escapeHtml(item.reason)}</td></tr>`),
                ...result.duplicateNumbers.map(item => `<tr><td>${escapeHtml(item)}</td><td>Duplicada no texto informado.</td></tr>`)
              ].join('') || '<tr><td colspan="2">Nenhuma inconsistência.</td></tr>'}
            </tbody>
          </table>
        </section>
      </div>
    </section>
  ` : '';

  const content = `
    <section class="page-header">
      <div><h2>Conciliação de cobrança</h2><p>Informe as OPs cobradas em lote, valide a base e mantenha o histórico de cobranças.</p></div>
      <a class="btn secondary" href="/ops?billing_status=not_billed">Ver OPs não cobradas</a>
    </section>
    <form class="panel stack-form" method="post" action="/billing-reconciliation">
      <div class="inline-form">
        <label>Data da cobrança<input type="date" name="billed_at" value="${escapeHtml(values.billed_at || today())}" required /></label>
        <label>Observação<input name="notes" value="${escapeHtml(values.notes || '')}" placeholder="Opcional" /></label>
      </div>
      <label>OPs cobradas (uma por linha, ou separadas por espaço, vírgula ou ponto e vírgula)
        <textarea name="op_numbers" rows="12" required placeholder="Ex.:&#10;OP-1001&#10;OP-1002&#10;OP-1003">${escapeHtml(values.op_numbers || '')}</textarea>
      </label>
      <div class="actions"><button class="btn" type="submit">Validar e marcar como cobradas</button></div>
      <p class="hint">Regras: OP inexistente entra como inválida; OP devolvida fica fora da cobrança; OP já cobrada não é remarcada; as válidas recebem data/observação e entram no histórico.</p>
    </form>
    ${resultSummary}
    <section class="panel">
      <div class="panel-header"><h3>Últimos históricos de cobrança</h3><span class="hint">Acompanhamento rápido do que foi conciliado.</span></div>
      <table>
        <thead><tr><th>Data</th><th>OP</th><th>Produto</th><th>Observação</th><th>Lote</th></tr></thead>
        <tbody>
          ${recent.map(item => `<tr><td>${escapeHtml(nowPt(item.billed_at))}</td><td><a href="/ops/${item.op_id}">${escapeHtml(item.op_number)}</a></td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(item.notes || '-')}</td><td>${escapeHtml(item.batch_reference || '-')}</td></tr>`).join('') || '<tr><td colspan="5">Nenhum histórico de cobrança ainda.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'Conciliação de cobrança', content, error, notice: result?.processed?.length ? `${result.processed.length} OP(s) marcadas como cobradas.` : '', role });
}

function handleConcludeOccurrence(opId, occurrenceId, form, res) {
  if (!form.conclusion_reason) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe a justificativa de conclusão da ocorrência.')}`);
  }
  db.prepare(`
    UPDATE op_occurrences
    SET is_concluded = 1,
        concluded_at = CURRENT_TIMESTAMP,
        conclusion_reason = ?
    WHERE id = ? AND op_id = ?
  `).run(form.conclusion_reason.trim(), occurrenceId, opId);
  recalculateOpStatus(opId);
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent('Ocorrência concluída.')}`);
}

function normalizeIds(value) {
  if (Array.isArray(value)) return value.map(item => Number(item)).filter(Boolean);
  if (!value) return [];
  return [Number(value)].filter(Boolean);
}

function getShipmentCreatePreview(opIds) {
  if (!opIds.length) return { rows: [], totals: emptyShipmentTotals() };
  const placeholders = opIds.map(() => '?').join(', ');
  const rows = db.prepare(`
    SELECT id, op_number, product_name, brand, collection_name, pilot_mode, appliance, op_type, total_pieces, minutes_f21, minutes_f22, f23_mode, minutes_f23, entry_date, status_color, shipped_at
    FROM ops
    WHERE id IN (${placeholders})
    ORDER BY op_number
  `).all(...opIds).map(op => ({ ...op, ...calculateOpShipmentMinutes(op) }));
  return { rows, totals: summarizeShipmentTotals(rows) };
}

function emptyShipmentTotals() {
  return {
    opCount: 0,
    productionMinutes: 0,
    sampleMinutes: 0,
    sewingMinutes: 0,
    postSewingMinutes: 0,
    totalMinutes: 0
  };
}

function summarizeShipmentTotals(rows) {
  return rows.reduce((acc, row) => {
    acc.opCount += 1;
    acc.sewingMinutes = round2(acc.sewingMinutes + row.sewing_minutes);
    acc.postSewingMinutes = round2(acc.postSewingMinutes + row.post_sewing_minutes);
    acc.totalMinutes = round2(acc.totalMinutes + row.total_shipment_minutes);
    if (row.op_type === 'mostruario') {
      acc.sampleMinutes = round2(acc.sampleMinutes + row.total_shipment_minutes);
    } else {
      acc.productionMinutes = round2(acc.productionMinutes + row.total_shipment_minutes);
    }
    return acc;
  }, emptyShipmentTotals());
}

function nextShipmentNumber(shipmentDate) {
  const compactDate = String(shipmentDate || today()).replace(/-/g, '');
  const prefix = `EMB-${compactDate}-`;
  const last = db.prepare(`
    SELECT shipment_number
    FROM shipments
    WHERE is_reversed = 0 AND shipment_number LIKE ?
    ORDER BY shipment_number DESC
    LIMIT 1
  `).get(`${prefix}%`);
  const lastSequence = last ? Number(String(last.shipment_number).slice(prefix.length)) || 0 : 0;
  return `${prefix}${String(lastSequence + 1).padStart(3, '0')}`;
}

function handleCreateShipment(form, res) {
  const opIds = normalizeIds(form.op_ids);
  const shipmentDate = form.shipment_date || today();
  const notes = form.notes || null;

  if (!opIds.length) {
    return sendHtml(res, renderShipmentCreatePage({ q: form.q || '', op_number: form.op_number || '', entry_date: form.entry_date || '', shipment_date: shipmentDate }, 'Selecione pelo menos uma OP apta para gerar o embarque.'), 422);
  }

  const selected = getShipmentCreatePreview(opIds).rows;
  if (selected.length !== opIds.length) {
    return sendHtml(res, renderShipmentCreatePage({ q: form.q || '', op_number: form.op_number || '', entry_date: form.entry_date || '', shipment_date: shipmentDate }, 'Uma ou mais OPs selecionadas não foram encontradas.'), 422);
  }

  const invalid = selected.filter(op => op.status_color !== 'azul' || op.shipped_at);
  if (invalid.length) {
    return sendHtml(res, renderShipmentCreatePage({ q: form.q || '', op_number: form.op_number || '', entry_date: form.entry_date || '', shipment_date: shipmentDate }, 'Só é permitido embarcar OPs azuis e ainda não embarcadas.'), 422);
  }

  const totals = summarizeShipmentTotals(selected);
  const shipmentNumber = nextShipmentNumber(shipmentDate);

  try {
    db.exec('BEGIN');
    db.prepare(`
      INSERT INTO shipments (
        shipment_number, shipment_date, notes, total_ops,
        production_minutes, sample_minutes, sewing_minutes, post_sewing_minutes, total_minutes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      shipmentNumber,
      shipmentDate,
      notes,
      totals.opCount,
      totals.productionMinutes,
      totals.sampleMinutes,
      totals.sewingMinutes,
      totals.postSewingMinutes,
      totals.totalMinutes
    );

    const shipmentId = db.prepare('SELECT last_insert_rowid() AS id').get().id;
    const insertItem = db.prepare(`
      INSERT INTO shipment_items (
        shipment_id, op_id, op_number, op_type, total_pieces,
        sewing_minutes, post_sewing_minutes, total_minutes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const updateOp = db.prepare('UPDATE ops SET shipped_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?');

    for (const op of selected) {
      insertItem.run(
        shipmentId,
        op.id,
        op.op_number,
        op.op_type,
        op.total_pieces,
        op.sewing_minutes,
        op.post_sewing_minutes,
        op.total_shipment_minutes
      );
      updateOp.run(shipmentDate, op.id);
      recalculateOpStatus(op.id);
    }

    db.exec('COMMIT');
    redirect(res, `/shipments/${shipmentId}?notice=${encodeURIComponent(`Embarque ${shipmentNumber} gerado com ${totals.opCount} OP(s).`)}`);
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    sendHtml(res, renderShipmentCreatePage({ q: form.q || '', op_number: form.op_number || '', entry_date: form.entry_date || '', shipment_date: shipmentDate }, `Erro ao gerar embarque: ${error.message}`), 422);
  }
}

function getShipmentList(filters = {}) {
  let sql = `
    SELECT
      s.*,
      COUNT(si.id) AS item_count
    FROM shipments s
    LEFT JOIN shipment_items si ON si.shipment_id = s.id
    WHERE s.is_reversed = 0
  `;
  const params = [];
  if (filters.start_date) {
    sql += ' AND s.shipment_date >= ?';
    params.push(filters.start_date);
  }
  if (filters.end_date) {
    sql += ' AND s.shipment_date <= ?';
    params.push(filters.end_date);
  }
  if (filters.q) {
    sql += ' AND (s.shipment_number LIKE ? OR EXISTS (SELECT 1 FROM shipment_items x WHERE x.shipment_id = s.id AND x.op_number LIKE ?))';
    params.push(`%${filters.q}%`, `%${filters.q}%`);
  }
  sql += ' GROUP BY s.id ORDER BY s.shipment_date DESC, s.created_at DESC';
  const rows = db.prepare(sql).all(...params);

  const totals = rows.reduce((acc, row) => {
    acc.shipments += 1;
    acc.ops += Number(row.total_ops || 0);
    acc.productionMinutes = round2(acc.productionMinutes + Number(row.production_minutes || 0));
    acc.sampleMinutes = round2(acc.sampleMinutes + Number(row.sample_minutes || 0));
    acc.sewingMinutes = round2(acc.sewingMinutes + Number(row.sewing_minutes || 0));
    acc.postSewingMinutes = round2(acc.postSewingMinutes + Number(row.post_sewing_minutes || 0));
    acc.totalMinutes = round2(acc.totalMinutes + Number(row.total_minutes || 0));
    return acc;
  }, {
    shipments: 0,
    ops: 0,
    productionMinutes: 0,
    sampleMinutes: 0,
    sewingMinutes: 0,
    postSewingMinutes: 0,
    totalMinutes: 0
  });

  return { rows, totals };
}

function getShipmentDetail(id) {
  const shipment = db.prepare('SELECT * FROM shipments WHERE id = ?').get(id);
  if (!shipment) return null;
  const items = db.prepare(`
    SELECT
      si.*,
      o.product_name,
      o.brand,
      o.collection_name,
      o.pilot_mode,
      o.appliance,
      o.minutes_f21,
      o.f23_mode,
      o.minutes_f23,
      o.entry_date,
      o.shipped_at,
      o.lifecycle_type
    FROM shipment_items si
    LEFT JOIN ops o ON o.id = si.op_id
    WHERE si.shipment_id = ?
    ORDER BY si.op_number
  `).all(id);
  return { shipment, items };
}

// ===================== FILA EM DIAS (T1.4) =====================
// Fila = Σ saldo × F21 das OPs em aberto (verde, amarela, rosa). Capacidade = média de minutos
// lançados por dia útil nos últimos 10 dias úteis. Dias de fila = fila ÷ capacidade.
function addBusinessDays(fromIso, count) {
  const cursor = new Date(`${fromIso}T00:00:00Z`);
  let added = 0;
  let guard = 0;
  while (added < count && guard < 3650) {
    cursor.setUTCDate(cursor.getUTCDate() + 1);
    if (isBusinessDay(iso(cursor))) added += 1;
    guard += 1;
  }
  return iso(cursor);
}

function getQueueForecast() {
  const open = getOpList({}).filter(op => ['verde', 'amarelo', 'rosa'].includes(op.status_color) && !op.shipped_at && !isReturnedWithoutProductionLifecycle(op.lifecycle_type));
  const queueMinutes = round2(open.reduce((sum, op) => sum + Math.max(Number(op.remaining_quantity || 0), 0) * Number(op.minutes_f21 || 0), 0));
  const queuePieces = open.reduce((sum, op) => sum + Math.max(Number(op.remaining_quantity || 0), 0), 0);
  const days = [];
  const cursor = new Date(`${today()}T00:00:00Z`);
  let guard = 0;
  while (days.length < 10 && guard < 120) {
    cursor.setUTCDate(cursor.getUTCDate() - 1);
    if (isBusinessDay(iso(cursor))) days.push(iso(cursor));
    guard += 1;
  }
  const produced = days.length ? db.prepare(`
    SELECT COALESCE(SUM(p.produced_minutes), 0) AS minutes
    FROM op_daily_productions p JOIN ops o ON o.id = p.op_id
    WHERE p.is_reversed = 0 AND COALESCE(o.is_reversed, 0) = 0 AND p.production_date BETWEEN ? AND ?
  `).get(days[days.length - 1], days[0]).minutes : 0;
  const dailyCapacity = days.length ? round2(Number(produced || 0) / days.length) : 0;
  const queueDays = dailyCapacity > 0 ? round2(queueMinutes / dailyCapacity) : null;
  const finishDate = queueDays !== null ? addBusinessDays(today(), Math.ceil(queueDays)) : '';
  return { openOps: open.length, queuePieces, queueMinutes, dailyCapacity, queueDays, finishDate, sampleDays: days.length };
}

function renderQueueForecastCard() {
  const f = getQueueForecast();
  const level = f.queueDays === null ? '' : (f.queueDays > 15 ? 'queue-high' : (f.queueDays < 5 ? 'queue-low' : 'queue-ok'));
  return `
    <section class="panel section-gap queue-card ${level}">
      <div class="queue-main">
        <span>Fila atual</span>
        <strong>${f.queueDays === null ? 'Sem base' : `${fmtNum(f.queueDays, 1)} dias úteis`}</strong>
        <small>${f.finishDate ? `Término estimado: ${formatDatePtBr(f.finishDate)}` : 'Sem produção nos últimos 10 dias úteis para estimar.'}</small>
      </div>
      <div class="queue-stats">
        <div><span>OPs em aberto</span><strong>${f.openOps}</strong></div>
        <div><span>Peças na fila</span><strong>${fmtNum(f.queuePieces, 0)}</strong></div>
        <div><span>Minutos na fila</span><strong>${fmtNum(f.queueMinutes, 0)}</strong></div>
        <div><span>Capacidade/dia</span><strong>${fmtNum(f.dailyCapacity, 0)} min</strong><small>média dos últimos ${f.sampleDays} dias úteis</small></div>
      </div>
    </section>`;
}

function renderDashboard(query, role = 'adm') {
  const defaultMonthBase = getPeriodRange('month', today()).start;
  const currentDay = today();
  const firstDayCurrentMonth = `${currentDay.slice(0, 8)}01`;
  const employeeStartDate = query.employee_start_date || defaultMonthBase;
  const employeeEndDate = query.employee_end_date || currentDay;
  const mostruarioCustomFilter = Boolean(query.mostruario_start_date || query.mostruario_end_date);
  const producaoCustomFilter = Boolean(query.producao_start_date || query.producao_end_date);
  const mostruarioStartDate = query.mostruario_start_date || firstDayCurrentMonth;
  const mostruarioEndDate = query.mostruario_end_date || currentDay;
  const producaoStartDate = query.producao_start_date || firstDayCurrentMonth;
  const producaoEndDate = query.producao_end_date || currentDay;
  const brand = query.brand || '';
  const notice = query.notice || '';

  const employeeData = getDashboardData('day', currentDay, '', '', employeeStartDate, employeeEndDate, false);
  const employeeOptions = db.prepare('SELECT id, registration_code, full_name FROM employees ORDER BY full_name ASC').all();
  const selectedEmployeeId = Number(query.employee_id || 0);
  const displayedEmployees = selectedEmployeeId ? employeeData.employees.filter(employee => employee.id === selectedEmployeeId) : employeeData.employees;
  const dailyEmployeeRows = getEmployeeDailyResultRows(employeeStartDate, employeeEndDate, selectedEmployeeId ? String(selectedEmployeeId) : '');
  const dailyTrackingData = getDailyTrackingData(currentDay, 'month', selectedEmployeeId ? String(selectedEmployeeId) : '', '', '');
  const dailyTrackingTopRows = dailyTrackingData.employeeSummaries.slice(0, 5);
  const hourlyDashboardData = getHourlyDashboardData(currentDay);
  const dashboardGraphRows = [...displayedEmployees].sort((a, b) => {
    const pctDiff = Number(b.efficiency_percent || 0) - Number(a.efficiency_percent || 0);
    if (pctDiff !== 0) return pctDiff;
    return Number(b.produced_minutes || 0) - Number(a.produced_minutes || 0);
  });
  const totalDisplayedMinutes = round2(displayedEmployees.reduce((sum, employee) => sum + Number(employee.produced_minutes || 0), 0));
  const operatorCount = displayedEmployees.length;
  const companyActiveDays = displayedEmployees.reduce((total, employee) => total + employee.active_days, 0);
  const companyAvailableMinutes = round2(companyActiveDays * baseMinutesDay());
  const companyAverageMinutes = operatorCount ? round2(totalDisplayedMinutes / operatorCount) : 0;
  const companyPercent = companyAvailableMinutes > 0 ? round2((totalDisplayedMinutes / companyAvailableMinutes) * 100) : 0;
  const employeeLaunchBreakdown = db.prepare(`
    SELECT
      o.op_type,
      ROUND(COALESCE(SUM(p.produced_quantity * (COALESCE(p.used_minutes_f21,0) + COALESCE(o.minutes_f22,0))), 0), 2) AS minutes
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    WHERE p.is_reversed = 0
      AND o.is_reversed = 0
      AND COALESCE(o.lifecycle_type, 'normal') NOT IN ('nao_industrializada', 'devolvida_sem_producao')
      AND p.production_date BETWEEN ? AND ?
    GROUP BY o.op_type
  `).all(employeeData.range.start, employeeData.range.end);
  const minutesProducao = round2(employeeLaunchBreakdown.find(item => item.op_type === 'producao')?.minutes || 0);
  const minutesMostruario = round2(employeeLaunchBreakdown.find(item => item.op_type === 'mostruario')?.minutes || 0);
  const minutesTotal = round2(minutesProducao + minutesMostruario);
  const companyClass = companyPercent >= targetPercent() ? 'company-good' : 'company-bad';
  const companyLabel = companyPercent >= targetPercent() ? 'Meta mínima atingida' : 'Abaixo da meta mínima';
  const companyAction = companyPercent >= targetPercent() ? 'Seguimos dentro da meta geral da empresa.' : `Precisamos de plano de ação para elevar a eficiência geral acima de ${tp()}%.`;
  const mostruarioData = getDashboardData('day', today(), 'mostruario', brand, mostruarioStartDate, mostruarioEndDate, mostruarioCustomFilter);
  const producaoData = getDashboardData('day', today(), 'producao', brand, producaoStartDate, producaoEndDate, producaoCustomFilter);
  const availableBrands = [...new Set([
    ...getDashboardBrands('mostruario'),
    ...getDashboardBrands('producao')
  ])].sort((a, b) => a.localeCompare(b));
  const dashboardPinkRows = db.prepare(`
    SELECT
      o.id,
      o.op_number,
      o.product_name,
      o.brand,
      o.status_color,
      (SELECT c.name FROM op_cell_transfers t JOIN sewing_cells c ON c.id = t.cell_id WHERE t.op_id = o.id AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0) ORDER BY t.id DESC LIMIT 1) AS active_cell_name,
      COALESCE(SUM(p.produced_quantity), 0) AS total_produced,
      o.total_pieces - COALESCE(SUM(p.produced_quantity), 0) AS remaining,
      ROUND((o.total_pieces - COALESCE(SUM(p.produced_quantity), 0)) * MAX(COALESCE(o.minutes_f21,0) - COALESCE(o.minutes_f22,0), 0), 3) AS remaining_minutes
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.is_reversed = 0
      AND o.status_color = 'rosa'
      AND EXISTS (SELECT 1 FROM op_cell_transfers t WHERE t.op_id = o.id AND COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0))
    GROUP BY o.id
    ORDER BY o.op_number ASC
  `).all();

  const content = `
    <section class="page-header">
      <div>
        <h2>Dashboard</h2>
        <p>Leitura em tempo real do que já foi lançado hoje por hora.</p>
      </div>
    </section>

    ${renderQueueForecastCard()}

    <section class="panel section-gap" id="hourly-dashboard-panel">
      <div class="panel-header"><h3>Resultado do dia — lançamentos por hora</h3><span class="hint">Leitura em tempo real do que já foi lançado hoje por hora.</span></div>
      <div class="shipment-summary-grid section-gap">
        <article class="mini-card"><span>Costureiras com hora lançada</span><strong id="hourly-total-seamstresses">${hourlyDashboardData.seamstressCount}</strong></article>
        <article class="mini-card"><span>Peças lançadas hoje</span><strong id="hourly-total-quantity">${hourlyDashboardData.totalQuantity}</strong></article>
        <article class="mini-card"><span>Minutos lançados hoje</span><strong id="hourly-total-minutes">${fmtNum(hourlyDashboardData.totalMinutes, 3)}</strong></article>
        <article class="mini-card"><span>% geral até agora</span><strong id="hourly-total-percent">0,00%</strong></article>
      </div>
      ${(() => {
        const absent = getEmployeesWithoutLaunch(currentDay);
        const labels = { atestado: 'Atestado', ferias: 'Férias', folga: 'Folga', afastamento: 'Afastamento', falta: 'Falta', outro: 'Outro' };
        if (!absent.active) return '';
        return `<details class="absent-box ${absent.list.length ? 'has-absent' : ''}" ${absent.list.length && absent.list.length <= 12 ? 'open' : ''}>
          <summary><strong>${absent.list.length}</strong> de ${absent.active} colaboradora(s) sem lançamento hoje${absent.withAbsence ? ` · ${absent.withAbsence} com ausência registrada` : ''}</summary>
          ${absent.list.length ? `<div class="absent-list">${absent.list.map(i => `<span class="absent-chip ${i.absence ? 'is-justified' : ''}">${escapeHtml(i.name)}${i.absence ? ` <small>${escapeHtml(labels[i.absence] || i.absence)}</small>` : ''}</span>`).join('')}</div>
          <p class="hint">Sem nenhum lançamento hoje (por hora, hora zero ou lançamento rápido). Ausências registradas aparecem marcadas. <a href="/closures">Tratar no fechamento</a></p>` : '<p class="hint">Todas as colaboradoras ativas já têm lançamento hoje.</p>'}
        </details>`;
      })()}
      ${hourlyDashboardData.rows.length ? `<div class="hourly-list-head"><span>#</span><span>Colaboradora</span><span>Andamento</span><span>%</span><span>Peças</span><span>Min</span><span>Horas</span><span>Início</span></div>` : ''}
      <div class="hourly-list" id="hourly-dashboard-list">
        ${hourlyDashboardData.rows.map(item => `<div class="hourly-row" data-hourly-card data-first-hour="${item.first_hour_number}" data-minutes="${item.total_minutes}"><span class="hourly-rank" data-hourly-rank></span><strong class="hourly-name" title="${escapeHtml(item.full_name)}">${escapeHtml(item.full_name)}${item.termination_date && item.termination_date <= currentDay ? ' <span style="color:#ef4444;font-weight:600;">(Inativa)</span>' : ''}</strong><span class="hourly-bar"><span data-hourly-bar></span></span><strong class="hourly-pct" data-hourly-percent>0,00%</strong><span>${item.total_quantity}</span><span>${fmtNum(item.total_minutes, 0)}</span><span>${item.launched_hours}h</span><span>${escapeHtml(item.first_hour_slot || '-')}</span></div>`).join('') || '<p class="hint">Nenhum lançamento por hora hoje.</p>'}
      </div>
      <script>
        (() => {
          const panel = document.getElementById('hourly-dashboard-panel');
          if (!panel) return;
          const cards = Array.from(panel.querySelectorAll('[data-hourly-card]'));
          if (!cards.length) return;
          const currentHour = new Date().getHours();
          let totalMinutes = 0;
          let totalExpectedBase = 0;
          cards.forEach(card => {
            const firstHour = Number(card.dataset.firstHour || 0);
            const minutes = Number(card.dataset.minutes || 0);
            // Eficiência do dia sempre sobre a base cheia do dia
            const expectedBase = ${baseMinutesDay()};
            const pct = expectedBase > 0 ? (minutes / expectedBase) * 100 : 0;
            const pctText = card.querySelector('[data-hourly-percent]');
            const bar = card.querySelector('[data-hourly-bar]');
            const color = pct < 40 ? '#ef4444' : (pct >= ${targetPercent()} ? '#16a34a' : '#f59e0b');
            if (pctText) { pctText.textContent = pct.toFixed(1).replace('.', ',') + '%'; pctText.style.color = color; }
            if (bar) {
              bar.style.width = Math.max(2, Math.min(pct, 100)) + '%';
              bar.style.background = color;
            }
            totalMinutes += minutes;
            totalExpectedBase += expectedBase;
          });
          cards.sort((a, b) => {
            const ap = Number((a.querySelector('[data-hourly-percent]')?.textContent || '0').replace('%', '').replace(',', '.'));
            const bp = Number((b.querySelector('[data-hourly-percent]')?.textContent || '0').replace('%', '').replace(',', '.'));
            return bp - ap;
          }).forEach((card, i) => { const r = card.querySelector('[data-hourly-rank]'); if (r) r.textContent = i + 1; panel.querySelector('#hourly-dashboard-list').appendChild(card); });
          const totalPct = totalExpectedBase > 0 ? (totalMinutes / totalExpectedBase) * 100 : 0;
          const totalPctEl = document.getElementById('hourly-total-percent');
          if (totalPctEl) totalPctEl.textContent = totalPct.toFixed(2).replace('.', ',') + '%';
        })();
      </script>
    </section>

    <div class="dashboard-columns">
      <div class="dashboard-col-left">
        <section class="panel">
          <h3>Resultado por colaborador no período</h3>
          <form class="filters inline-form" method="get" action="/">
            <label>Data inicial
              <input type="date" name="employee_start_date" value="${escapeHtml(employeeStartDate)}" />
            </label>
            <label>Data final
              <input type="date" name="employee_end_date" value="${escapeHtml(employeeEndDate)}" />
            </label>
            <label>Colaborador
              <select name="employee_id">
                <option value="">Todos os funcionários</option>
                ${employeeOptions.map(employee => `<option value="${employee.id}" ${selectedEmployeeId === employee.id ? 'selected' : ''}>${escapeHtml(employee.registration_code)} - ${escapeHtml(employee.full_name)}</option>`).join('')}
              </select>
            </label>
            <input type="hidden" name="brand" value="${escapeHtml(brand)}" />
            <button class="btn" type="submit">Aplicar</button>
          </form>
          <section class="panel section-gap" style="margin:0 0 16px 0;">
            <div class="panel-header"><h3>Gráfico inicial de resultado por costureira</h3><span class="hint">Modelo visual principal do dashboard.</span></div>
            <div style="display:grid;gap:10px;">
              ${dashboardGraphRows.map((emp, index) => {
                const pct = round2(emp.efficiency_percent || 0);
                const barWidth = Math.max(2, Math.min(pct, 100));
                const needsAttention = pct < 40;
                const isInactive = emp.termination_date && emp.termination_date <= employeeData.range.end;
                const tone = needsAttention ? '#ef4444' : (pct >= 60 ? '#22c55e' : '#f59e0b');
                const bg = needsAttention ? 'rgba(239,68,68,.10)' : (pct >= 60 ? 'rgba(34,197,94,.10)' : 'rgba(245,158,11,.10)');
                return `<div style="display:grid;grid-template-columns:44px 1fr 84px;gap:12px;align-items:center;padding:12px 14px;border-radius:14px;background:${bg};border:1px solid rgba(148,163,184,.18);"><div style="display:flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:999px;background:white;font-weight:700;color:${tone};">${index + 1}</div><div><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;"><strong style="font-size:15px;">${escapeHtml(emp.full_name)}</strong>${isInactive ? '<span style="font-size:12px;color:#ef4444;font-weight:700;">INATIVA</span>' : ''}</div><div style="margin-top:8px;background:rgba(15,23,42,.08);border-radius:999px;height:10px;overflow:hidden;"><div style="width:${barWidth}%;height:10px;background:${tone};"></div></div><div style="margin-top:6px;font-size:12px;color:#64748b;">${fmtNum(round2(emp.produced_minutes), 2)} min · ${needsAttention ? 'Necessita atenção' : 'Dentro da leitura esperada'}${isInactive ? ` · Inativa desde ${formatDatePtBr(emp.termination_date)}` : ''}</div></div><div style="text-align:right;"><div style="font-size:22px;font-weight:800;color:${tone};line-height:1;">${fmtNum(pct, 2)}%</div><div style="font-size:12px;color:#64748b;margin-top:4px;">resultado</div></div></div>`;
              }).join('') || '<p class="hint">Nenhuma costureira ativa no período.</p>'}
            </div>
          </section>
          <table>
            <thead><tr><th>Matrícula</th><th>Nome</th><th>Dias ativos</th><th>Minutos</th><th>Base</th><th>Percentual</th></tr></thead>
            <tbody>
              ${displayedEmployees.map(emp => {
                const pct = round2(emp.efficiency_percent || 0);
                const cls = pct < 50 ? 'perf-low' : (pct <= 60 ? 'perf-mid' : 'perf-high');
                const isInactive = emp.termination_date && emp.termination_date <= employeeData.range.end;
                return `<tr><td>${escapeHtml(emp.registration_code)}</td><td>${escapeHtml(emp.full_name)}${isInactive ? ' <span style="color:#ef4444;font-weight:600;">(Inativa)</span>' : ''}</td><td>${emp.active_days}</td><td>${fmtNum(round2(emp.produced_minutes), 2)}</td><td>${fmtNum(round2(emp.available_minutes), 2)}</td><td class="${cls}">${fmtNum(pct, 2)}%</td></tr>`;
              }).join('') || '<tr><td colspan="6">Nenhum colaborador ativo no período.</td></tr>'}
            </tbody>
          </table>
          <div class="shipment-summary-grid section-gap">
            <article class="mini-card"><span>Minutos produção</span><strong>${fmtNum(minutesProducao, 2)}</strong></article>
            <article class="mini-card"><span>Minutos mostruário</span><strong>${fmtNum(minutesMostruario, 2)}</strong></article>
            <article class="mini-card"><span>Total filtrado</span><strong>${fmtNum(minutesTotal, 2)}</strong></article>
          </div>
          <div class="company-total ${companyClass}">
            <span>Eficiência até o corte (${escapeHtml(formatDatePtBr(employeeData.efficiencyCutoff))})</span>
            <strong>${fmtNum(companyPercent, 2)}%</strong>
            <small>${companyLabel}</small>
            <p>Média geral: ${fmtNum(companyAverageMinutes, 2)} minutos por operador (${operatorCount} operadores ativos no período).</p><p>Base ativa total: ${fmtNum(companyAvailableMinutes, 2)} minutos (${companyActiveDays} dias ativos somados).</p>
            <p>${companyAction}</p>
          </div>
          <p class="subtle-note"><strong>Período:</strong> ${escapeHtml(formatDatePtBr(employeeData.range.start))} até ${escapeHtml(formatDatePtBr(employeeData.range.end))} · minutos e base contados até o corte (último dia útil anterior), igual ao Acompanhamento diário.</p>
          <p class="subtle-note">Filtro exclusivo para resultados de colaboradores: ${escapeHtml(formatDatePtBr(employeeData.range.start))} até ${escapeHtml(formatDatePtBr(employeeData.range.end))}.${selectedEmployeeId ? ` Colaborador filtrado: ${escapeHtml(employeeOptions.find(item => item.id === selectedEmployeeId)?.full_name || '')}.` : ''}</p>
        </section>

        <section class="panel section-gap tracking-panel-highlight">
          <div class="panel-header"><h3>Acompanhamento diário do mês operacional</h3><a class="btn secondary" href="/acompanhamento/diario${getDailyTrackingQueryString(dailyTrackingData.filters)}">Abrir painel completo</a></div>
          <p class="hint"><strong>Período ${periodLabel()}:</strong> ${formatDatePtBr(dailyTrackingData.range.start)} até ${formatDatePtBr(dailyTrackingData.range.end)} · <strong>corte atual:</strong> ${formatDatePtBr(dailyTrackingData.progressEnd)}.</p>
          <div class="shipment-summary-grid section-gap">
            <article class="mini-card"><span>Minutos acumulados</span><strong>${fmtNum(dailyTrackingData.totals.producedMinutes, 2)}</strong></article>
            <article class="mini-card tracking-status-good"><span>Já em ${tp()}%+</span><strong>${dailyTrackingData.totals.reachedCurrentTarget}</strong></article>
            <article class="mini-card tracking-status-risk"><span>Abaixo de ${tp()}%</span><strong>${dailyTrackingData.totals.belowCurrentTarget}</strong></article>
            <article class="mini-card"><span>% atual geral</span><strong>${fmtNum(dailyTrackingData.totals.currentPercent, 2)}%</strong></article>
          </div>
          <div class="tracking-dashboard-summary">
            <div>
              <span class="hint">Resumo gerencial do acompanhamento</span>
              <p><strong>Líder:</strong> ${dailyTrackingData.management.leader ? `${escapeHtml(dailyTrackingData.management.leader.full_name)} (${fmtNum(dailyTrackingData.management.leader.current_percent, 2)}%)` : 'sem dados'}.</p>
              <p><strong>Próxima ação:</strong> ${escapeHtml(dailyTrackingData.management.nextActionLabel)}</p>
            </div>
            <a class="btn secondary" href="/premios/producao${getProductionPrizeQueryString(dailyTrackingData.filters)}">Ver prêmio de produção</a>
          </div>
          <table>
            <thead><tr><th>Rank</th><th>Registro</th><th>Colaboradora</th><th>Status</th><th>Dias úteis</th><th>Minutos</th><th>% até o corte</th><th>Faltam p/ meta</th></tr></thead>
            <tbody>
              ${dailyTrackingTopRows.map(emp => `<tr class="${emp.status_meta.rowClass}"><td><strong>#${emp.ranking_position}</strong></td><td>${escapeHtml(emp.registration_code)}</td><td>${escapeHtml(emp.full_name)}</td><td><span class="${emp.status_meta.badgeClass}">${emp.status_meta.label}</span></td><td>${emp.business_days_elapsed}/${emp.business_days_total}</td><td>${fmtNum(emp.produced_minutes, 2)}</td><td class="${emp.status_meta.textClass}">${fmtNum(emp.current_percent, 2)}%</td><td>${fmtNum(emp.minutes_to_current_target, 2)}</td></tr>`).join('') || '<tr><td colspan="8">Nenhum colaborador ativo no mês operacional atual.</td></tr>'}
            </tbody>
          </table>
        </section>

        <section class="panel section-gap">
          <div class="panel-header"><h3>Resultado diário detalhado</h3><span class="hint">Dia a dia do período filtrado antes de gerar qualquer relatório.</span></div>
          <table>
            <thead><tr><th>Data</th><th>Registro</th><th>Colaborador</th><th>Peças</th><th>Minutos</th><th>Base</th><th>Percentual</th></tr></thead>
            <tbody>
              ${dailyEmployeeRows.map(row => {
                const pct = round2(row.result_percent || 0);
                const cls = pct < 50 ? 'perf-low' : (pct <= 60 ? 'perf-mid' : 'perf-high');
                return `<tr><td>${formatDatePtBr(row.production_date)}</td><td>${escapeHtml(row.registration_code)}</td><td>${escapeHtml(row.full_name)}</td><td>${row.produced_quantity}</td><td>${fmtNum(round2(row.produced_minutes), 2)}</td><td>${fmtNum(round2(row.available_minutes), 2)}</td><td class="${cls}">${fmtNum(pct, 2)}%</td></tr>`;
              }).join('') || '<tr><td colspan="7">Nenhum dia útil encontrado no filtro informado.</td></tr>'}
            </tbody>
          </table>
        </section>
      </div>

      <div class="dashboard-col-right">
        <section class="panel">
          <h3>Filtros dos blocos de OPs</h3>
          <p class="subtle-note">Mostruário e Produção agora trabalham com filtros independentes. Cada bloco usa seu próprio intervalo de datas, iniciando por padrão do dia 01 do mês atual até hoje.</p>
        </section>

        <section class="panel">
          <h3>MOSTRUARIOS</h3>
          <form class="filters inline-form" method="get" action="/">
            <label>Data inicial
              <input type="date" name="mostruario_start_date" value="${escapeHtml(mostruarioStartDate)}" />
            </label>
            <label>Data final
              <input type="date" name="mostruario_end_date" value="${escapeHtml(mostruarioEndDate)}" />
            </label>
            <input type="hidden" name="producao_start_date" value="${escapeHtml(producaoStartDate)}" />
            <input type="hidden" name="producao_end_date" value="${escapeHtml(producaoEndDate)}" />
            <input type="hidden" name="employee_start_date" value="${escapeHtml(employeeStartDate)}" />
            <input type="hidden" name="employee_end_date" value="${escapeHtml(employeeEndDate)}" />
            <input type="hidden" name="employee_id" value="${escapeHtml(selectedEmployeeId ? String(selectedEmployeeId) : '')}" />
            <button class="btn" type="submit">Aplicar filtro Mostruário</button>
          </form>
          <p class="hint">${mostruarioCustomFilter ? `Embarques filtrados de ${escapeHtml(formatDatePtBr(mostruarioData.range.start))} até ${escapeHtml(formatDatePtBr(mostruarioData.range.end))}.` : `Resultados filtrados de ${escapeHtml(formatDatePtBr(mostruarioData.range.start))} até ${escapeHtml(formatDatePtBr(mostruarioData.range.end))}.`}</p>
          <div class="cards">
            <article class="card status-card bg-green"><span>Verde (a produzir)</span><strong>${fmtNum(mostruarioData.cards.greenSewingMinutes, 2)}</strong><small>Minutos</small></article>
            <article class="card status-card bg-yellow"><span>Amarelo (com pendência)</span><strong>${fmtNum(mostruarioData.cards.yellowSewingMinutes, 2)}</strong><small>Minutos</small></article>
            <article class="card status-card bg-blue"><span>Azul (finalizados)</span><strong>${fmtNum(mostruarioData.cards.blueSewingMinutes, 2)}</strong><small>Minutos</small></article>
            <article class="card status-card bg-pink"><span>Rosa (em célula)</span><strong>${fmtNum(mostruarioData.cards.pinkSewingMinutes, 2)}</strong><small>Minutos fora do fluxo comum</small></article>
            <article class="card status-card bg-red"><span>Vermelho (embarcado)</span><strong>${fmtNum(mostruarioData.cards.redSewingMinutes, 2)}</strong><small>Minutos</small></article>
          </div>
        </section>

        <section class="panel">
          <h3>PRODUCAO</h3>
          <form class="filters inline-form" method="get" action="/">
            <label>Data inicial
              <input type="date" name="producao_start_date" value="${escapeHtml(producaoStartDate)}" />
            </label>
            <label>Data final
              <input type="date" name="producao_end_date" value="${escapeHtml(producaoEndDate)}" />
            </label>
            <input type="hidden" name="mostruario_start_date" value="${escapeHtml(mostruarioStartDate)}" />
            <input type="hidden" name="mostruario_end_date" value="${escapeHtml(mostruarioEndDate)}" />
            <input type="hidden" name="employee_start_date" value="${escapeHtml(employeeStartDate)}" />
            <input type="hidden" name="employee_end_date" value="${escapeHtml(employeeEndDate)}" />
            <input type="hidden" name="employee_id" value="${escapeHtml(selectedEmployeeId ? String(selectedEmployeeId) : '')}" />
            <button class="btn" type="submit">Aplicar filtro Produção</button>
          </form>
          <p class="hint">${producaoCustomFilter ? `Embarques filtrados de ${escapeHtml(formatDatePtBr(producaoData.range.start))} até ${escapeHtml(formatDatePtBr(producaoData.range.end))}.` : `Resultados filtrados de ${escapeHtml(formatDatePtBr(producaoData.range.start))} até ${escapeHtml(formatDatePtBr(producaoData.range.end))}.`}</p>
          <div class="cards">
            <article class="card status-card bg-green"><span>Verde (a produzir)</span><strong>${fmtNum(producaoData.cards.greenSewingMinutes, 2)}</strong><small>Minutos</small></article>
            <article class="card status-card bg-yellow"><span>Amarelo (com pendência)</span><strong>${fmtNum(producaoData.cards.yellowSewingMinutes, 2)}</strong><small>Minutos</small></article>
            <article class="card status-card bg-blue"><span>Azul (finalizados)</span><strong>${fmtNum(producaoData.cards.blueSewingMinutes, 2)}</strong><small>Minutos</small></article>
            <article class="card status-card bg-pink"><span>Rosa (em célula)</span><strong>${fmtNum(producaoData.cards.pinkSewingMinutes, 2)}</strong><small>Minutos fora do fluxo comum</small></article>
            <article class="card status-card bg-red"><span>Vermelho (embarcado)</span><strong>${fmtNum(producaoData.cards.redSewingMinutes, 2)}</strong><small>Minutos</small></article>
          </div>
        </section>

        <section class="panel">
          <h3>Mostruario</h3>
          <table>
            <thead><tr><th>Marca</th><th>A produzir</th><th>Em aberto</th><th>Finalizado</th><th>Em célula</th><th>Embarcado</th></tr></thead>
            <tbody>
              ${mostruarioData.brands.map(item => `<tr><td>${escapeHtml(item.brand)}</td><td>${fmtNum(Number(item.green_minutes), 2)}</td><td>${fmtNum(Number(item.yellow_minutes), 2)}</td><td>${fmtNum(Number(item.blue_minutes), 2)}</td><td>${fmtNum(Number(item.pink_minutes || 0), 2)}</td><td>${fmtNum(Number(item.red_minutes), 2)}</td></tr>`).join('') || '<tr><td colspan="6">Sem dados de mostruário.</td></tr>'}
            </tbody>
          </table>
        </section>

        <section class="panel">
          <h3>Produção</h3>
          <table>
            <thead><tr><th>Marca</th><th>A produzir</th><th>Em aberto</th><th>Finalizado</th><th>Em célula</th><th>Embarcado</th></tr></thead>
            <tbody>
              ${producaoData.brands.map(item => `<tr><td>${escapeHtml(item.brand)}</td><td>${fmtNum(Number(item.green_minutes), 2)}</td><td>${fmtNum(Number(item.yellow_minutes), 2)}</td><td>${fmtNum(Number(item.blue_minutes), 2)}</td><td>${fmtNum(Number(item.pink_minutes || 0), 2)}</td><td>${fmtNum(Number(item.red_minutes), 2)}</td></tr>`).join('') || '<tr><td colspan="6">Sem dados de produção.</td></tr>'}
            </tbody>
          </table>
        </section>

        <section class="panel">
          <div class="panel-header"><h3>OPs em célula no filtro atual</h3><span class="hint">Acompanhamento rápido das OPs rosas antes do retorno.</span></div>
          <table>
            <thead><tr><th>OP</th><th>Produto</th><th>Marca</th><th>Status</th><th>Célula</th><th>Saldo peças</th><th>Saldo minutos</th></tr></thead>
            <tbody>
              ${dashboardPinkRows.map(op => `<tr><td><a href="/ops/${op.id}">${escapeHtml(op.op_number)}</a></td><td>${escapeHtml(op.product_name)}</td><td>${escapeHtml(op.brand || '-')}</td><td>${statusBadge(op.status_color)}</td><td>${escapeHtml(op.active_cell_name || '-')}</td><td>${op.remaining}</td><td>${fmtNum(Number(op.remaining_minutes || 0), 3)}</td></tr>`).join('') || '<tr><td colspan="7">Nenhuma OP rosa neste filtro.</td></tr>'}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  `;
  return pageLayout({ title: 'Dashboard', content, notice, role });
}

function statusBadge(status) {
  return `<span class="badge ${escapeHtml(status)}">${escapeHtml(status)}</span>`;
}

function isReturnedWithoutProductionLifecycle(lifecycleType) {
  return ['nao_industrializada', 'devolvida_sem_producao'].includes(String(lifecycleType || 'normal'));
}

function billingStatusLabel(op) {
  if (isReturnedWithoutProductionLifecycle(op.lifecycle_type)) {
    return '<span class="badge azul">Devolvida</span>';
  }
  if (Number(op.is_billed || 0)) {
    return `<span class="badge azul">Cobrada em ${escapeHtml(nowPt(op.billed_at))}</span>`;
  }
  return '<span class="badge badge-neutral">Não cobrada</span>';
}

function billingStatusText(op) {
  if (isReturnedWithoutProductionLifecycle(op.lifecycle_type)) return 'Devolvida';
  return Number(op.is_billed || 0) ? `Cobrada em ${escapeHtml(nowPt(op.billed_at))}` : 'Não cobrada';
}

function lifecycleFlowLabel(lifecycleType) {
  if (isReturnedWithoutProductionLifecycle(lifecycleType)) return 'Devolvida sem produção';
  return 'Fluxo normal';
}

function lifecycleBadge(lifecycleType) {
  if (isReturnedWithoutProductionLifecycle(lifecycleType)) {
    return '<span class="badge azul">devolvida</span>';
  }
  return '';
}

function canMarkOpWithoutIndustrialization(op, role = 'adm') {
  return isAdminRole(role)
    && !Number(op.is_reversed || 0)
    && !op.shipped_at
    && !isReturnedWithoutProductionLifecycle(op.lifecycle_type)
    && Number(op.produced_quantity || 0) <= 0;
}

function renderWithoutIndustrializationShortcut(op, role = 'adm', redirectTo = '/ops', compact = false) {
  if (!canMarkOpWithoutIndustrialization(op, role)) return '';
  const formClass = compact ? 'stack-form compact without-industrialization-shortcut' : 'stack-form without-industrialization-shortcut';
  const buttonClass = compact ? 'btn secondary btn-danger-soft' : 'btn secondary';
  return `
    <form method="post" action="/estornos/op/without-industrialization" class="${formClass}" onsubmit="return confirm('Confirmar baixa sem costurar desta OP? Essa ação libera a OP para embarque sem contar costura.');">
      <input type="hidden" name="id" value="${op.id}" />
      <input type="hidden" name="redirect_to" value="${escapeHtml(redirectTo)}" />
      <label class="full">Motivo obrigatório<textarea name="reason" rows="${compact ? 2 : 3}" required placeholder="Explique por que a OP será devolvida sem costurar / não industrializar."></textarea></label>
      <div class="actions">
        <button class="${buttonClass}" type="submit">Devolução sem costurar</button>
      </div>
      <p class="hint">Somente administrador: zera o saldo da operação, marca a OP como devolvida, não soma como costurada e mantém a liberação para embarque sem minutos.</p>
    </form>
  `;
}

function getSourceLabel(notes) {
  const text = String(notes || '');
  if (text.includes('Importado da aba PRODUÇÕES')) return 'Produções';
  if (text.includes('Importado da aba MOSTRUARIOS')) return 'Mostruários';
  if (text.includes('Importado da aba O.PS NO PÓS F23')) return 'OPs no Pós';
  return 'Manual';
}

function renderOpForm(values = {}, error = '', role = 'adm') {
  const brands = getBrandList();
  const collections = getCollectionList();
  const brandOptions = brands.map(item => `<option value="${escapeHtml(item.name)}"></option>`).join('');
  const collectionOptions = collections.map(item => `<option value="${escapeHtml(item.name)}"></option>`).join('');
  const content = `
    <section class="page-header"><div><h2>Cadastro de OPs</h2><p>Nova OP inicia verde. F23 interno exige minutos F23. Marca precisa existir previamente em Cadastros.</p></div></section>
    <form class="panel form-grid" method="post" action="/ops">
      <label>Barcode<input name="barcode" value="${escapeHtml(values.barcode || '')}" /></label>
      <label>Número da OP *<input name="op_number" required data-op-mask maxlength="11" inputmode="numeric" pattern="\\d{7}-\\d{3}" title="Padrão: 7 dígitos + -001 (ex.: 1801772-001)" placeholder="1801772-001" value="${escapeHtml(values.op_number || '')}" /></label>
      <script>
        (() => {
          const el = document.querySelector('[data-op-mask]');
          if (!el) return;
          const mask = v => { const d = String(v || '').replace(/\\D/g, '').slice(0, 10); return d.length > 7 ? d.slice(0, 7) + '-' + d.slice(7) : d; };
          el.addEventListener('input', () => { el.value = mask(el.value); });
          el.addEventListener('blur', () => { const d = el.value.replace(/\\D/g, ''); if (d.length === 7) el.value = d + '-001'; });
        })();
      </script>
      <label>Produto<input name="product_name" required value="${escapeHtml(values.product_name || '')}" /></label>
      <label>Flag/tipo
        <select name="op_type">
          <option value="producao" ${(values.op_type || '') === 'producao' ? 'selected' : ''}>Produção</option>
          <option value="mostruario" ${(values.op_type || '') === 'mostruario' ? 'selected' : ''}>Mostruário</option>
        </select>
      </label>
      <label>Marca
        <input name="brand" list="brand-suggestions" required autocomplete="off" value="${escapeHtml(values.brand || '')}" placeholder="Digite ou selecione uma marca cadastrada" />
        <datalist id="brand-suggestions">${brandOptions}</datalist>
      </label>
      <label>Coleção
        <input name="collection_name" list="collection-suggestions" autocomplete="off" value="${escapeHtml(values.collection_name || '')}" placeholder="Digite ou selecione uma coleção cadastrada" required />
        <datalist id="collection-suggestions">${collectionOptions}</datalist>
      </label>
      <label>Piloto
        <select name="pilot_mode">
          <option value="">Não informado</option>
          <option value="com piloto" ${(values.pilot_mode || 'com piloto') === 'com piloto' ? 'selected' : ''}>Com piloto</option>
          <option value="sem piloto" ${values.pilot_mode === 'sem piloto' ? 'selected' : ''}>Sem piloto</option>
        </select>
      </label>
      <label>Aparelho<input name="appliance" value="${escapeHtml(values.appliance || '')}" placeholder="Ex.: 2 agulhas" /></label>
      <label>Quantidade total<input type="number" min="1" name="total_pieces" required value="${escapeHtml(values.total_pieces || '')}" /></label>
      <label>Minutos F21<input type="number" min="0" step="0.001" name="minutes_f21" required value="${escapeHtml(values.minutes_f21 || '')}" /></label>
      <label>Minutos F22<input type="number" min="0" step="0.001" name="minutes_f22" value="${escapeHtml(values.minutes_f22 || '')}" /></label>
      <label>F23
        <select name="f23_mode">
          <option value="interno" ${(values.f23_mode || 'interno') === 'interno' ? 'selected' : ''}>Interno</option>
          <option value="externo" ${(values.f23_mode || '') === 'externo' ? 'selected' : ''}>Externo</option>
        </select>
      </label>
      <label>Minutos F23<input type="number" min="0" step="0.001" name="minutes_f23" value="${escapeHtml(values.minutes_f23 || '')}" /></label>
      <label>Data de entrada<input type="date" name="entry_date" value="${escapeHtml(values.entry_date || today())}" /></label>
      <label>Data de entrega<input type="date" name="delivery_date" value="${escapeHtml(values.delivery_date || '')}" /></label>
      <label class="full">Observações<textarea name="notes" rows="4">${escapeHtml(values.notes || '')}</textarea></label>
      <div class="full actions"><button class="btn" type="submit">Salvar OP</button>${isAdminRole(role) ? '<a class="btn secondary" href="/cadastros">Abrir cadastros</a>' : ''}<a class="btn secondary" href="/ops">Ver consulta de OPs</a></div>
      <p class="hint full">Bloqueio ativo: não é permitido cadastrar OP com marca fora da base de Marcas. Cadastre antes em <strong>Cadastros</strong>.</p>
    </form>
  `;
  return pageLayout({ title: 'Nova OP', content, error, role });
}

// Tempo extra cadastrado/alterado depois do lançamento: refaz os minutos extras dos lançamentos
// da OP a partir da data informada (minutos normais ficam como foram lançados).
function recalculateExtraMinutesForOp(opId, fromDate) {
  const op = db.prepare('SELECT * FROM ops WHERE id = ?').get(Number(opId));
  if (!op || !fromDate) return { rows: 0, delta: 0 };
  let rows = 0;
  let delta = 0;
  for (const table of ['op_daily_productions', 'hourly_productions']) {
    const list = db.prepare(`SELECT * FROM ${table} WHERE op_id = ? AND is_reversed = 0 AND production_date >= ?`).all(op.id, fromDate);
    const update = db.prepare(`
      UPDATE ${table}
      SET extra_minutes = ?, produced_minutes = ?, extra_time_id = ?, extra_reason_snapshot = ?,
          extra_description_snapshot = ?, extra_effective_date_snapshot = ?, extra_minutes_per_piece_snapshot = ?
      WHERE id = ?`);
    for (const row of list) {
      const config = getActiveOpExtraTimeForOp(op.id, row.production_date);
      const perPiece = Number(config?.extra_minutes_per_piece || 0);
      const extra = round3(Number(row.produced_quantity || 0) * perPiece);
      if (Math.abs(extra - Number(row.extra_minutes || 0)) < 0.001 && Number(row.extra_time_id || 0) === Number(config?.id || 0)) continue;
      const produced = round3(Number(row.normal_minutes || 0) + extra);
      update.run(extra, produced, config ? config.id : null, config?.reason || null, config?.description || null, config?.effective_date || null, config ? round3(perPiece) : null, row.id);
      if (table === 'op_daily_productions') { rows += 1; delta += extra - Number(row.extra_minutes || 0); }
    }
  }
  return { rows, delta: round2(delta) };
}

function extraRecalcNotice(base, result) {
  return result.rows ? `${base} ${result.rows} lançamento(s) recalculado(s) (${result.delta >= 0 ? '+' : ''}${fmtNum(result.delta, 2)} min).` : base;
}

function getOpExtraTimeById(id) {
  return db.prepare(`
    SELECT et.*, o.op_number, o.product_name, o.op_type
    FROM op_extra_times et
    JOIN ops o ON o.id = et.op_id
    WHERE et.id = ?
    LIMIT 1
  `).get(Number(id)) || null;
}

function getProductionRowsUsingExtraTimeId(id) {
  return db.prepare(`
    SELECT p.id, p.production_date, p.produced_quantity, p.extra_minutes, o.op_number, e.registration_code, e.full_name
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    JOIN employees e ON e.id = p.employee_id
    WHERE p.extra_time_id = ?
      AND p.is_reversed = 0
    ORDER BY p.production_date DESC, p.id DESC
    LIMIT 20
  `).all(Number(id));
}

function getOpExtraTimeRows(filters = {}) {
  const search = String(filters.search || '').trim();
  const where = [];
  const params = [];
  if (search) {
    where.push(`(o.op_number LIKE ? OR o.product_name LIKE ? OR et.reason LIKE ? OR COALESCE(et.description, '') LIKE ?)`);
    params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
  }
  const sql = `
    SELECT
      et.*,
      o.op_number,
      o.product_name,
      o.op_type
    FROM op_extra_times et
    JOIN ops o ON o.id = et.op_id
    ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
    ORDER BY et.effective_date DESC, et.id DESC
    LIMIT 100
  `;
  return db.prepare(sql).all(...params);
}

function getOpExtraReportQueryString(filters = {}) {
  const params = new URLSearchParams();
  if (filters.base_date) params.set('base_date', filters.base_date);
  if (filters.period && filters.period !== 'month') params.set('period', filters.period);
  if (filters.employee_id) params.set('employee_id', filters.employee_id);
  if (filters.start_date) params.set('start_date', filters.start_date);
  if (filters.end_date) params.set('end_date', filters.end_date);
  if (filters.op_number) params.set('op_number', filters.op_number);
  if (filters.op_type) params.set('op_type', filters.op_type);
  const query = params.toString();
  return query ? `?${query}` : '';
}

function getOpExtraTimeReportData(query = {}) {
  const period = ['day', 'week', 'month', 'general', 'custom'].includes(query.period) ? query.period : 'month';
  const baseDate = query.base_date || today();
  const employeeId = Number(query.employee_id || 0);
  const startDate = query.start_date || '';
  const endDate = query.end_date || '';
  const opNumber = String(query.op_number || '').trim();
  const opType = String(query.op_type || '').trim();
  const range = getClosureReportRange(period, baseDate, startDate, endDate);
  const employees = db.prepare(`
    SELECT id, registration_code, full_name
    FROM employees
    ORDER BY full_name ASC
  `).all();

  const where = [
    'p.is_reversed = 0',
    'p.production_date BETWEEN ? AND ?',
    'COALESCE(p.extra_minutes, 0) > 0'
  ];
  const params = [range.start, range.end];
  if (employeeId) {
    where.push('p.employee_id = ?');
    params.push(employeeId);
  }
  if (opNumber) {
    where.push('o.op_number LIKE ?');
    params.push(`%${opNumber}%`);
  }
  if (opType) {
    where.push('o.op_type = ?');
    params.push(opType);
  }

  const rows = db.prepare(`
    SELECT
      p.id,
      p.production_date,
      p.produced_quantity,
      p.normal_minutes,
      p.extra_minutes,
      p.produced_minutes,
      p.used_minutes_f21,
      o.id AS op_id,
      o.op_number,
      o.product_name,
      o.op_type,
      e.id AS employee_id,
      e.registration_code,
      e.full_name,
      COALESCE(p.extra_reason_snapshot, '') AS extra_reason,
      COALESCE(p.extra_description_snapshot, '') AS extra_description,
      p.extra_effective_date_snapshot AS extra_effective_date,
      ROUND(COALESCE(p.extra_minutes_per_piece_snapshot,
        CASE WHEN COALESCE(p.produced_quantity, 0) > 0 THEN p.extra_minutes / p.produced_quantity ELSE 0 END
      ), 3) AS extra_minutes_per_piece
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    JOIN employees e ON e.id = p.employee_id
    WHERE ${where.join(' AND ')}
    ORDER BY p.production_date DESC, p.id DESC
  `).all(...params);

  const byEmployeeMap = new Map();
  const byOpMap = new Map();
  const byDayMap = new Map();
  const summary = {
    launchCount: rows.length,
    employees: 0,
    ops: 0,
    producedQuantity: 0,
    normalMinutes: 0,
    extraMinutes: 0,
    producedMinutes: 0
  };

  for (const row of rows) {
    const qty = Number(row.produced_quantity || 0);
    const normal = Number(row.normal_minutes || 0);
    const extra = Number(row.extra_minutes || 0);
    const total = Number(row.produced_minutes || 0);

    summary.producedQuantity += qty;
    summary.normalMinutes = round2(summary.normalMinutes + normal);
    summary.extraMinutes = round2(summary.extraMinutes + extra);
    summary.producedMinutes = round2(summary.producedMinutes + total);

    const employeeKey = row.employee_id;
    if (!byEmployeeMap.has(employeeKey)) {
      byEmployeeMap.set(employeeKey, {
        employee_id: row.employee_id,
        registration_code: row.registration_code,
        full_name: row.full_name,
        launch_count: 0,
        ops_count: 0,
        produced_quantity: 0,
        normal_minutes: 0,
        extra_minutes: 0,
        produced_minutes: 0,
        op_ids: new Set(),
        last_reason: row.extra_reason || ''
      });
    }
    const employeeItem = byEmployeeMap.get(employeeKey);
    employeeItem.launch_count += 1;
    employeeItem.produced_quantity += qty;
    employeeItem.normal_minutes = round2(employeeItem.normal_minutes + normal);
    employeeItem.extra_minutes = round2(employeeItem.extra_minutes + extra);
    employeeItem.produced_minutes = round2(employeeItem.produced_minutes + total);
    employeeItem.op_ids.add(row.op_id);
    if (!employeeItem.last_reason && row.extra_reason) employeeItem.last_reason = row.extra_reason;

    const opKey = row.op_id;
    if (!byOpMap.has(opKey)) {
      byOpMap.set(opKey, {
        op_id: row.op_id,
        op_number: row.op_number,
        product_name: row.product_name,
        op_type: row.op_type,
        launch_count: 0,
        employees_count: 0,
        produced_quantity: 0,
        normal_minutes: 0,
        extra_minutes: 0,
        produced_minutes: 0,
        reason: row.extra_reason || '',
        employee_ids: new Set()
      });
    }
    const opItem = byOpMap.get(opKey);
    opItem.launch_count += 1;
    opItem.produced_quantity += qty;
    opItem.normal_minutes = round2(opItem.normal_minutes + normal);
    opItem.extra_minutes = round2(opItem.extra_minutes + extra);
    opItem.produced_minutes = round2(opItem.produced_minutes + total);
    opItem.employee_ids.add(row.employee_id);
    if (!opItem.reason && row.extra_reason) opItem.reason = row.extra_reason;

    const dayKey = row.production_date;
    if (!byDayMap.has(dayKey)) {
      byDayMap.set(dayKey, {
        work_date: row.production_date,
        launch_count: 0,
        employees_count: 0,
        ops_count: 0,
        produced_quantity: 0,
        normal_minutes: 0,
        extra_minutes: 0,
        produced_minutes: 0,
        employee_ids: new Set(),
        op_ids: new Set()
      });
    }
    const dayItem = byDayMap.get(dayKey);
    dayItem.launch_count += 1;
    dayItem.produced_quantity += qty;
    dayItem.normal_minutes = round2(dayItem.normal_minutes + normal);
    dayItem.extra_minutes = round2(dayItem.extra_minutes + extra);
    dayItem.produced_minutes = round2(dayItem.produced_minutes + total);
    dayItem.employee_ids.add(row.employee_id);
    dayItem.op_ids.add(row.op_id);
  }

  const byEmployee = Array.from(byEmployeeMap.values()).map(item => ({
    ...item,
    ops_count: item.op_ids.size,
    extra_share_percent: item.produced_minutes > 0 ? round2((item.extra_minutes / item.produced_minutes) * 100) : 0
  })).sort((a, b) => (b.extra_minutes - a.extra_minutes) || (b.produced_minutes - a.produced_minutes) || String(a.full_name).localeCompare(String(b.full_name)));

  const byOp = Array.from(byOpMap.values()).map(item => ({
    ...item,
    employees_count: item.employee_ids.size,
    extra_share_percent: item.produced_minutes > 0 ? round2((item.extra_minutes / item.produced_minutes) * 100) : 0
  })).sort((a, b) => (b.extra_minutes - a.extra_minutes) || String(a.op_number).localeCompare(String(b.op_number)));

  const byDay = Array.from(byDayMap.values()).map(item => ({
    ...item,
    employees_count: item.employee_ids.size,
    ops_count: item.op_ids.size,
    extra_share_percent: item.produced_minutes > 0 ? round2((item.extra_minutes / item.produced_minutes) * 100) : 0
  })).sort((a, b) => a.work_date.localeCompare(b.work_date));

  summary.employees = byEmployee.length;
  summary.ops = byOp.length;
  summary.extraSharePercent = summary.producedMinutes > 0 ? round2((summary.extraMinutes / summary.producedMinutes) * 100) : 0;

  return {
    range,
    filters: {
      base_date: baseDate,
      period,
      employee_id: employeeId ? String(employeeId) : '',
      start_date: startDate,
      end_date: endDate,
      op_number: opNumber,
      op_type: opType
    },
    employees,
    selectedEmployee: employeeId ? employees.find(item => item.id === employeeId) || null : null,
    summary,
    rows,
    byEmployee,
    byOp,
    byDay
  };
}

function renderOpExtraTimeReportPage(query = {}, role = 'adm') {
  const data = getOpExtraTimeReportData(query);
  const filters = data.filters;
  const content = `
    <section class="page-header">
      <div><h2>Tempo extra de OP - relatórios</h2><p>Leitura consolidada do extra aplicado nos lançamentos, sem alterar as regras atuais do cálculo produtivo.</p></div>
      <a class="btn secondary" href="/op-extra-times">Voltar ao cadastro</a>
    </section>

    <form class="panel inline-form" method="get" action="/op-extra-times/report">
      <label>Relatório / visão
        <select name="period" onchange="this.form.submit()">
          <option value="day" ${filters.period === 'day' ? 'selected' : ''}>Diário</option>
          <option value="week" ${filters.period === 'week' ? 'selected' : ''}>Semanal</option>
          <option value="month" ${filters.period === 'month' ? 'selected' : ''}>Mensal operacional</option>
          <option value="general" ${filters.period === 'general' ? 'selected' : ''}>Geral</option>
          <option value="custom" ${filters.period === 'custom' ? 'selected' : ''}>Personalizado</option>
        </select>
      </label>
      <label>Data base<input type="date" name="base_date" value="${escapeHtml(filters.base_date)}" /></label>
      <label>Colaboradora<select name="employee_id"><option value="">Todas</option>${data.employees.map(employee => `<option value="${employee.id}" ${String(filters.employee_id) === String(employee.id) ? 'selected' : ''}>${escapeHtml(employee.registration_code)} · ${escapeHtml(employee.full_name)}</option>`).join('')}</select></label>
      <label>OP<input name="op_number" value="${escapeHtml(filters.op_number)}" placeholder="Ex.: OP-1001" /></label>
      <label>Tipo da OP<select name="op_type"><option value="">Todos</option><option value="producao" ${filters.op_type === 'producao' ? 'selected' : ''}>Produção</option><option value="mostruario" ${filters.op_type === 'mostruario' ? 'selected' : ''}>Mostruário</option></select></label>
      <label>Início personalizado<input type="date" name="start_date" value="${escapeHtml(filters.start_date)}" /></label>
      <label>Fim personalizado<input type="date" name="end_date" value="${escapeHtml(filters.end_date)}" /></label>
      <button class="btn" type="submit">Atualizar</button>
      <a class="btn secondary" href="/op-extra-times/report">Limpar</a>
      <a class="btn secondary" href="/op-extra-times/report/export${getOpExtraReportQueryString(filters)}" target="_blank" rel="noopener">Imprimir / Salvar PDF</a>
    </form>

    <p class="hint"><strong>Período analisado:</strong> ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)} · <strong>modo:</strong> ${escapeHtml(data.range.label)}${data.selectedEmployee ? ` · <strong>colaboradora:</strong> ${escapeHtml(data.selectedEmployee.full_name)}` : ''}.</p>

    <div class="cards closure-cards">
      <article class="card"><span>Lançamentos com extra</span><strong>${data.summary.launchCount}</strong><small>Movimentos onde o extra foi aplicado</small></article>
      <article class="card"><span>Colaboradoras impactadas</span><strong>${data.summary.employees}</strong><small>No filtro atual</small></article>
      <article class="card"><span>OPs com extra</span><strong>${data.summary.ops}</strong><small>Com produção no período</small></article>
      <article class="card"><span>Peças com extra</span><strong>${data.summary.producedQuantity}</strong><small>Quantidade produzida nos lançamentos filtrados</small></article>
      <article class="card"><span>Min. normais</span><strong>${fmtNum(data.summary.normalMinutes, 2)}</strong><small>Base normal preservada</small></article>
      <article class="card"><span>Min. extras</span><strong>${fmtNum(data.summary.extraMinutes, 2)}</strong><small>${fmtNum(data.summary.extraSharePercent, 2)}% do total filtrado</small></article>
      <article class="card"><span>Min. totais</span><strong>${fmtNum(data.summary.producedMinutes, 2)}</strong><small>Normais + extras aplicados</small></article>
    </div>

    <div class="two-columns closure-report-grid">
      <section class="panel section-gap">
        <div class="panel-header"><h3>Consolidado por colaboradora</h3><span class="hint">Quem mais recebeu minutos extras no período.</span></div>
        <table>
          <thead><tr><th>Registro</th><th>Colaboradora</th><th>Lanç.</th><th>OPs</th><th>Peças</th><th>Normal</th><th>Extra</th><th>Total</th><th>% extra</th></tr></thead>
          <tbody>
            ${data.byEmployee.map(item => `<tr><td>${escapeHtml(item.registration_code)}</td><td>${escapeHtml(item.full_name)}</td><td>${item.launch_count}</td><td>${item.ops_count}</td><td>${item.produced_quantity}</td><td>${fmtNum(item.normal_minutes, 2)}</td><td>${fmtNum(item.extra_minutes, 2)}</td><td>${fmtNum(item.produced_minutes, 2)}</td><td>${fmtNum(item.extra_share_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="9">Nenhum lançamento com tempo extra nesse filtro.</td></tr>'}
          </tbody>
        </table>
      </section>

      <section class="panel section-gap">
        <div class="panel-header"><h3>Consolidado por OP</h3><span class="hint">Quanto do extra ficou concentrado por OP.</span></div>
        <table>
          <thead><tr><th>OP</th><th>Produto</th><th>Tipo</th><th>Lanç.</th><th>Colab.</th><th>Peças</th><th>Extra</th><th>Total</th><th>% extra</th></tr></thead>
          <tbody>
            ${data.byOp.map(item => `<tr><td><a href="/ops/${item.op_id}">${escapeHtml(item.op_number)}</a></td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(item.op_type)}</td><td>${item.launch_count}</td><td>${item.employees_count}</td><td>${item.produced_quantity}</td><td>${fmtNum(item.extra_minutes, 2)}</td><td>${fmtNum(item.produced_minutes, 2)}</td><td>${fmtNum(item.extra_share_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="9">Nenhuma OP com tempo extra aplicado nesse filtro.</td></tr>'}
          </tbody>
        </table>
      </section>
    </div>

    <div class="two-columns closure-report-grid">
      <section class="panel section-gap">
        <div class="panel-header"><h3>Consolidado por período</h3><span class="hint">Leitura diária do impacto do extra nos lançamentos.</span></div>
        <table>
          <thead><tr><th>Data</th><th>Lanç.</th><th>Colab.</th><th>OPs</th><th>Peças</th><th>Normal</th><th>Extra</th><th>Total</th><th>% extra</th></tr></thead>
          <tbody>
            ${data.byDay.map(item => `<tr><td>${formatDatePtBr(item.work_date)}</td><td>${item.launch_count}</td><td>${item.employees_count}</td><td>${item.ops_count}</td><td>${item.produced_quantity}</td><td>${fmtNum(item.normal_minutes, 2)}</td><td>${fmtNum(item.extra_minutes, 2)}</td><td>${fmtNum(item.produced_minutes, 2)}</td><td>${fmtNum(item.extra_share_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="9">Sem movimentação com tempo extra no período.</td></tr>'}
          </tbody>
        </table>
      </section>

      <section class="panel section-gap">
        <div class="panel-header"><h3>Leitura gerencial</h3><span class="hint">Resumo rápido para conferência desta etapa.</span></div>
        <ul>
          <li>O <strong>embarque continua usando apenas F21</strong>; o extra segue restrito aos lançamentos produtivos.</li>
          <li>Fechamento e prêmio de produção continuam calculando eficiência pelo <strong>total lançado</strong>, agora com abertura entre normal e extra.</li>
          <li>Este relatório considera somente lançamentos com <strong>extra_minutes &gt; 0</strong>, para mostrar o impacto real do módulo.</li>
          <li>Motivo e descrição agora são lidos do <strong>snapshot gravado no lançamento</strong>, preservando o histórico mesmo após editar o cadastro.</li>
        </ul>
      </section>
    </div>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Detalhamento dos lançamentos com extra</h3><span class="hint">Base auditável por colaboradora, OP e motivo.</span></div>
      <table>
        <thead><tr><th>Data</th><th>Registro</th><th>Colaboradora</th><th>OP</th><th>Produto</th><th>Tipo</th><th>Qtd</th><th>Normal</th><th>Extra</th><th>Total</th><th>Extra/pç</th><th>Motivo aplicado</th></tr></thead>
        <tbody>
          ${data.rows.map(row => `<tr><td>${formatDatePtBr(row.production_date)}</td><td>${escapeHtml(row.registration_code)}</td><td>${escapeHtml(row.full_name)}</td><td><a href="/ops/${row.op_id}">${escapeHtml(row.op_number)}</a></td><td>${escapeHtml(row.product_name)}</td><td>${escapeHtml(row.op_type)}</td><td>${row.produced_quantity}</td><td>${fmtNum(Number(row.normal_minutes || 0), 2)}</td><td>${fmtNum(Number(row.extra_minutes || 0), 2)}</td><td>${fmtNum(Number(row.produced_minutes || 0), 2)}</td><td>${fmtNum(Number(row.extra_minutes_per_piece || 0), 3)}</td><td>${escapeHtml(row.extra_reason || '-')}</td></tr>`).join('') || '<tr><td colspan="12">Nenhum lançamento com tempo extra encontrado.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;

  return pageLayout({ title: 'Tempo extra de OP - relatórios', content, notice: query.notice || '', error: query.error || '', role });
}

function renderOpExtraTimeExportPage(query = {}, role = 'adm') {
  const data = getOpExtraTimeReportData(query);
  const subtitle = `${data.range.label}: ${formatDatePtBr(data.range.start)} até ${formatDatePtBr(data.range.end)}${data.selectedEmployee ? ` · ${data.selectedEmployee.registration_code} · ${data.selectedEmployee.full_name}` : ''}${data.filters.op_number ? ` · OP ${data.filters.op_number}` : ''}${data.filters.op_type ? ` · ${data.filters.op_type}` : ''}`;
  const content = `
    <section class="page-header print-header">
      <div>
        <h2>Relatório de tempo extra de OP</h2>
        <p>${escapeHtml(subtitle)}</p>
      </div>
      <div class="header-actions no-print">
        <button class="btn" type="button" onclick="window.print()">Imprimir / Salvar PDF</button>
      </div>
    </section>

    <div class="cards closure-cards">
      <article class="card"><span>Lançamentos com extra</span><strong>${data.summary.launchCount}</strong><small>Movimentos onde o extra foi aplicado</small></article>
      <article class="card"><span>Colaboradoras impactadas</span><strong>${data.summary.employees}</strong><small>No filtro atual</small></article>
      <article class="card"><span>OPs com extra</span><strong>${data.summary.ops}</strong><small>Com produção no período</small></article>
      <article class="card"><span>Peças com extra</span><strong>${data.summary.producedQuantity}</strong><small>Quantidade produzida nos lançamentos filtrados</small></article>
      <article class="card"><span>Min. normais</span><strong>${fmtNum(data.summary.normalMinutes, 2)}</strong><small>Base normal preservada</small></article>
      <article class="card"><span>Min. extras</span><strong>${fmtNum(data.summary.extraMinutes, 2)}</strong><small>${fmtNum(data.summary.extraSharePercent, 2)}% do total filtrado</small></article>
      <article class="card"><span>Min. totais</span><strong>${fmtNum(data.summary.producedMinutes, 2)}</strong><small>Normais + extras aplicados</small></article>
    </div>

    <section class="panel section-gap">
      <h3>Consolidado por colaboradora</h3>
      <table>
        <thead><tr><th>Registro</th><th>Colaboradora</th><th>Lanç.</th><th>OPs</th><th>Peças</th><th>Normal</th><th>Extra</th><th>Total</th><th>% extra</th></tr></thead>
        <tbody>
          ${data.byEmployee.map(item => `<tr><td>${escapeHtml(item.registration_code)}</td><td>${escapeHtml(item.full_name)}</td><td>${item.launch_count}</td><td>${item.ops_count}</td><td>${item.produced_quantity}</td><td>${fmtNum(item.normal_minutes, 2)}</td><td>${fmtNum(item.extra_minutes, 2)}</td><td>${fmtNum(item.produced_minutes, 2)}</td><td>${fmtNum(item.extra_share_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="9">Nenhum lançamento com tempo extra nesse filtro.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel section-gap">
      <h3>Consolidado por OP</h3>
      <table>
        <thead><tr><th>OP</th><th>Produto</th><th>Tipo</th><th>Lanç.</th><th>Colab.</th><th>Peças</th><th>Extra</th><th>Total</th><th>% extra</th></tr></thead>
        <tbody>
          ${data.byOp.map(item => `<tr><td>${escapeHtml(item.op_number)}</td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(item.op_type)}</td><td>${item.launch_count}</td><td>${item.employees_count}</td><td>${item.produced_quantity}</td><td>${fmtNum(item.extra_minutes, 2)}</td><td>${fmtNum(item.produced_minutes, 2)}</td><td>${fmtNum(item.extra_share_percent, 2)}%</td></tr>`).join('') || '<tr><td colspan="9">Nenhuma OP com tempo extra aplicada nesse filtro.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel section-gap">
      <h3>Detalhamento dos lançamentos com extra</h3>
      <table>
        <thead><tr><th>Data</th><th>Registro</th><th>Colaboradora</th><th>OP</th><th>Produto</th><th>Qtd</th><th>Normal</th><th>Extra</th><th>Total</th><th>Extra/pç</th><th>Motivo aplicado</th><th>Descrição</th></tr></thead>
        <tbody>
          ${data.rows.map(row => `<tr><td>${formatDatePtBr(row.production_date)}</td><td>${escapeHtml(row.registration_code)}</td><td>${escapeHtml(row.full_name)}</td><td>${escapeHtml(row.op_number)}</td><td>${escapeHtml(row.product_name)}</td><td>${row.produced_quantity}</td><td>${fmtNum(Number(row.normal_minutes || 0), 2)}</td><td>${fmtNum(Number(row.extra_minutes || 0), 2)}</td><td>${fmtNum(Number(row.produced_minutes || 0), 2)}</td><td>${fmtNum(Number(row.extra_minutes_per_piece || 0), 3)}</td><td>${escapeHtml(row.extra_reason || '-')}</td><td>${escapeHtml(row.extra_description || '-')}</td></tr>`).join('') || '<tr><td colspan="12">Nenhum lançamento com tempo extra encontrado.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'Tempo extra de OP - relatórios', content, role });
}

function handleCreateOpExtraTime(form, res, role) {
  if (!canAccessCadastros(role)) return requireAdmin(null, res, role);
  const op = getOpByNumber(form.op_number);
  const extraMinutesPerPiece = Number(form.extra_minutes_per_piece || 0);
  const reason = String(form.reason || '').trim();
  const description = String(form.description || '').trim();
  const effectiveDate = String(form.effective_date || today()).trim();
  if (!op) return sendHtml(res, renderOpExtraTimesPage({}, form, 'Informe uma OP válida.', role), 422);
  if (Number.isNaN(extraMinutesPerPiece) || extraMinutesPerPiece < 0) return sendHtml(res, renderOpExtraTimesPage({}, form, 'Minutos extras por peça inválidos.', role), 422);
  if (!reason) return sendHtml(res, renderOpExtraTimesPage({}, form, 'Informe o motivo do tempo extra.', role), 422);
  if (!effectiveDate) return sendHtml(res, renderOpExtraTimesPage({}, form, 'Informe a data inicial.', role), 422);
  db.prepare(`
    INSERT INTO op_extra_times (
      op_id, extra_minutes_per_piece, reason, description, effective_date, notes, is_active, created_by_user_id, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `).run(op.id, extraMinutesPerPiece, reason, description || null, effectiveDate, String(form.notes || '').trim() || null, form.is_active === '0' ? 0 : 1);
  const recalc = recalculateExtraMinutesForOp(op.id, effectiveDate);
  redirect(res, `/op-extra-times?notice=${encodeURIComponent(extraRecalcNotice('Tempo extra cadastrado com sucesso.', recalc))}`);
}

function handleUpdateOpExtraTime(id, form, res, role) {
  if (!canAccessCadastros(role)) return requireAdmin(null, res, role);
  const row = getOpExtraTimeById(id);
  if (!row) return redirect(res, `/op-extra-times?error=${encodeURIComponent('Cadastro de tempo extra não encontrado.')}`);
  const op = getOpByNumber(form.op_number || row.op_number);
  const extraMinutesPerPiece = Number(form.extra_minutes_per_piece || 0);
  const reason = String(form.reason || '').trim();
  const description = String(form.description || '').trim();
  const effectiveDate = String(form.effective_date || today()).trim();
  if (!op) return sendHtml(res, renderOpExtraTimesPage({ edit: String(id) }, { ...form }, 'Informe uma OP válida.', role), 422);
  if (Number.isNaN(extraMinutesPerPiece) || extraMinutesPerPiece < 0) return sendHtml(res, renderOpExtraTimesPage({ edit: String(id) }, { ...form }, 'Minutos extras por peça inválidos.', role), 422);
  if (!reason) return sendHtml(res, renderOpExtraTimesPage({ edit: String(id) }, { ...form }, 'Informe o motivo do tempo extra.', role), 422);
  if (!effectiveDate) return sendHtml(res, renderOpExtraTimesPage({ edit: String(id) }, { ...form }, 'Informe a data inicial.', role), 422);
  db.prepare(`
    UPDATE op_extra_times
    SET op_id = ?, extra_minutes_per_piece = ?, reason = ?, description = ?, effective_date = ?, notes = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(op.id, extraMinutesPerPiece, reason, description || null, effectiveDate, String(form.notes || '').trim() || null, form.is_active === '0' ? 0 : 1, Number(id));
  const fromDate = [effectiveDate, row.effective_date].filter(Boolean).sort()[0];
  const recalc = recalculateExtraMinutesForOp(op.id, fromDate);
  if (Number(row.op_id) !== Number(op.id)) recalculateExtraMinutesForOp(row.op_id, row.effective_date);
  redirect(res, `/op-extra-times?notice=${encodeURIComponent(extraRecalcNotice('Tempo extra atualizado com sucesso.', recalc))}`);
}

function handleDeleteOpExtraTime(id, res, role) {
  if (!canAccessCadastros(role)) return requireAdmin(null, res, role);
  const row = getOpExtraTimeById(id);
  if (!row) return redirect(res, `/op-extra-times?error=${encodeURIComponent('Cadastro de tempo extra não encontrado.')}`);
  const usage = getProductionRowsUsingExtraTimeId(id);
  if (usage.length) {
    db.prepare('UPDATE op_extra_times SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(Number(id));
    const recalc = recalculateExtraMinutesForOp(row.op_id, row.effective_date);
    return redirect(res, `/op-extra-times?notice=${encodeURIComponent(extraRecalcNotice('Cadastro já usado em lançamentos: foi apenas inativado para preservar o histórico.', recalc))}`);
  }
  db.prepare('DELETE FROM op_extra_times WHERE id = ?').run(Number(id));
  redirect(res, `/op-extra-times?notice=${encodeURIComponent('Cadastro de tempo extra excluído com sucesso.')}`);
}

function handleToggleOpExtraTime(id, res, role) {
  if (!canAccessCadastros(role)) return requireAdmin(null, res, role);
  const row = db.prepare('SELECT * FROM op_extra_times WHERE id = ?').get(Number(id));
  if (!row) return redirect(res, `/op-extra-times?error=${encodeURIComponent('Cadastro de tempo extra não encontrado.')}`);
  db.prepare('UPDATE op_extra_times SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(row.is_active ? 0 : 1, row.id);
  const recalc = recalculateExtraMinutesForOp(row.op_id, row.effective_date);
  redirect(res, `/op-extra-times?notice=${encodeURIComponent(extraRecalcNotice(`Tempo extra ${row.is_active ? 'inativado' : 'ativado'} com sucesso.`, recalc))}`);
}

function renderOpExtraTimesPage(query = {}, values = {}, error = '', role = 'adm') {
  const search = String(query.search || '').trim();
  const editId = Number(query.edit || 0);
  const rows = getOpExtraTimeRows({ search });
  const editingRow = editId ? getOpExtraTimeById(editId) : null;
  const formValues = editingRow && !Object.keys(values || {}).length ? {
    op_number: editingRow.op_number,
    extra_minutes_per_piece: editingRow.extra_minutes_per_piece,
    reason: editingRow.reason,
    description: editingRow.description || '',
    effective_date: editingRow.effective_date,
    is_active: String(editingRow.is_active),
    notes: editingRow.notes || ''
  } : values;
  const content = `
    <section class="page-header">
      <div><h2>Tempo extra de OP</h2><p>Cadastre minutos extras por peça para a OP. O extra entra no lançamento diário, sem alterar o embarque.</p></div>
      <a class="btn secondary" href="/op-extra-times/report">Abrir relatórios</a>
    </section>

    <div class="two-columns cadastros-grid">
      <section class="panel">
        <h3>${editingRow ? 'Editar tempo extra' : 'Novo tempo extra'}</h3>
        <form class="stack-form" method="post" action="${editingRow ? `/op-extra-times/${editingRow.id}` : '/op-extra-times'}">
          <label>OP<input name="op_number" required autocomplete="off" value="${escapeHtml(formValues.op_number || '')}" placeholder="Ex.: OP-1001" /></label>
          <label>Minutos extras por peça<input type="number" min="0" step="0.001" name="extra_minutes_per_piece" required value="${escapeHtml(formValues.extra_minutes_per_piece || '')}" /></label>
          <label>Motivo<input name="reason" required value="${escapeHtml(formValues.reason || '')}" placeholder="Ex.: retrabalho, regulagem, acabamento extra" /></label>
          <label>Descrição<input name="description" value="${escapeHtml(formValues.description || '')}" placeholder="Resumo curto do motivo" /></label>
          <label>Data inicial<input type="date" name="effective_date" required value="${escapeHtml(formValues.effective_date || today())}" /></label>
          <label>Status inicial
            <select name="is_active">
              <option value="1" ${String(formValues.is_active ?? '1') === '1' ? 'selected' : ''}>Ativo</option>
              <option value="0" ${String(formValues.is_active || '') === '0' ? 'selected' : ''}>Inativo</option>
            </select>
          </label>
          <label>Observação<textarea name="notes" rows="3" placeholder="Opcional">${escapeHtml(formValues.notes || '')}</textarea></label>
          <div class="actions">
            <button class="btn" type="submit">${editingRow ? 'Salvar edição' : 'Salvar tempo extra'}</button>
            ${editingRow ? '<a class="btn secondary" href="/op-extra-times">Cancelar edição</a>' : ''}
          </div>
        </form>
        <p class="hint">Regra: se houver cadastro ativo para a data do lançamento, o sistema soma esse extra ao cálculo separado, sem mexer no embarque.</p>
        ${editingRow ? `<p class="hint">Se esse cadastro já foi usado em lançamentos, o histórico do motivo permanece congelado no lançamento e não será alterado retroativamente.</p>` : ''}
      </section>

      <section class="panel">
        <h3>Tempos extras cadastrados</h3>
        <form class="inline-form" method="get" action="/op-extra-times">
          <label>Buscar<input name="search" value="${escapeHtml(search)}" placeholder="OP, produto, motivo" /></label>
          <button class="btn secondary" type="submit">Filtrar</button>
        </form>
        <table>
          <thead><tr><th>OP</th><th>Produto</th><th>Início</th><th>Extra/pç</th><th>Motivo</th><th>Status</th><th>Ações</th></tr></thead>
          <tbody>
            ${rows.map(item => {
              const usageCount = getProductionRowsUsingExtraTimeId(item.id).length;
              return `<tr><td><a href="/ops/${item.op_id}">${escapeHtml(item.op_number)}</a></td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(nowPt(item.effective_date))}</td><td>${fmtNum(Number(item.extra_minutes_per_piece || 0), 3)}</td><td>${escapeHtml(item.reason)}</td><td>${item.is_active ? 'Ativo' : 'Inativo'}${usageCount ? ` · ${usageCount} lançamento(s)` : ''}</td><td><div class="table-actions"><a class="btn secondary" href="/op-extra-times?edit=${item.id}">Editar</a><form method="post" action="/op-extra-times/${item.id}/toggle"><button class="btn secondary" type="submit">${item.is_active ? 'Inativar' : 'Ativar'}</button></form><form method="post" action="/op-extra-times/${item.id}/delete" onsubmit="return confirm('Confirma a exclusão/inativação controlada deste cadastro?');"><button class="btn secondary" type="submit">${usageCount ? 'Inativar seguro' : 'Excluir'}</button></form></div></td></tr>`;
            }).join('') || '<tr><td colspan="7">Nenhum tempo extra cadastrado.</td></tr>'}
          </tbody>
        </table>
      </section>
    </div>
  `;
  return pageLayout({ title: 'Tempo extra de OP', content, notice: query.notice || '', error: error || query.error || '', role });
}

function renderCadastrosPage(query = {}, values = {}, error = '', role = 'adm') {
  const search = String(query.search || '').trim();
  const brands = getBrandList({ onlyActive: false, search });
  const collections = getCollectionList({ onlyActive: false, search });
  const content = `
    <section class="page-header">
      <div><h2>Cadastros</h2><p>Módulo liberado para Administrador e Operacional. Nesta etapa, controla marcas, coleções e o nome exibido nas etiquetas.</p></div>
    </section>

    <section class="panel section-gap">
      <h3>Configuração simples da empresa</h3>
      <form class="inline-form" method="post" action="/settings/company">
        <label>Nome da empresa nas etiquetas<input name="company_name" required value="${escapeHtml(getCompanyName())}" placeholder="Ex.: Facção Exemplo" /></label>
        <button class="btn" type="submit">Salvar nome</button>
      </form>
      <p class="hint">Esse nome aparece no cabeçalho das etiquetas de entrada e embarque.</p>
      <p class="hint">Veja também: <a href="/op-extra-times">Tempo extra de OP</a>.</p>
    </section>

    <div class="two-columns cadastros-grid">
      <section class="panel">
        <h3>Nova marca</h3>
        <form class="stack-form" method="post" action="/brands">
          <label>Nome da marca<input name="name" required autocomplete="off" value="${escapeHtml(values.name || '')}" placeholder="Ex.: Marca Alfa" /></label>
          <button class="btn" type="submit">Salvar marca</button>
        </form>
        <p class="hint">A marca cadastrada aqui passa a aparecer no autocomplete da OP e vira válida para uso nos filtros.</p>
      </section>

      <section class="panel">
        <h3>Marcas cadastradas</h3>
        <form class="inline-form" method="get" action="/cadastros">
          <label>Buscar marca<input name="search" value="${escapeHtml(search)}" placeholder="Nome da marca" /></label>
          <button class="btn secondary" type="submit">Filtrar</button>
        </form>
        <table>
          <thead><tr><th>Marca</th><th>Status</th><th>Criada em</th></tr></thead>
          <tbody>
            ${brands.map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${item.is_active ? 'Ativa' : 'Inativa'}</td><td>${escapeHtml(nowPt(item.created_at))}</td></tr>`).join('') || '<tr><td colspan="3">Nenhuma marca cadastrada.</td></tr>'}
          </tbody>
        </table>
      </section>
    </div>

    <div class="two-columns cadastros-grid">
      <section class="panel">
        <h3>Nova célula de costura</h3>
        <form class="stack-form" method="post" action="/cells">
          <label>Nome da célula<input name="cell_name" required autocomplete="off" value="${escapeHtml(values.cell_name || '')}" placeholder="Ex.: Célula A" /></label>
          <label>Observações<textarea name="cell_notes" rows="3" placeholder="Opcional">${escapeHtml(values.cell_notes || '')}</textarea></label>
          <button class="btn" type="submit">Salvar célula</button>
        </form>
        <p class="hint">Cadastro base para envio/retorno da OP em célula. Status pode ser ativo ou inativo.</p>
      </section>

      <section class="panel">
        <div class="panel-header"><h3>Células cadastradas</h3><a class="btn secondary" href="/cells/report">Relatórios de célula</a></div>
        <table>
          <thead><tr><th>Célula</th><th>Status</th><th>Obs.</th><th></th></tr></thead>
          <tbody>
            ${getCellList({ onlyActive: false, search }).map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${item.is_active ? 'Ativa' : 'Inativa'}</td><td>${escapeHtml(item.notes || '-')}</td><td><form method="post" action="/cells/${item.id}/toggle"><button class="btn secondary" type="submit">${item.is_active ? 'Inativar' : 'Ativar'}</button></form></td></tr>`).join('') || '<tr><td colspan="4">Nenhuma célula cadastrada.</td></tr>'}
          </tbody>
        </table>
      </section>
    </div>

    <div class="two-columns cadastros-grid">
      <section class="panel">
        <h3>Nova coleção</h3>
        <form class="stack-form" method="post" action="/collections">
          <label>Nome da coleção<input name="name" required autocomplete="off" value="${escapeHtml(values.collection_name_form || '')}" placeholder="Ex.: Inverno 2026" /></label>
          <button class="btn" type="submit">Salvar coleção</button>
        </form>
        <p class="hint">A coleção cadastrada aqui entra no autocomplete da OP, no filtro e nas etiquetas.</p>
      </section>

      <section class="panel">
        <h3>Coleções cadastradas</h3>
        <form class="inline-form" method="get" action="/cadastros">
          <label>Buscar coleção<input name="search" value="${escapeHtml(search)}" placeholder="Nome da coleção" /></label>
          <button class="btn secondary" type="submit">Filtrar</button>
        </form>
        <table>
          <thead><tr><th>Coleção</th><th>Status</th><th>Criada em</th></tr></thead>
          <tbody>
            ${collections.map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${item.is_active ? 'Ativa' : 'Inativa'}</td><td>${escapeHtml(nowPt(item.created_at))}</td></tr>`).join('') || '<tr><td colspan="3">Nenhuma coleção cadastrada.</td></tr>'}
          </tbody>
        </table>
      </section>
    </div>

    ${renderWorkSchedulesSection(values, query)}
  `;
  return pageLayout({ title: 'Cadastros', content, notice: query.notice || '', error: error || query.error || '', role });
}

// ===================== JORNADAS DE TRABALHO =====================
const WEEKDAY_LABELS = { 0: 'Dom', 1: 'Seg', 2: 'Ter', 3: 'Qua', 4: 'Qui', 5: 'Sex', 6: 'Sáb' };

function getWorkSchedules({ onlyActive = false } = {}) {
  return db.prepare(`SELECT * FROM work_schedules ${onlyActive ? 'WHERE is_active = 1' : ''} ORDER BY name ASC`).all();
}

// "07:00" -> 420
function timeToMinutes(value) {
  const match = String(value || '').match(/^(\d{1,2}):(\d{2})$/);
  if (!match) return null;
  const minutes = Number(match[1]) * 60 + Number(match[2]);
  return minutes >= 0 && minutes <= 24 * 60 ? minutes : null;
}

function getScheduleTimes(schedule) {
  const start = timeToMinutes(schedule.start_time) ?? Number(schedule.start_hour || 0) * 60;
  const end = timeToMinutes(schedule.end_time) ?? Number(schedule.end_hour || 24) * 60;
  const breakStart = timeToMinutes(schedule.break_start);
  const breakEnd = timeToMinutes(schedule.break_end);
  const hasBreak = breakStart !== null && breakEnd !== null && breakEnd > breakStart;
  return { start, end, breakStart: hasBreak ? breakStart : null, breakEnd: hasBreak ? breakEnd : null };
}

function getScheduleWorkMinutes(schedule) {
  const t = getScheduleTimes(schedule);
  return Math.max(t.end - t.start - (t.breakStart !== null ? t.breakEnd - t.breakStart : 0), 0);
}

function formatMinutesAsHours(minutes) {
  return `${Math.floor(minutes / 60)}h${String(minutes % 60).padStart(2, '0')}`;
}

function formatWorkSchedule(schedule) {
  if (!schedule) return 'Sem jornada';
  const days = String(schedule.weekdays || '').split(',').filter(Boolean).map(d => WEEKDAY_LABELS[d]).join(', ');
  const t = getScheduleTimes(schedule);
  const hhmm = m => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
  const pause = t.breakStart !== null ? ` · intervalo ${hhmm(t.breakStart)}–${hhmm(t.breakEnd)}` : '';
  return `${schedule.name} · ${hhmm(t.start)}–${hhmm(t.end)}${pause} · ${days}`;
}

// A hora lançada (slot "HH:00") está dentro da jornada? Fora do início/término ou no intervalo = horário extra.
function isSlotInsideSchedule(schedule, hourSlot) {
  const slot = timeToMinutes(String(hourSlot).slice(0, 5));
  if (slot === null) return true;
  const t = getScheduleTimes(schedule);
  if (slot < Math.floor(t.start / 60) * 60 || slot >= t.end) return false;
  if (t.breakStart !== null && slot >= t.breakStart && slot < t.breakEnd) return false;
  return true;
}

// Lançamento fora da jornada oficial? Retorna o motivo (vazio = dentro da jornada).
// Sem jornada vinculada: só sábado, domingo e feriado pedem a flag.
function getOutsideScheduleReason(employee, productionDate, hourSlot = '') {
  if (!employee || !productionDate) return '';
  const holidays = getHolidayDateSet();
  if (holidays.has(productionDate)) return 'feriado';
  const weekday = new Date(`${productionDate}T00:00:00Z`).getUTCDay();
  const schedule = employee.work_schedule_id
    ? db.prepare('SELECT * FROM work_schedules WHERE id = ?').get(employee.work_schedule_id)
    : null;
  const workDays = schedule ? String(schedule.weekdays || '').split(',').map(Number) : [1, 2, 3, 4, 5];
  if (!workDays.includes(weekday)) return weekday === 6 ? 'sábado' : (weekday === 0 ? 'domingo' : 'dia fora da jornada');
  if (schedule && hourSlot && !isSlotInsideSchedule(schedule, hourSlot)) return 'horário extra ou intervalo';
  return '';
}

function resolveCountsForPrize(form, employee, productionDate, hourSlot = '') {
  // Dentro da jornada sempre conta. Fora dela, vale a flag (padrão: conta).
  if (!getOutsideScheduleReason(employee, productionDate, hourSlot)) return 1;
  if (form.counts_for_prize === undefined) return 1;
  return parseCountsForPrizeFlag(form.counts_for_prize);
}

// Valor da flag enviado pelo formulário (hidden 0 + checkbox 1)
function parseCountsForPrizeFlag(value) {
  const list = Array.isArray(value) ? value : [value];
  return list.map(String).includes('1') ? 1 : 0;
}

// Script de cliente: mostra a flag "Conta para prêmio" quando a data/hora sai da jornada
function renderPrizeFlagScript({ formSelector, employeeFieldSelector, dateFieldSelector, hourFieldSelector = '' }) {
  const schedules = Object.fromEntries(getWorkSchedules().map(item => {
    const t = getScheduleTimes(item);
    return [item.id, { s: Math.floor(t.start / 60) * 60, e: t.end, bs: t.breakStart, be: t.breakEnd, d: String(item.weekdays).split(',').map(Number) }];
  }));
  const employeeSchedules = Object.fromEntries(db.prepare('SELECT id, work_schedule_id FROM employees').all().map(item => [item.id, item.work_schedule_id || 0]));
  const holidays = [...getHolidayDateSet()].filter(d => d >= '2025-01-01');
  return `<script>
  (() => {
    const form = document.querySelector(${JSON.stringify(formSelector)});
    if (!form) return;
    const box = form.querySelector('[data-prize-flag]');
    if (!box) return;
    const schedules = ${JSON.stringify(schedules)};
    const empSchedule = ${JSON.stringify(employeeSchedules)};
    const holidays = new Set(${JSON.stringify(holidays)});
    const emp = form.querySelector(${JSON.stringify(employeeFieldSelector)});
    const date = form.querySelector(${JSON.stringify(dateFieldSelector)});
    const hour = ${hourFieldSelector ? `form.querySelector(${JSON.stringify(hourFieldSelector)})` : 'null'};
    const reasonEl = box.querySelector('[data-prize-reason]');
    const check = () => {
      const d = date && date.value;
      let reason = '';
      if (d) {
        const sch = schedules[empSchedule[emp && emp.value] || 0];
        const wd = new Date(d + 'T00:00:00Z').getUTCDay();
        const days = sch ? sch.d : [1, 2, 3, 4, 5];
        if (holidays.has(d)) reason = 'feriado';
        else if (!days.includes(wd)) reason = wd === 6 ? 'sábado' : (wd === 0 ? 'domingo' : 'dia fora da jornada');
        else if (sch && hour && hour.value) {
          const h = Number(String(hour.value).replace(/\D/g, '').padStart(4, '0').slice(0, 2)) * 60;
          if (h < sch.s || h >= sch.e) reason = 'horário extra';
          else if (sch.bs !== null && h >= sch.bs && h < sch.be) reason = 'intervalo';
        }
      }
      box.hidden = !reason;
      if (reasonEl) reasonEl.textContent = reason;
    };
    ['change', 'input'].forEach(evt => [emp, date, hour].forEach(el => el && el.addEventListener(evt, check)));
    check();
  })();
  </script>`;
}

function renderPrizeFlagField(values = {}) {
  const checked = values.counts_for_prize === undefined ? true : parseCountsForPrizeFlag(values.counts_for_prize) === 1;
  return `<div class="prize-flag" data-prize-flag hidden>
    <input type="hidden" name="counts_for_prize" value="0" />
    <label class="checkbox-line"><input type="checkbox" name="counts_for_prize" value="1" ${checked ? 'checked' : ''} /> Conta para eficiência e prêmio</label>
    <small class="hint">Lançamento fora da jornada (<span data-prize-reason></span>). Desmarque se esse trabalho não deve entrar no prêmio.</small>
  </div>`;
}

function renderWorkScheduleSelect(selectedId, required = false) {
  const options = getWorkSchedules().filter(item => item.is_active || item.id === Number(selectedId));
  return `<label>Jornada de trabalho${required ? ' *' : ''}<select name="work_schedule_id" ${required ? 'required' : ''}><option value="">${required ? 'Selecione...' : 'Sem jornada'}</option>${options.map(item => `<option value="${item.id}" ${Number(selectedId) === item.id ? 'selected' : ''}>${escapeHtml(item.name)}</option>`).join('')}</select></label>`;
}

function renderWorkSchedulesSection(values = {}, query = {}) {
  const editing = query.edit_schedule ? db.prepare('SELECT * FROM work_schedules WHERE id = ?').get(Number(query.edit_schedule)) : null;
  const v = editing && !values.schedule_name ? {
    schedule_name: editing.name,
    start_time: editing.start_time,
    end_time: editing.end_time,
    break_start: editing.break_start || '',
    break_end: editing.break_end || '',
    weekdays_list: editing.weekdays
  } : values;
  const weekdays = String(v.weekdays_list || '1,2,3,4,5').split(',');
  const list = getWorkSchedules();
  const usage = new Map(db.prepare('SELECT work_schedule_id AS id, COUNT(*) AS n FROM employees WHERE work_schedule_id IS NOT NULL AND is_active = 1 GROUP BY work_schedule_id').all().map(r => [r.id, r.n]));
  return `
    <div class="two-columns cadastros-grid" id="jornadas">
      <section class="panel">
        <h3>${editing ? `Editar jornada: ${escapeHtml(editing.name)}` : 'Nova jornada de trabalho'}</h3>
        <form class="stack-form" method="post" action="${editing ? `/work-schedules/${editing.id}` : '/work-schedules'}" data-schedule-form>
          <label>Nome<input name="schedule_name" required value="${escapeHtml(v.schedule_name || '')}" placeholder="Ex.: Primeiro turno" /></label>
          <div class="inline-form">
            <label>Início<input name="start_time" type="time" required value="${escapeHtml(v.start_time || '07:00')}" /></label>
            <label>Término<input name="end_time" type="time" required value="${escapeHtml(v.end_time || '16:48')}" /></label>
          </div>
          <div class="inline-form">
            <label>Intervalo das<input name="break_start" type="time" value="${escapeHtml(v.break_start ?? '12:00')}" /></label>
            <label>às<input name="break_end" type="time" value="${escapeHtml(v.break_end ?? '13:00')}" /></label>
          </div>
          <p class="hint">Tempo de trabalho: <strong data-schedule-total>-</strong> por dia (referência da base: 8h48 = 528 min).</p>
          <fieldset><legend>Dias de trabalho</legend>
            ${[1, 2, 3, 4, 5, 6, 0].map(d => `<label class="checkbox-line"><input type="checkbox" name="weekdays" value="${d}" ${weekdays.includes(String(d)) ? 'checked' : ''} /> ${WEEKDAY_LABELS[d]}</label>`).join('')}
          </fieldset>
          <div class="actions"><button class="btn" type="submit">${editing ? 'Salvar alterações' : 'Salvar jornada'}</button>${editing ? '<a class="btn secondary" href="/cadastros#jornadas">Cancelar</a>' : ''}</div>
        </form>
        <script>
          (() => {
            const f = document.querySelector('[data-schedule-form]');
            if (!f) return;
            const m = v => { const p = String(v || '').split(':'); return p.length === 2 ? Number(p[0]) * 60 + Number(p[1]) : null; };
            const out = f.querySelector('[data-schedule-total]');
            const calc = () => {
              const s = m(f.start_time.value), e = m(f.end_time.value), bs = m(f.break_start.value), be = m(f.break_end.value);
              if (s === null || e === null || e <= s) { out.textContent = '-'; return; }
              const total = e - s - (bs !== null && be !== null && be > bs ? be - bs : 0);
              out.textContent = Math.floor(total / 60) + 'h' + String(total % 60).padStart(2, '0') + ' (' + total + ' min)';
            };
            f.addEventListener('input', calc);
            calc();
          })();
        </script>
        <p class="hint">Lançamento por hora fora do início/término, no intervalo, em dia fora da jornada ou feriado mostra a opção "Conta para eficiência e prêmio". A base de cálculo continua 528 min por dia útil (seg–sex).</p>
      </section>
      <section class="panel">
        <h3>Jornadas cadastradas</h3>
        <table>
          <thead><tr><th>Jornada</th><th>Trabalho/dia</th><th>Colaboradoras ativas</th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${list.map(item => `<tr><td>${escapeHtml(formatWorkSchedule(item))}</td><td>${formatMinutesAsHours(getScheduleWorkMinutes(item))}</td><td>${usage.get(item.id) || 0}</td><td>${item.is_active ? 'Ativa' : 'Inativa'}</td><td class="actions"><a class="btn secondary" href="/cadastros?edit_schedule=${item.id}#jornadas">Editar</a><form method="post" action="/work-schedules/${item.id}/toggle"><button class="btn secondary" type="submit">${item.is_active ? 'Inativar' : 'Ativar'}</button></form></td></tr>`).join('') || '<tr><td colspan="5">Nenhuma jornada cadastrada.</td></tr>'}
          </tbody>
        </table>
        <p class="hint">Vincule a jornada no cadastro de cada colaboradora (menu Colaboradores).</p>
      </section>
    </div>`;
}

function parseWorkScheduleForm(form) {
  const name = String(form.schedule_name || '').trim();
  const startTime = String(form.start_time || '').trim();
  const endTime = String(form.end_time || '').trim();
  const breakStart = String(form.break_start || '').trim();
  const breakEnd = String(form.break_end || '').trim();
  const weekdays = (Array.isArray(form.weekdays) ? form.weekdays : [form.weekdays]).filter(v => v !== undefined && v !== '').map(Number).filter(d => d >= 0 && d <= 6);
  const back = { ...form, weekdays_list: weekdays.join(',') };
  const s = timeToMinutes(startTime), e = timeToMinutes(endTime), bs = timeToMinutes(breakStart), be = timeToMinutes(breakEnd);
  let error = '';
  if (!name) error = 'Informe o nome da jornada.';
  else if (s === null || e === null || s >= e) error = 'Horário inválido: o início deve ser antes do término.';
  else if ((breakStart || breakEnd) && (bs === null || be === null || bs >= be || bs < s || be > e)) error = 'Intervalo inválido: precisa ter início e fim, dentro da jornada.';
  else if (!weekdays.length) error = 'Marque ao menos um dia de trabalho.';
  return {
    error,
    back,
    row: {
      name, startTime, endTime,
      breakStart: breakStart && breakEnd ? breakStart : null,
      breakEnd: breakStart && breakEnd ? breakEnd : null,
      startHour: s === null ? 0 : Math.floor(s / 60),
      endHour: e === null ? 24 : Math.min(Math.ceil(e / 60), 24),
      weekdays: [...new Set(weekdays)].sort().join(',')
    }
  };
}

function handleCreateWorkSchedule(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const { error, back, row } = parseWorkScheduleForm(form);
  if (error) return sendHtml(res, renderCadastrosPage({}, back, error, role), 422);
  try {
    db.prepare(`INSERT INTO work_schedules (name, start_hour, end_hour, start_time, end_time, break_start, break_end, weekdays)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(row.name, row.startHour, row.endHour, row.startTime, row.endTime, row.breakStart, row.breakEnd, row.weekdays);
    redirect(res, `/cadastros?notice=${encodeURIComponent('Jornada cadastrada com sucesso.')}#jornadas`);
  } catch (err) {
    const msg = err.message.includes('UNIQUE') ? 'Já existe uma jornada com esse nome.' : `Erro ao salvar jornada: ${err.message}`;
    sendHtml(res, renderCadastrosPage({}, back, msg, role), 422);
  }
}

function handleUpdateWorkSchedule(id, form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const { error, back, row } = parseWorkScheduleForm(form);
  if (error) return sendHtml(res, renderCadastrosPage({ edit_schedule: String(id) }, back, error, role), 422);
  try {
    const result = db.prepare(`UPDATE work_schedules SET name = ?, start_hour = ?, end_hour = ?, start_time = ?, end_time = ?,
      break_start = ?, break_end = ?, weekdays = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
      .run(row.name, row.startHour, row.endHour, row.startTime, row.endTime, row.breakStart, row.breakEnd, row.weekdays, id);
    if (!result.changes) return redirect(res, `/cadastros?error=${encodeURIComponent('Jornada não encontrada.')}`);
    redirect(res, `/cadastros?notice=${encodeURIComponent('Jornada atualizada.')}#jornadas`);
  } catch (err) {
    const msg = err.message.includes('UNIQUE') ? 'Já existe uma jornada com esse nome.' : `Erro ao salvar jornada: ${err.message}`;
    sendHtml(res, renderCadastrosPage({ edit_schedule: String(id) }, back, msg, role), 422);
  }
}

function handleToggleWorkSchedule(id, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const item = db.prepare('SELECT * FROM work_schedules WHERE id = ?').get(id);
  if (!item) return redirect(res, `/cadastros?error=${encodeURIComponent('Jornada não encontrada.')}`);
  db.prepare('UPDATE work_schedules SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(item.is_active ? 0 : 1, id);
  redirect(res, `/cadastros?notice=${encodeURIComponent(`Jornada ${item.is_active ? 'inativada' : 'ativada'}.`)}`);
}
// ===============================================================

// ===================== ALERTAS TELEGRAM (T2.1 / T2.2) =====================
// Cada empresa usa o próprio bot (token em Parâmetros), vincula grupos/conversas com
// "/vincular CÓDIGO" e marca quais alertas quer receber. Um worker roda a cada minuto.
const APP_BASE_URL = String(process.env.APP_BASE_URL || 'https://app.agilfac.com.br').replace(/\/+$/, '');
const TELEGRAM_API_BASE = String(process.env.TELEGRAM_API_BASE || 'https://api.telegram.org').replace(/\/+$/, '');

// Catálogo: frequência "hourly" (de hora em hora na janela, sem repetir o mesmo item no dia),
// "daily" (uma vez por dia, no horário do resumo) ou "event" (avisa assim que acontece).
const ALERT_CATALOG = [
  { key: 'cell_stuck', group: 'Produção', label: 'OP parada em célula', help: 'OP com saldo em célula há N dias ou mais.', freq: 'hourly', defaultOn: true, param: { key: 'days', label: 'dias', def: 3 } },
  { key: 'delivery_late', group: 'Produção', label: 'Entrega atrasada', help: 'OP não embarcada com data de entrega vencida.', freq: 'daily', defaultOn: true },
  { key: 'delivery_soon', group: 'Produção', label: 'Entrega próxima', help: 'OP não embarcada que vence em até N dias.', freq: 'daily', defaultOn: true, param: { key: 'days', label: 'dias', def: 2 } },
  { key: 'no_delivery_date', group: 'Produção', label: 'OP sem data de entrega', help: 'Quantas OPs em aberto ainda estão sem data de entrega.', freq: 'daily', defaultOn: false },
  { key: 'op_idle', group: 'Produção', label: 'OP verde sem movimento', help: 'OP a produzir sem nenhum lançamento há N dias desde a entrada.', freq: 'daily', defaultOn: false, param: { key: 'days', label: 'dias', def: 5 } },
  { key: 'ready_not_shipped', group: 'Produção', label: 'OP finalizada aguardando embarque', help: 'OP azul sem embarque há N dias desde o último lançamento.', freq: 'daily', defaultOn: false, param: { key: 'days', label: 'dias', def: 2 } },
  { key: 'occurrence_open', group: 'Produção', label: 'Ocorrência aberta', help: 'Ocorrência de OP sem conclusão há N dias.', freq: 'daily', defaultOn: false, param: { key: 'days', label: 'dias', def: 2 } },
  { key: 'quality_issue', group: 'Qualidade', label: 'Peças com problema registradas', help: 'Avisa a cada novo registro de peça com problema.', freq: 'event', defaultOn: false },
  { key: 'reject_rate', group: 'Qualidade', label: 'Taxa de reprovação alta', help: 'Peças com problema ÷ peças produzidas no período acima de X%.', freq: 'daily', defaultOn: false, param: { key: 'percent', label: '%', def: 1 } },
  { key: 'no_launch', group: 'Pessoas', label: 'Colaboradora sem lançamento', help: 'Ativa, sem lançamento, sem ausência e sem justificativa no último dia útil.', freq: 'daily', defaultOn: true },
  { key: 'below_target', group: 'Pessoas', label: 'Colaboradoras abaixo da meta', help: 'Lista quem está abaixo da meta até o corte.', freq: 'daily', defaultOn: false },
  { key: 'company_below_target', group: 'Pessoas', label: 'Empresa abaixo da meta', help: 'Eficiência geral até o corte abaixo da meta.', freq: 'daily', defaultOn: true },
  { key: 'pending_closure', group: 'Pessoas', label: 'Pendências no fechamento', help: 'Dias úteis sem lançamento e sem tratativa no período acima de N.', freq: 'daily', defaultOn: false, param: { key: 'count', label: 'dias pendentes', def: 10 } },
  { key: 'off_schedule', group: 'Pessoas', label: 'Lançamentos fora do prêmio', help: 'Lançamentos de ontem marcados como "não conta para prêmio".', freq: 'daily', defaultOn: false },
  { key: 'birthday', group: 'Pessoas', label: 'Aniversariantes do dia', help: 'Colaboradoras ativas fazendo aniversário hoje.', freq: 'daily', defaultOn: false },
  { key: 'shipment_created', group: 'Expedição e financeiro', label: 'Embarque registrado', help: 'Avisa a cada novo embarque, com OPs e minutos.', freq: 'event', defaultOn: false },
  { key: 'unbilled', group: 'Expedição e financeiro', label: 'Embarcadas sem cobrança', help: 'OPs embarcadas há N dias ou mais e ainda não cobradas.', freq: 'daily', defaultOn: false, param: { key: 'days', label: 'dias', def: 7 } },
  { key: 'reversal', group: 'Sistema', label: 'Estornos realizados', help: 'Avisa a cada estorno de OP, lançamento ou embarque, com o motivo.', freq: 'event', defaultOn: false },
  { key: 'login_blocked', group: 'Sistema', label: 'Login bloqueado', help: 'Bloqueio por excesso de tentativas de senha nesta empresa.', freq: 'event', defaultOn: false },
  { key: 'daily_summary', group: 'Resumos e relatórios', label: 'Resumo gerencial diário', help: 'Minutos de ontem, eficiência até o corte, abaixo da meta, entregas, células paradas e fila.', freq: 'summary', defaultOn: true },
  { key: 'op_agenda', group: 'Resumos e relatórios', label: 'Agenda do dia (operacional)', help: 'O que precisa ser feito hoje: entregas de hoje e amanhã, OPs paradas em célula, prontas para embarcar e quem ficou sem lançamento.', freq: 'summary', defaultOn: true },
  { key: 'weekly_report', group: 'Resumos e relatórios', label: 'Relatório semanal', help: 'Toda segunda: produção da semana anterior, embarques, eficiência do período, melhores e piores resultados.', freq: 'weekly', defaultOn: true }
];

// Dois bots: "gestor" (relatórios e visão gerencial) e "op" (operacional: avisos do dia a dia).
// Se o bot operacional não tiver token próprio, usa o mesmo bot do gestor (em grupos diferentes).
const ALERT_AUDIENCES = [
  { key: 'gestor', label: 'Gestor', title: 'Bot do gestor', desc: 'Relatórios, análises e informações gerenciais.', tokenKey: 'telegram_bot_token', chatsKey: 'telegram_chats', codeKey: 'telegram_link_code', codePrefix: 'GES' },
  { key: 'op', label: 'Operacional', title: 'Bot operacional', desc: 'Avisos antecipados, alertas e disparos para o trabalho do dia a dia.', tokenKey: 'telegram_bot_token_op', chatsKey: 'telegram_chats_op', codeKey: 'telegram_link_code_op', codePrefix: 'OPE' }
];
const ALERT_AUDIENCE_DEFAULTS = {
  gestor: new Set(['below_target', 'company_below_target', 'daily_summary', 'delivery_late', 'login_blocked', 'pending_closure', 'reject_rate', 'reversal', 'unbilled', 'weekly_report']),
  op: new Set(['birthday', 'cell_stuck', 'delivery_late', 'delivery_soon', 'no_delivery_date', 'no_launch', 'occurrence_open', 'off_schedule', 'op_agenda', 'op_idle', 'quality_issue', 'ready_not_shipped', 'shipment_created'])
};

const ALERT_SETTING_DEFAULTS = {
  telegram_bot_token: '',
  telegram_bot_token_op: '',
  telegram_chats: '[]',
  telegram_chats_op: '[]',
  telegram_link_code: '',
  telegram_link_code_op: '',
  alerts_enabled: '0',
  alerts_start_hour: '7',
  alerts_end_hour: '19',
  alerts_summary_hour: '7',
  alerts_weekdays_only: '1'
};

function getAlertSetting(key) {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  if (row && row.value !== null && row.value !== undefined) return String(row.value);
  if (key in ALERT_SETTING_DEFAULTS) return ALERT_SETTING_DEFAULTS[key];
  const m = key.match(/^alert_(gestor|op|param)_(.+)$/);
  if (m) {
    const rule = ALERT_CATALOG.find(r => r.key === m[2]);
    if (!rule) return '';
    return m[1] === 'param' ? String(rule.param?.def ?? '') : (ALERT_AUDIENCE_DEFAULTS[m[1]].has(rule.key) ? '1' : '0');
  }
  return '';
}

function setAlertSetting(key, value) {
  db.prepare(`INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`).run(key, String(value));
}

function getAudience(key) {
  return ALERT_AUDIENCES.find(a => a.key === key) || ALERT_AUDIENCES[0];
}

function getTelegramChats(aud = 'gestor') {
  try { return JSON.parse(getAlertSetting(getAudience(aud).chatsKey) || '[]').filter(c => c && c.id); } catch (_) { return []; }
}

function getAudienceToken(aud) {
  const own = getAlertSetting(getAudience(aud).tokenKey);
  return own || (aud === 'op' ? getAlertSetting('telegram_bot_token') : '');
}

function ensureTelegramLinkCode(aud = 'gestor') {
  const a = getAudience(aud);
  let code = getAlertSetting(a.codeKey);
  if (!code) {
    code = `${a.codePrefix}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    setAlertSetting(a.codeKey, code);
  }
  return code;
}

function maskToken(token) {
  const t = String(token || '');
  return t ? `${t.slice(0, 6)}••••••${t.slice(-4)}` : '';
}

function tgEscape(text) {
  return String(text ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function telegramCall(token, method, payload = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`${TELEGRAM_API_BASE}/bot${token}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!data.ok) throw new Error(data.description || `HTTP ${response.status}`);
    return data.result;
  } finally {
    clearTimeout(timer);
  }
}

async function sendTelegramToAll(text, aud = 'gestor') {
  const token = getAudienceToken(aud);
  const chats = getTelegramChats(aud);
  if (!token || !chats.length) return 0;
  let sent = 0;
  for (const chat of chats) {
    try {
      await telegramCall(token, 'sendMessage', { chat_id: chat.id, text: text.slice(0, 4000), parse_mode: 'HTML', disable_web_page_preview: true });
      sent += 1;
    } catch (error) {
      console.error(`Telegram (${getCompanyName()}) falhou para ${chat.title || chat.id}:`, error.message);
    }
  }
  return sent;
}

function opLink(op) {
  return `<a href="${APP_BASE_URL}/ops/${op.id}">${tgEscape(op.op_number)}</a>`;
}

function listLines(items, max = 15) {
  const lines = items.slice(0, max);
  if (items.length > max) lines.push(`… e mais ${items.length - max}`);
  return lines.join('\n');
}

function lastBusinessDayBefore(isoDate) {
  return getPreviousBusinessDay(isoDate);
}

function getActiveEmployees() {
  return db.prepare('SELECT * FROM employees').all().filter(emp => describeEmployeeStatus(emp) === 'Ativo');
}

function getTargetSnapshot(lastDayArg = '') {
  // Período que contém o último dia útil fechado (no 1º dia de um período novo, mostra o anterior)
  const lastDay = lastDayArg || getPreviousBusinessDay(today());
  const range = getPeriodRange('month', lastDay);
  const cutoff = [range.end, lastDay].sort()[0];
  const employees = getActiveEmployees();
  if (cutoff < range.start) return { range, cutoff, rows: [], total: { minutes: 0, base: 0, pct: 0 } };
  const counted = getCountedProductionByEmployee(range.start, cutoff, employees);
  const rows = employees.map(emp => {
    const minutes = round2(counted.get(emp.id)?.minutes || 0);
    const eff = calculateEmployeeEfficiency(emp, minutes, range.start, range.end, cutoff);
    return { emp, minutes, base: eff.available_minutes, pct: eff.efficiency_percent, target: employeeTargetPercent(emp) };
  }).filter(r => r.base > 0);
  const minutes = rows.reduce((s, r) => s + r.minutes, 0);
  const base = rows.reduce((s, r) => s + r.base, 0);
  return { range, cutoff, rows, total: { minutes: round2(minutes), base: round2(base), pct: base > 0 ? round2((minutes / base) * 100) : 0 } };
}

function openOpsWhere() {
  return "o.is_reversed = 0 AND o.shipped_at IS NULL AND o.status_color <> 'vermelho' AND COALESCE(o.lifecycle_type, 'normal') = 'normal'";
}

function paramOf(ruleKey) {
  const rule = ALERT_CATALOG.find(r => r.key === ruleKey);
  const n = Number(String(getAlertSetting(`alert_param_${ruleKey}`)).replace(',', '.'));
  return Number.isFinite(n) && n >= 0 ? n : Number(rule?.param?.def || 0);
}

// Cada regra devolve uma lista de { ref, text }. "ref" evita repetir o mesmo aviso no mesmo dia.
const ALERT_RULES = {
  cell_stuck() {
    const days = paramOf('cell_stuck');
    const limit = addDaysIso(today(), -days);
    return db.prepare(`
      SELECT o.id, o.op_number, c.name AS cell_name, t.sent_at, (t.quantity_sent - t.quantity_returned) AS open_qty
      FROM op_cell_transfers t JOIN ops o ON o.id = t.op_id JOIN sewing_cells c ON c.id = t.cell_id
      WHERE t.quantity_sent > t.quantity_returned AND t.sent_at <= ? AND o.is_reversed = 0
      ORDER BY t.sent_at
    `).all(limit).map(r => {
      const d = Math.round((new Date(`${today()}T00:00:00Z`) - new Date(`${r.sent_at.slice(0, 10)}T00:00:00Z`)) / 86400000);
      return { ref: `${r.id}:${r.sent_at}`, text: `🩷 OP ${opLink(r)} na célula <b>${tgEscape(r.cell_name)}</b> há ${d} dias (${r.open_qty} pç em aberto)` };
    });
  },
  delivery_late() {
    const rows = db.prepare(`SELECT o.id, o.op_number, o.delivery_date, o.brand FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date IS NOT NULL AND o.delivery_date <> '' AND o.delivery_date < ? ORDER BY o.delivery_date`).all(today());
    return rows.length ? [{ ref: 'all', text: `🔴 <b>${rows.length} OP(s) com entrega atrasada</b>\n${listLines(rows.map(r => `• ${opLink(r)} · ${tgEscape(r.brand || '-')} · venceu ${formatDatePtBr(r.delivery_date)}`))}` }] : [];
  },
  delivery_soon() {
    const days = paramOf('delivery_soon');
    const rows = db.prepare(`SELECT o.id, o.op_number, o.delivery_date, o.brand FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date BETWEEN ? AND ? ORDER BY o.delivery_date`).all(today(), addDaysIso(today(), days));
    return rows.length ? [{ ref: 'all', text: `🟠 <b>${rows.length} OP(s) vencem em até ${days} dia(s)</b>\n${listLines(rows.map(r => `• ${opLink(r)} · ${tgEscape(r.brand || '-')} · ${formatDatePtBr(r.delivery_date)}`))}` }] : [];
  },
  no_delivery_date() {
    const n = db.prepare(`SELECT COUNT(*) AS n FROM ops o WHERE ${openOpsWhere()} AND (o.delivery_date IS NULL OR o.delivery_date = '')`).get().n;
    return n ? [{ ref: 'all', text: `📅 ${n} OP(s) em aberto sem data de entrega. <a href="${APP_BASE_URL}/ops?deadline=sem_data">Ver lista</a>` }] : [];
  },
  op_idle() {
    const days = paramOf('op_idle');
    const rows = db.prepare(`
      SELECT o.id, o.op_number, o.entry_date FROM ops o
      WHERE ${openOpsWhere()} AND o.status_color = 'verde' AND o.entry_date <= ?
        AND NOT EXISTS (SELECT 1 FROM op_daily_productions p WHERE p.op_id = o.id AND p.is_reversed = 0)
      ORDER BY o.entry_date`).all(addDaysIso(today(), -days));
    return rows.length ? [{ ref: 'all', text: `🟢 <b>${rows.length} OP(s) sem nenhum lançamento há ${days}+ dias</b>\n${listLines(rows.map(r => `• ${opLink(r)} · entrada ${formatDatePtBr(r.entry_date)}`))}` }] : [];
  },
  ready_not_shipped() {
    const days = paramOf('ready_not_shipped');
    const rows = db.prepare(`
      SELECT o.id, o.op_number, MAX(p.production_date) AS last_date FROM ops o
      LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
      WHERE o.is_reversed = 0 AND o.status_color = 'azul' AND o.shipped_at IS NULL
      GROUP BY o.id HAVING COALESCE(MAX(p.production_date), o.entry_date) <= ?`).all(addDaysIso(today(), -days));
    return rows.length ? [{ ref: 'all', text: `🔵 <b>${rows.length} OP(s) finalizada(s) aguardando embarque</b>\n${listLines(rows.map(r => `• ${opLink(r)}${r.last_date ? ` · último lançamento ${formatDatePtBr(r.last_date)}` : ''}`))}` }] : [];
  },
  occurrence_open() {
    const days = paramOf('occurrence_open');
    const rows = db.prepare(`
      SELECT oc.id, oc.description, oc.opened_at, o.id AS op_id, o.op_number FROM op_occurrences oc JOIN ops o ON o.id = oc.op_id
      WHERE oc.is_concluded = 0 AND date(oc.opened_at) <= ? ORDER BY oc.opened_at`).all(addDaysIso(today(), -days));
    return rows.length ? [{ ref: 'all', text: `⚠️ <b>${rows.length} ocorrência(s) aberta(s) há ${days}+ dias</b>\n${listLines(rows.map(r => `• ${opLink({ id: r.op_id, op_number: r.op_number })}: ${tgEscape(String(r.description).slice(0, 80))}`))}` }] : [];
  },
  quality_issue() {
    const mark = getAlertSetting('alert_mark_quality_issue');
    if (mark === '') { setAlertSetting('alert_mark_quality_issue', db.prepare('SELECT COALESCE(MAX(id), 0) AS n FROM op_problem_items').get().n); return []; }
    const last = Number(mark);
    const rows = db.prepare(`SELECT pi.id, pi.quantity, pi.reason, o.id AS op_id, o.op_number FROM op_problem_items pi JOIN ops o ON o.id = pi.op_id WHERE pi.id > ? ORDER BY pi.id`).all(last);
    if (rows.length) setAlertSetting('alert_mark_quality_issue', rows[rows.length - 1].id);
    return rows.map(r => ({ ref: `pi${r.id}`, text: `🧷 Peça com problema: ${r.quantity} pç na OP ${opLink({ id: r.op_id, op_number: r.op_number })} · ${tgEscape(String(r.reason).slice(0, 100))}` }));
  },
  reject_rate() {
    const limit = paramOf('reject_rate');
    const range = getPeriodRange('month', today());
    const problems = db.prepare('SELECT COALESCE(SUM(quantity), 0) AS n FROM op_problem_items WHERE problem_date BETWEEN ? AND ?').get(range.start, range.end).n;
    const produced = db.prepare('SELECT COALESCE(SUM(produced_quantity), 0) AS n FROM op_daily_productions WHERE is_reversed = 0 AND production_date BETWEEN ? AND ?').get(range.start, range.end).n;
    const rate = produced > 0 ? round2((problems / produced) * 100) : 0;
    return rate > limit ? [{ ref: 'all', text: `🧷 Taxa de reprovação do período em <b>${fmtNum(rate, 2)}%</b> (limite ${fmtNum(limit, 2)}%): ${problems} pç com problema em ${fmtNum(produced, 0)} produzidas.` }] : [];
  },
  no_launch() {
    const day = lastBusinessDayBefore(today());
    const employees = getActiveEmployees().filter(emp => getEmployeeBusinessDaysInRange(emp, day, day).length);
    const launched = new Set(db.prepare('SELECT DISTINCT employee_id FROM op_daily_productions WHERE is_reversed = 0 AND production_date = ?').all(day).map(r => r.employee_id));
    const absent = new Set(db.prepare('SELECT employee_id FROM employee_absences WHERE absence_date = ?').all(day).map(r => r.employee_id));
    const justified = new Set(db.prepare('SELECT employee_id FROM employee_daily_closures WHERE work_date = ?').all(day).map(r => r.employee_id));
    const missing = employees.filter(e => !launched.has(e.id) && !absent.has(e.id) && !justified.has(e.id));
    return missing.length ? [{ ref: day, text: `👤 <b>${missing.length} colaboradora(s) sem lançamento em ${formatDatePtBr(day)}</b> (sem ausência ou justificativa)\n${listLines(missing.map(e => `• ${tgEscape(e.full_name)}`))}\n<a href="${APP_BASE_URL}/closures">Tratar no fechamento</a>` }] : [];
  },
  below_target() {
    const snap = getTargetSnapshot();
    const below = snap.rows.filter(r => r.pct < r.target).sort((a, b) => a.pct - b.pct);
    return below.length ? [{ ref: 'all', text: `📉 <b>${below.length} colaboradora(s) abaixo da meta</b> até ${formatDatePtBr(snap.cutoff)}\n${listLines(below.map(r => `• ${tgEscape(r.emp.full_name)}: ${fmtNum(r.pct, 1)}% (meta ${fmtPct(r.target)}%)`))}` }] : [];
  },
  company_below_target() {
    const snap = getTargetSnapshot();
    return snap.total.base > 0 && snap.total.pct < targetPercent()
      ? [{ ref: 'all', text: `🏭 Eficiência da empresa em <b>${fmtNum(snap.total.pct, 2)}%</b> até ${formatDatePtBr(snap.cutoff)}, abaixo da meta de ${tp()}%.` }]
      : [];
  },
  pending_closure() {
    const limit = paramOf('pending_closure');
    const range = getPeriodRange('month', today());
    const end = [range.end, getPreviousBusinessDay(today())].sort()[0];
    if (end < range.start) return [];
    const data = getMonthlyClosureData(range.start, 'custom', '', range.start, end);
    const pending = Number(data?.totals?.pending || 0);
    return pending > limit ? [{ ref: 'all', text: `📋 ${pending} dia(s) pendente(s) no fechamento do período (limite ${limit}). <a href="${APP_BASE_URL}/closures">Abrir fechamento</a>` }] : [];
  },
  off_schedule() {
    const day = lastBusinessDayBefore(today());
    const rows = db.prepare(`
      SELECT e.full_name, o.op_number, p.produced_minutes FROM op_daily_productions p
      JOIN employees e ON e.id = p.employee_id JOIN ops o ON o.id = p.op_id
      WHERE p.is_reversed = 0 AND COALESCE(p.counts_for_prize, 1) = 0 AND p.production_date BETWEEN ? AND ?`).all(day, addDaysIso(today(), -1));
    return rows.length ? [{ ref: 'all', text: `⏱️ <b>${rows.length} lançamento(s) fora do prêmio</b> desde ${formatDatePtBr(day)}\n${listLines(rows.map(r => `• ${tgEscape(r.full_name)} · OP ${tgEscape(r.op_number)} · ${fmtNum(r.produced_minutes, 0)} min`))}` }] : [];
  },
  birthday() {
    const mmdd = today().slice(5);
    const rows = getActiveEmployees().filter(e => String(e.birth_date || '').slice(5) === mmdd);
    return rows.length ? [{ ref: 'all', text: `🎂 Aniversário hoje: ${rows.map(e => `<b>${tgEscape(e.full_name)}</b>`).join(', ')}` }] : [];
  },
  shipment_created() {
    const mark = getAlertSetting('alert_mark_shipment_created');
    if (mark === '') { setAlertSetting('alert_mark_shipment_created', db.prepare('SELECT COALESCE(MAX(id), 0) AS n FROM shipments').get().n); return []; }
    const last = Number(mark);
    const rows = db.prepare('SELECT id, shipment_number, shipment_date, total_ops, sewing_minutes FROM shipments WHERE id > ? AND COALESCE(is_reversed, 0) = 0 ORDER BY id').all(last);
    if (rows.length) setAlertSetting('alert_mark_shipment_created', rows[rows.length - 1].id);
    return rows.map(r => ({ ref: `sh${r.id}`, text: `🚚 Embarque <b>${tgEscape(r.shipment_number)}</b> em ${formatDatePtBr(r.shipment_date)}: ${r.total_ops} OP(s), ${fmtNum(r.sewing_minutes, 0)} min de costura.` }));
  },
  unbilled() {
    const days = paramOf('unbilled');
    const rows = db.prepare(`SELECT o.id, o.op_number, o.shipped_at FROM ops o WHERE o.is_reversed = 0 AND o.shipped_at IS NOT NULL AND COALESCE(o.is_billed, 0) = 0 AND COALESCE(o.lifecycle_type, 'normal') = 'normal' AND date(o.shipped_at) <= ? ORDER BY o.shipped_at`).all(addDaysIso(today(), -days));
    return rows.length ? [{ ref: 'all', text: `💵 <b>${rows.length} OP(s) embarcada(s) há ${days}+ dias sem cobrança</b>\n${listLines(rows.map(r => `• ${opLink(r)} · embarque ${formatDatePtBr(String(r.shipped_at).slice(0, 10))}`))}` }] : [];
  },
  reversal() {
    const since = getAlertSetting('alert_mark_reversal');
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    setAlertSetting('alert_mark_reversal', now);
    if (!since) return [];
    const ops = db.prepare('SELECT id, op_number, reversed_reason, reversed_at FROM ops WHERE is_reversed = 1 AND reversed_at > ? AND reversed_at <= ?').all(since, now)
      .map(r => ({ ref: `rop${r.id}`, text: `↩️ OP ${tgEscape(r.op_number)} estornada. Motivo: ${tgEscape(r.reversed_reason || '-')}` }));
    const prods = db.prepare(`SELECT p.id, o.op_number, e.full_name, p.reversed_reason FROM op_daily_productions p JOIN ops o ON o.id = p.op_id LEFT JOIN employees e ON e.id = p.employee_id WHERE p.is_reversed = 1 AND p.reversed_at > ? AND p.reversed_at <= ?`).all(since, now)
      .map(r => ({ ref: `rp${r.id}`, text: `↩️ Lançamento estornado: OP ${tgEscape(r.op_number)} · ${tgEscape(r.full_name || '-')}. Motivo: ${tgEscape(r.reversed_reason || '-')}` }));
    const ships = db.prepare('SELECT id, shipment_number, reversed_reason FROM shipments WHERE is_reversed = 1 AND reversed_at > ? AND reversed_at <= ?').all(since, now)
      .map(r => ({ ref: `rs${r.id}`, text: `↩️ Embarque ${tgEscape(r.shipment_number)} estornado. Motivo: ${tgEscape(r.reversed_reason || '-')}` }));
    return [...ops, ...prods, ...ships];
  },
  login_blocked() {
    const company = getRequestAuth()?.company;
    if (!company) return [];
    const since = getAlertSetting('alert_mark_login_blocked');
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    setAlertSetting('alert_mark_login_blocked', now);
    if (!since) return [];
    const rows = masterDb.prepare(`
      SELECT username, ip, COUNT(*) AS n FROM login_attempts
      WHERE scope = 'company' AND success = 0 AND company_slug = ? AND created_at > ? AND created_at <= ?
      GROUP BY username, ip HAVING COUNT(*) >= ?`).all(String(company.slug).toLowerCase(), since, now, LOGIN_MAX_FAILURES);
    return rows.map(r => ({ ref: `lb${r.username}:${r.ip}`, text: `🔐 Login bloqueado: usuário <b>${tgEscape(r.username)}</b>, ${r.n} tentativas erradas (IP ${tgEscape(r.ip)}).` }));
  }
};

function buildDailySummary() {
  const yesterday = lastBusinessDayBefore(today());
  const minutesYesterday = db.prepare(`
    SELECT COALESCE(SUM(p.produced_minutes), 0) AS m, COALESCE(SUM(p.produced_quantity), 0) AS q
    FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date = ?`).get(yesterday);
  const snap = getTargetSnapshot();
  const due = db.prepare(`SELECT COUNT(*) AS n FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date BETWEEN ? AND ?`).get(today(), addDaysIso(today(), 3)).n;
  const late = db.prepare(`SELECT COUNT(*) AS n FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date IS NOT NULL AND o.delivery_date <> '' AND o.delivery_date < ?`).get(today()).n;
  const cells = db.prepare('SELECT COUNT(DISTINCT op_id) AS n FROM op_cell_transfers WHERE quantity_sent > quantity_returned AND sent_at <= ?').get(addDaysIso(today(), -paramOf('cell_stuck'))).n;
  const below = snap.rows.filter(r => r.pct < r.target).length;
  let queue = null;
  try { queue = getQueueForecast(); } catch (_) {}
  return [
    `☀️ <b>Bom dia! Resumo ${tgEscape(getCompanyName())}</b> · ${formatDatePtBr(today())}`,
    '',
    `• Produção de ${formatDatePtBr(yesterday)}: <b>${fmtNum(minutesYesterday.m, 0)} min</b> (${fmtNum(minutesYesterday.q, 0)} pç)`,
    `• Eficiência até ${formatDatePtBr(snap.cutoff)}: <b>${fmtNum(snap.total.pct, 2)}%</b> (meta ${tp()}%)`,
    `• Colaboradoras abaixo da meta: ${below} de ${snap.rows.length}`,
    `• Entregas: ${late} atrasada(s), ${due} vencem em até 3 dias`,
    `• OPs paradas em célula (${paramOf('cell_stuck')}+ dias): ${cells}`,
    queue && queue.queueDays !== null ? `• Fila: ${fmtNum(queue.queueDays, 1)} dias úteis (término ${formatDatePtBr(queue.finishDate)})` : '',
    '',
    `<a href="${APP_BASE_URL}/">Abrir o AgilFac</a>`
  ].filter(line => line !== '').join('\n');
}


function buildOpAgenda() {
  const tomorrow = addBusinessDays(today(), 1);
  const dueToday = db.prepare(`SELECT o.id, o.op_number, o.brand FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date = ? ORDER BY o.op_number`).all(today());
  const dueTomorrow = db.prepare(`SELECT o.id, o.op_number, o.brand FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date > ? AND o.delivery_date <= ? ORDER BY o.op_number`).all(today(), tomorrow);
  const late = db.prepare(`SELECT COUNT(*) AS n FROM ops o WHERE ${openOpsWhere()} AND o.delivery_date IS NOT NULL AND o.delivery_date <> '' AND o.delivery_date < ?`).get(today()).n;
  const ready = db.prepare("SELECT COUNT(*) AS n FROM ops WHERE is_reversed = 0 AND status_color = 'azul' AND shipped_at IS NULL").get().n;
  const cells = db.prepare(`
    SELECT c.name, COUNT(DISTINCT t.op_id) AS n FROM op_cell_transfers t JOIN sewing_cells c ON c.id = t.cell_id
    WHERE t.quantity_sent > t.quantity_returned AND t.sent_at <= ? GROUP BY c.name ORDER BY n DESC`).all(addDaysIso(today(), -paramOf('cell_stuck')));
  const noLaunch = (ALERT_RULES.no_launch()[0]?.text || '').split('\n').length - 2;
  const lines = [
    `📋 <b>Agenda do dia · ${tgEscape(getCompanyName())}</b> · ${formatDatePtBr(today())}`,
    '',
    dueToday.length ? `🔴 <b>Entregar hoje (${dueToday.length}):</b>\n${listLines(dueToday.map(r => `• ${opLink(r)} · ${tgEscape(r.brand || '-')}`), 10)}` : '✅ Nenhuma entrega vencendo hoje',
    dueTomorrow.length ? `🟠 <b>Próximo dia útil (${dueTomorrow.length}):</b>\n${listLines(dueTomorrow.map(r => `• ${opLink(r)} · ${tgEscape(r.brand || '-')}`), 10)}` : '',
    late ? `⛔ ${late} OP(s) já atrasada(s)` : '',
    ready ? `🔵 ${ready} OP(s) prontas aguardando embarque` : '',
    cells.length ? `🩷 Células com OP parada (${paramOf('cell_stuck')}+ dias): ${cells.map(c => `${tgEscape(c.name)} (${c.n})`).join(', ')}` : '',
    noLaunch > 0 ? `👤 ${noLaunch} colaboradora(s) sem lançamento no último dia útil` : '',
    '',
    `<a href="${APP_BASE_URL}/">Abrir o AgilFac</a>`
  ];
  return lines.filter(Boolean).join('\n');
}

function buildWeeklyReport() {
  const end = addDaysIso(today(), -1);
  const start = addDaysIso(today(), -7);
  const prod = db.prepare(`
    SELECT COALESCE(SUM(p.produced_minutes), 0) AS m, COALESCE(SUM(p.produced_quantity), 0) AS q
    FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date BETWEEN ? AND ?`).get(start, end);
  const ships = db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(total_ops), 0) AS ops, COALESCE(SUM(sewing_minutes), 0) AS m FROM shipments WHERE COALESCE(is_reversed, 0) = 0 AND shipment_date BETWEEN ? AND ?').get(start, end);
  const unbilled = db.prepare("SELECT COUNT(*) AS n FROM ops WHERE is_reversed = 0 AND shipped_at IS NOT NULL AND COALESCE(is_billed, 0) = 0 AND COALESCE(lifecycle_type, 'normal') = 'normal'").get().n;
  const snap = getTargetSnapshot();
  const sorted = [...snap.rows].sort((a, b) => b.pct - a.pct);
  const top = sorted.slice(0, 5);
  const bottom = sorted.slice(-5).reverse().filter(r => !top.includes(r));
  const below = snap.rows.filter(r => r.pct < r.target).length;
  return [
    `📊 <b>Relatório semanal · ${tgEscape(getCompanyName())}</b>`,
    `Semana ${formatDatePtBr(start)} a ${formatDatePtBr(end)}`,
    '',
    `• Produção: <b>${fmtNum(prod.m, 0)} min</b> (${fmtNum(prod.q, 0)} pç)`,
    `• Embarques: ${ships.n} (${ships.ops} OPs, ${fmtNum(ships.m, 0)} min de costura)`,
    `• OPs embarcadas aguardando cobrança: ${unbilled}`,
    `• Eficiência do período até ${formatDatePtBr(snap.cutoff)}: <b>${fmtNum(snap.total.pct, 2)}%</b> (meta ${tp()}%) · ${below} de ${snap.rows.length} abaixo da meta`,
    top.length ? `\n🏆 <b>Melhores</b>\n${top.map(r => `• ${tgEscape(r.emp.full_name)}: ${fmtNum(r.pct, 1)}%`).join('\n')}` : '',
    bottom.length ? `\n⚠️ <b>Precisam de atenção</b>\n${bottom.map(r => `• ${tgEscape(r.emp.full_name)}: ${fmtNum(r.pct, 1)}%`).join('\n')}` : '',
    '',
    `<a href="${APP_BASE_URL}/closures">Ver fechamento</a>`
  ].filter(line => line !== '').join('\n');
}

const SUMMARY_BUILDERS = { daily_summary: () => buildDailySummary(), op_agenda: () => buildOpAgenda(), weekly_report: () => buildWeeklyReport() };

function ensureAlertTables(tenantDb) {
  tenantDb.exec(`
    CREATE TABLE IF NOT EXISTS alert_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rule TEXT NOT NULL,
      ref TEXT NOT NULL,
      alert_date TEXT NOT NULL,
      sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (rule, ref, alert_date)
    )
  `);
}

function currentBrHour() {
  return Number(BUSINESS_HOUR_FMT.format(new Date()));
}

function audienceReady(aud) {
  return Boolean(getAudienceToken(aud) && getTelegramChats(aud).length);
}

// Roda as regras marcadas desta empresa, para cada bot (gestor / operacional).
// force=true ignora horário e repetição (botão "Enviar teste agora").
async function runTenantAlerts({ force = false, only = null } = {}) {
  ensureAlertTables(getActiveDb());
  if (getAlertSetting('alerts_enabled') !== '1' && !force) return { sent: 0, messages: 0 };
  const audiences = ALERT_AUDIENCES.map(a => a.key).filter(a => (!only || only === a) && audienceReady(a));
  if (!audiences.length) return { sent: 0, messages: 0 };
  const hour = currentBrHour();
  const start = Number(getAlertSetting('alerts_start_hour'));
  const end = Number(getAlertSetting('alerts_end_hour'));
  const summaryHour = Number(getAlertSetting('alerts_summary_hour'));
  const dayKey = today();
  const weekdayOk = getAlertSetting('alerts_weekdays_only') !== '1' || isBusinessDay(dayKey);
  const inWindow = force || (weekdayOk && hour >= start && hour <= end);
  const hourKey = `${dayKey}T${String(hour).padStart(2, '0')}`;
  const ranHour = getAlertSetting('alerts_last_hour_run') === hourKey;
  const dailyDue = force || (weekdayOk && hour >= summaryHour && getAlertSetting('alerts_last_daily_run') !== dayKey);
  const isMonday = new Date(`${dayKey}T12:00:00Z`).getUTCDay() === 1;
  const weeklyDue = force || (isMonday && hour >= summaryHour && getAlertSetting('alerts_last_weekly_run') !== dayKey);
  const already = db.prepare('SELECT 1 FROM alert_log WHERE rule = ? AND ref = ? AND alert_date = ?');
  const logIt = db.prepare('INSERT OR IGNORE INTO alert_log (rule, ref, alert_date) VALUES (?, ?, ?)');
  const outbox = Object.fromEntries(audiences.map(a => [a, []]));

  for (const rule of ALERT_CATALOG) {
    const targets = audiences.filter(a => getAlertSetting(`alert_${a}_${rule.key}`) === '1');
    if (!targets.length) continue;
    const due = rule.freq === 'summary' ? dailyDue
      : rule.freq === 'weekly' ? weeklyDue
      : rule.freq === 'event' ? inWindow // fora do horário os eventos ficam guardados para a próxima janela
      : rule.freq === 'hourly' ? (inWindow && (force || !ranHour))
      : dailyDue;
    if (!due) continue;
    if (SUMMARY_BUILDERS[rule.key]) {
      let text = '';
      try { text = SUMMARY_BUILDERS[rule.key](); } catch (error) { console.error(`Resumo ${rule.key} (${getCompanyName()}):`, error.message); continue; }
      targets.forEach(a => outbox[a].push(text));
      continue;
    }
    let items = [];
    try { items = ALERT_RULES[rule.key]() || []; } catch (error) { console.error(`Alerta ${rule.key} (${getCompanyName()}):`, error.message); continue; }
    for (const a of targets) {
      const logKey = `${a}:${rule.key}`;
      const fresh = force ? items : items.filter(item => !already.get(logKey, String(item.ref), dayKey));
      if (!fresh.length) continue;
      if (!force) fresh.forEach(item => logIt.run(logKey, String(item.ref), dayKey));
      outbox[a].push(fresh.map(item => item.text).join('\n'));
    }
  }
  if (!force) {
    if (inWindow) setAlertSetting('alerts_last_hour_run', hourKey);
    if (dailyDue) setAlertSetting('alerts_last_daily_run', dayKey);
    if (weeklyDue) setAlertSetting('alerts_last_weekly_run', dayKey);
  }
  let sent = 0;
  let messages = 0;
  for (const a of audiences) {
    for (const message of outbox[a]) { messages += 1; sent += await sendTelegramToAll(message, a); }
  }
  return { sent, messages };
}

// ----- T2.5 Comandos de consulta (somente leitura, sem IA) -----
// Só respondem em grupos/conversas vinculados. No bot operacional não sai resultado individual.
const BOT_COMMANDS = [
  { command: 'op', description: 'Situação de uma OP: /op 1801138-001' },
  { command: 'pendentes', description: 'OPs em aberto por data de entrega' },
  { command: 'atrasadas', description: 'OPs com entrega vencida' },
  { command: 'rosas', description: 'OPs em célula, por célula' },
  { command: 'prontas', description: 'OPs finalizadas aguardando embarque' },
  { command: 'embarques', description: 'Embarques de hoje (ou /embarques 25/10, /embarques semana)' },
  { command: 'meta', description: 'Eficiência até o corte e produção de hoje' },
  { command: 'fila', description: 'Fila em dias úteis e término estimado' },
  { command: 'ajuda', description: 'Lista de comandos' }
];

const STATUS_TXT = { verde: '🟢 Em produção', amarelo: '🟡 Com ocorrência', rosa: '🩷 Em célula', azul: '🔵 Finalizada', vermelho: '🔴 Embarcada' };

function daysSince(dateText) {
  const d = String(dateText || '').slice(0, 10);
  if (!d) return 0;
  return Math.max(0, Math.round((new Date(`${today()}T00:00:00Z`) - new Date(`${d}T00:00:00Z`)) / 86400000));
}

function deliveryText(op) {
  if (!op.delivery_date) return 'sem data';
  const diff = Math.round((new Date(`${op.delivery_date}T00:00:00Z`) - new Date(`${today()}T00:00:00Z`)) / 86400000);
  if (op.delivery_date < today()) return `${formatDatePtBr(op.delivery_date)} (atrasada ${daysSince(op.delivery_date)}d)`;
  if (op.delivery_date === today()) return `${formatDatePtBr(op.delivery_date)} (hoje)`;
  return `${formatDatePtBr(op.delivery_date)} (em ${diff}d)`;
}

function openOpsWithRemaining() {
  return getOpList({}).filter(op => ['verde', 'amarelo', 'rosa'].includes(op.status_color) && !op.shipped_at && !isReturnedWithoutProductionLifecycle(op.lifecycle_type));
}

function parseBrDate(text) {
  const m = String(text || '').match(/^(\d{1,2})\/(\d{1,2})(?:\/(\d{2,4}))?$/);
  if (!m) return '';
  const year = m[3] ? (m[3].length === 2 ? `20${m[3]}` : m[3]) : today().slice(0, 4);
  const iso = `${year}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}`;
  return Number.isNaN(new Date(`${iso}T00:00:00Z`).getTime()) ? '' : iso;
}

const BOT_HANDLERS = {
  ajuda() {
    return `🤖 <b>AgilFac · ${tgEscape(getCompanyName())}</b>\n${BOT_COMMANDS.map(c => `/${c.command} — ${tgEscape(c.description)}`).join('\n')}`;
  },
  op(args) {
    if (!args) return 'Informe o número: <code>/op 1801138-001</code>';
    const found = getOpByNumber(args);
    if (!found) return `OP <b>${tgEscape(args)}</b> não encontrada.`;
    const op = getOpDetail(found.id)?.op;
    if (!op) return `OP <b>${tgEscape(args)}</b> não encontrada.`;
    const occ = db.prepare('SELECT description FROM op_occurrences WHERE op_id = ? AND is_concluded = 0 ORDER BY opened_at DESC').all(op.id);
    const ship = db.prepare('SELECT s.shipment_number, s.shipment_date FROM shipment_items si JOIN shipments s ON s.id = si.shipment_id WHERE si.op_id = ? AND s.is_reversed = 0 ORDER BY s.shipment_date DESC LIMIT 1').get(op.id);
    const cell = found.active_cell_name;
    return [
      `📦 <b>OP ${opLink(op)}</b> · ${STATUS_TXT[op.status_color] || tgEscape(op.status_color)}`,
      `${tgEscape(op.product_name || '-')} · ${tgEscape(op.brand || '-')}${op.op_type === 'mostruario' ? ' · mostruário' : ''}`,
      `Peças: ${fmtNum(op.total_pieces, 0)} · contadas ${fmtNum(op.counted_quantity, 0)} · faltam ${fmtNum(Math.max(op.remaining_quantity, 0), 0)}`,
      Number(op.problem_quantity) ? `Com problema: ${fmtNum(op.problem_quantity, 0)} pç` : '',
      cell ? `Em célula: <b>${tgEscape(cell)}</b> (${fmtNum(op.open_in_cells_quantity, 0)} pç)` : '',
      `Entrada: ${formatDatePtBr(op.entry_date)} · Entrega: ${deliveryText(op)}`,
      `Produzido: ${fmtNum(op.produced_minutes, 0)} min`,
      occ.length ? `⚠️ Ocorrência: ${occ.map(o => tgEscape(String(o.description).slice(0, 80))).join(' | ')}` : '',
      ship ? `🚚 Embarque ${tgEscape(ship.shipment_number)} em ${formatDatePtBr(ship.shipment_date)}` : ''
    ].filter(Boolean).join('\n');
  },
  pendentes() {
    const ops = openOpsWithRemaining().sort((a, b) => String(a.delivery_date || '9999').localeCompare(String(b.delivery_date || '9999')));
    if (!ops.length) return '✅ Nenhuma OP em aberto.';
    const pieces = ops.reduce((s, op) => s + Math.max(Number(op.remaining_quantity || 0), 0), 0);
    return `📋 <b>${ops.length} OP(s) em aberto</b> · ${fmtNum(pieces, 0)} pç a fazer\n${listLines(ops.map(op => `• ${opLink(op)} · ${tgEscape(op.brand || '-')} · faltam ${fmtNum(Math.max(op.remaining_quantity, 0), 0)} · ${deliveryText(op)}`), 20)}`;
  },
  atrasadas() {
    const ops = openOpsWithRemaining().filter(op => op.delivery_date && op.delivery_date < today()).sort((a, b) => a.delivery_date.localeCompare(b.delivery_date));
    if (!ops.length) return '✅ Nenhuma OP com entrega atrasada.';
    return `⛔ <b>${ops.length} OP(s) atrasada(s)</b>\n${listLines(ops.map(op => `• ${opLink(op)} · ${tgEscape(op.brand || '-')} · ${deliveryText(op)}`), 20)}`;
  },
  rosas() {
    const rows = db.prepare(`
      SELECT o.id, o.op_number, c.name AS cell_name, MIN(t.sent_at) AS sent_at, SUM(t.quantity_sent - t.quantity_returned) AS open_qty
      FROM op_cell_transfers t JOIN ops o ON o.id = t.op_id JOIN sewing_cells c ON c.id = t.cell_id
      WHERE t.quantity_sent > t.quantity_returned AND o.is_reversed = 0
      GROUP BY o.id, c.name ORDER BY c.name, sent_at`).all();
    if (!rows.length) return '✅ Nenhuma OP em célula.';
    const limit = paramOf('cell_stuck');
    const byCell = new Map();
    rows.forEach(r => { if (!byCell.has(r.cell_name)) byCell.set(r.cell_name, []); byCell.get(r.cell_name).push(r); });
    return `🩷 <b>${rows.length} OP(s) em célula</b>\n${[...byCell].map(([cell, list]) => `\n<b>${tgEscape(cell)}</b>\n${list.map(r => { const d = daysSince(r.sent_at); return `• ${opLink(r)} · ${r.open_qty} pç · ${d}d${d >= limit ? ' ⚠️' : ''}`; }).join('\n')}`).join('\n')}`;
  },
  prontas() {
    const rows = db.prepare("SELECT id, op_number, brand, total_pieces, delivery_date FROM ops WHERE is_reversed = 0 AND status_color = 'azul' AND shipped_at IS NULL ORDER BY COALESCE(delivery_date, '9999'), op_number").all();
    if (!rows.length) return 'Nenhuma OP finalizada aguardando embarque.';
    return `🔵 <b>${rows.length} OP(s) prontas para embarcar</b>\n${listLines(rows.map(r => `• ${opLink(r)} · ${tgEscape(r.brand || '-')} · ${fmtNum(r.total_pieces, 0)} pç · ${deliveryText(r)}`), 25)}`;
  },
  embarques(args) {
    let start = today();
    let end = today();
    let label = 'hoje';
    const arg = String(args || '').trim().toLowerCase();
    if (arg === 'ontem') { start = end = addDaysIso(today(), -1); label = 'ontem'; }
    else if (arg === 'semana') { start = addDaysIso(today(), -6); label = 'nos últimos 7 dias'; }
    else if (arg === 'mes' || arg === 'mês') { const r = getPeriodRange('month', today()); start = r.start; end = r.end; label = 'no período'; }
    else if (arg) { const d = parseBrDate(arg); if (!d) return 'Use: /embarques, /embarques ontem, /embarques semana, /embarques mes ou /embarques 25/10'; start = end = d; label = `em ${formatDatePtBr(d)}`; }
    const rows = db.prepare('SELECT shipment_number, shipment_date, total_ops, sewing_minutes, total_minutes FROM shipments WHERE COALESCE(is_reversed, 0) = 0 AND shipment_date BETWEEN ? AND ? ORDER BY shipment_date, id').all(start, end);
    if (!rows.length) return `🚚 Nenhum embarque ${label}.`;
    const ops = rows.reduce((s, r) => s + Number(r.total_ops || 0), 0);
    const minutes = rows.reduce((s, r) => s + Number(r.sewing_minutes || 0), 0);
    return `🚚 <b>${rows.length} embarque(s) ${label}</b> · ${ops} OP(s) · ${fmtNum(minutes, 0)} min de costura\n${listLines(rows.map(r => `• ${tgEscape(r.shipment_number)} · ${formatDatePtBr(r.shipment_date)} · ${r.total_ops} OP(s) · ${fmtNum(r.sewing_minutes, 0)} min`), 20)}`;
  },
  meta(args, aud) {
    const snap = getTargetSnapshot();
    const todayMin = db.prepare(`SELECT COALESCE(SUM(p.produced_minutes), 0) AS m FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date = ?`).get(today()).m;
    const active = getActiveEmployees().length;
    const goalToday = getActiveEmployees().reduce((sum, emp) => sum + baseMinutesDay() * employeeTargetRatio(emp), 0);
    const below = snap.rows.filter(r => r.pct < r.target).sort((a, b) => a.pct - b.pct);
    const lines = [
      `🎯 <b>Meta ${tp()}%</b> · ${tgEscape(getCompanyName())}`,
      `Eficiência até ${formatDatePtBr(snap.cutoff)}: <b>${fmtNum(snap.total.pct, 2)}%</b>`,
      `Hoje até agora: ${fmtNum(todayMin, 0)} min${goalToday > 0 ? ` de ~${fmtNum(goalToday, 0)} para a meta da equipe` : ''}`,
      `Abaixo da meta: ${below.length} de ${snap.rows.length}`
    ];
    if (aud === 'gestor' && snap.rows.length) {
      const sorted = [...snap.rows].sort((a, b) => b.pct - a.pct);
      lines.push('', sorted.map(r => `${r.pct >= r.target ? '✅' : '🔻'} ${tgEscape(r.emp.full_name)}: ${fmtNum(r.pct, 1)}%${r.target !== targetPercent() ? ` (meta ${fmtPct(r.target)}%)` : ''}`).join('\n'));
    }
    return lines.join('\n');
  },
  fila() {
    const f = getQueueForecast();
    if (f.queueDays === null) return `Fila: ${f.openOps} OP(s), ${fmtNum(f.queuePieces, 0)} pç. Sem produção recente para estimar os dias.`;
    return `⏳ <b>Fila: ${fmtNum(f.queueDays, 1)} dias úteis</b>\n${f.openOps} OP(s) · ${fmtNum(f.queuePieces, 0)} pç · ${fmtNum(f.queueMinutes, 0)} min\nCapacidade: ${fmtNum(f.dailyCapacity, 0)} min/dia (últimos ${f.sampleDays} dias úteis)\nTérmino estimado: ${formatDatePtBr(f.finishDate)}`;
  }
};
const BOT_ALIASES = { start: 'ajuda', help: 'ajuda', comandos: 'ajuda', embarque: 'embarques', rosa: 'rosas', celulas: 'rosas', pendente: 'pendentes', atrasada: 'atrasadas', pronta: 'prontas' };

function findChatAudience(audiences, chatId) {
  const linked = audiences.filter(a => getTelegramChats(a.key).some(c => String(c.id) === String(chatId)));
  return linked.find(a => a.key === 'gestor') || linked[0] || null;
}

async function handleBotCommand(token, audiences, msg) {
  const text = String(msg.text || '').trim();
  const m = text.match(/^\/([a-zà-ú]+)(?:@\w+)?(?:\s+([\s\S]*))?$/i);
  if (!m) return;
  const cmd = BOT_ALIASES[m[1].toLowerCase()] || m[1].toLowerCase();
  const args = String(m[2] || '').trim();
  const chat = msg.chat;
  const reply = body => telegramCall(token, 'sendMessage', { chat_id: chat.id, text: body.slice(0, 4000), parse_mode: 'HTML', disable_web_page_preview: true, reply_to_message_id: msg.message_id, allow_sending_without_reply: true }).catch(error => console.error('Telegram resposta:', error.message));
  if (cmd === 'vincular' || (m[1].toLowerCase() === 'start' && args)) {
    const typed = args.split(/\s+/)[0].toUpperCase();
    const target = audiences.find(a => ensureTelegramLinkCode(a.key) === typed);
    if (!target) return reply('Código inválido. Envie <code>/vincular CÓDIGO</code> com o código que aparece em Parâmetros → Alertas Telegram.');
    const chats = getTelegramChats(target.key).filter(c => String(c.id) !== String(chat.id));
    chats.push({ id: chat.id, title: chat.title || [chat.first_name, chat.last_name].filter(Boolean).join(' ') || chat.username || String(chat.id), type: chat.type, linked_at: new Date().toISOString() });
    setAlertSetting(target.chatsKey, JSON.stringify(chats));
    return reply(`✅ Conversa vinculada ao ${target.title.toLowerCase()} de ${tgEscape(getCompanyName())}.\nEnvie /ajuda para ver os comandos.`);
  }
  const aud = findChatAudience(audiences, chat.id);
  if (!aud) {
    if (chat.type === 'private') return reply('Esta conversa não está autorizada. Envie <code>/vincular CÓDIGO</code> (código em Parâmetros → Alertas Telegram).');
    return; // grupo não vinculado: fica em silêncio
  }
  const handler = BOT_HANDLERS[cmd];
  if (!handler) return reply(`Comando não reconhecido. ${BOT_HANDLERS.ajuda()}`);
  let body;
  try { body = handler(args, aud.key); } catch (error) {
    console.error(`Comando /${cmd} (${getCompanyName()}):`, error.message);
    body = 'Não consegui consultar agora. Tente de novo em instantes.';
  }
  return reply(body);
}

// Lê as mensagens de cada bot (a cada poucos segundos): /vincular e comandos de consulta.
async function pollTenantTelegram() {
  const byToken = new Map();
  for (const a of ALERT_AUDIENCES) {
    const token = getAudienceToken(a.key);
    if (!token) continue;
    if (!byToken.has(token)) byToken.set(token, []);
    byToken.get(token).push(a);
  }
  for (const [token, audiences] of byToken) {
    const offsetKey = `telegram_offset_${crypto.createHash('sha256').update(token).digest('hex').slice(0, 10)}`;
    const offset = Number(getAlertSetting(offsetKey) || 0);
    const updates = await telegramCall(token, 'getUpdates', { offset, timeout: 0, allowed_updates: ['message'] });
    for (const update of updates) {
      setAlertSetting(offsetKey, update.update_id + 1);
      const msg = update.message;
      if (!msg || !msg.text || !msg.chat || !msg.text.trim().startsWith('/')) continue;
      await handleBotCommand(token, audiences, msg);
    }
  }
}

let telegramPollBusy = false;
const telegramPollErrors = new Map();
async function runTelegramPolling() {
  if (telegramPollBusy) return;
  telegramPollBusy = true;
  try {
    const companies = masterDb.prepare('SELECT * FROM companies WHERE is_active = 1').all();
    for (const company of companies) {
      let tenantDb;
      try { tenantDb = getTenantDbForCompany(company); } catch (_) { continue; }
      await requestContext.run({ tenantDb, auth: { company, user: null, role: 'adm' } }, async () => {
        try { await pollTenantTelegram(); } catch (error) {
          // Loga no máximo uma vez a cada 10 min por empresa (rede instável não enche o log)
          const last = telegramPollErrors.get(company.slug) || 0;
          if (!/Conflict|terminated/i.test(error.message) && Date.now() - last > 600000) {
            telegramPollErrors.set(company.slug, Date.now());
            console.error(`Telegram polling (${company.slug}):`, error.message);
          }
        }
      });
    }
  } catch (error) {
    console.error('Polling Telegram:', error.message);
  } finally {
    telegramPollBusy = false;
  }
}

let alertWorkerBusy = false;
async function runAlertWorker() {
  if (alertWorkerBusy) return;
  alertWorkerBusy = true;
  try {
    const companies = masterDb.prepare('SELECT * FROM companies WHERE is_active = 1').all();
    for (const company of companies) {
      let tenantDb;
      try { tenantDb = getTenantDbForCompany(company); } catch (_) { continue; }
      await requestContext.run({ tenantDb, auth: { company, user: null, role: 'adm' } }, async () => {
        try { await runTenantAlerts(); } catch (error) { console.error(`Alertas (${company.slug}):`, error.message); }
      });
    }
  } catch (error) {
    console.error('Worker de alertas:', error.message);
  } finally {
    alertWorkerBusy = false;
  }
}

// Correção única: lançamentos feitos antes do cadastro do tempo extra (últimos 45 dias)
function runExtraTimeRecalcOnce() {
  for (const company of masterDb.prepare('SELECT * FROM companies WHERE is_active = 1').all()) {
    let tenantDb;
    try { tenantDb = getTenantDbForCompany(company); } catch (_) { continue; }
    requestContext.run({ tenantDb, auth: { company, user: null, role: 'adm' } }, () => {
      try {
        if (getAlertSetting('extra_time_recalc_v1')) return;
        const since = addDaysIso(today(), -45);
        const configs = db.prepare('SELECT op_id, MIN(effective_date) AS first_date FROM op_extra_times WHERE is_active = 1 GROUP BY op_id').all();
        let rows = 0;
        let delta = 0;
        for (const c of configs) {
          const r = recalculateExtraMinutesForOp(c.op_id, [c.first_date, since].sort().reverse()[0]);
          rows += r.rows;
          delta += r.delta;
        }
        setAlertSetting('extra_time_recalc_v1', JSON.stringify({ at: new Date().toISOString(), rows, delta: round2(delta) }));
        if (rows) console.log(`Tempo extra (${company.slug}): ${rows} lançamento(s) recalculado(s), ${round2(delta)} min.`);
      } catch (error) {
        console.error(`Recalcular tempo extra (${company.slug}):`, error.message);
      }
    });
  }
}
setTimeout(runExtraTimeRecalcOnce, 3000).unref();

if (process.env.AGILFAC_DISABLE_ALERTS !== '1') {
  setTimeout(() => runAlertWorker().catch(() => {}), Number(process.env.AGILFAC_ALERT_FIRST_MS || 15000)).unref();
  setInterval(() => runAlertWorker().catch(() => {}), Number(process.env.AGILFAC_ALERT_INTERVAL_MS || 60000)).unref();
  setInterval(() => runTelegramPolling().catch(() => {}), Number(process.env.AGILFAC_TG_POLL_MS || 4000)).unref();
}

// ----- tela (seção dentro de Parâmetros) -----
function renderAlertsSection() {
  const groups = [...new Set(ALERT_CATALOG.map(r => r.group))];
  const freqLabel = { hourly: 'verifica de hora em hora', daily: 'diário', event: 'avisa na hora', summary: 'diário', weekly: 'segundas-feiras' };
  const botCards = ALERT_AUDIENCES.map(a => {
    const own = getAlertSetting(a.tokenKey);
    const chats = getTelegramChats(a.key);
    const code = ensureTelegramLinkCode(a.key);
    const usingShared = a.key === 'op' && !own && getAlertSetting('telegram_bot_token');
    return `
      <div class="alert-bot">
        <h4>${escapeHtml(a.title)}</h4>
        <p class="hint">${escapeHtml(a.desc)}</p>
        <label>Token do bot (criado no @BotFather)
          <input type="password" name="${a.tokenKey}" autocomplete="off" placeholder="${own ? `Salvo: ${escapeHtml(maskToken(own))} — em branco mantém` : (a.key === 'op' ? 'Opcional: em branco usa o bot do gestor' : '123456789:AA...')}" />
        </label>
        ${own ? `<label class="checkbox-line"><input type="checkbox" name="clear_${a.tokenKey}" value="1" /> Remover este token</label>` : ''}
        ${usingShared ? '<p class="hint">Usando o mesmo bot do gestor — vincule outro grupo com o código abaixo.</p>' : ''}
        <div class="alerts-link">Adicione o bot ao grupo (ou abra a conversa com ele) e envie <code>/vincular ${escapeHtml(code)}</code>. Em até 1 minuto aparece aqui.
          <ul class="alerts-chats">
            ${chats.map(c => `<li>${escapeHtml(c.title)} <span class="hint">(${escapeHtml(c.type || '')})</span> <button class="btn secondary" type="submit" name="remove_chat" value="${a.key}|${escapeHtml(String(c.id))}" formnovalidate>Remover</button></li>`).join('') || '<li class="hint">Nenhuma conversa vinculada.</li>'}
          </ul>
        </div>
        <button class="btn secondary" type="submit" name="action" value="test_${a.key}">Enviar teste para ${escapeHtml(a.label.toLowerCase())}</button>
      </div>`;
  }).join('');
  return `
    <section class="panel" id="alertas">
      <h3>Alertas Telegram</h3>
      <form method="post" action="/parametros/alertas" class="alerts-form">
        <label class="checkbox-line"><input type="checkbox" name="alerts_enabled" value="1" ${getAlertSetting('alerts_enabled') === '1' ? 'checked' : ''} /> <strong>Alertas ligados</strong></label>
        <div class="alert-bots">${botCards}</div>
        <div class="form-grid">
          <label>Enviar a partir de (hora)<input type="number" name="alerts_start_hour" min="0" max="23" value="${escapeHtml(getAlertSetting('alerts_start_hour'))}" /></label>
          <label>Até (hora)<input type="number" name="alerts_end_hour" min="0" max="23" value="${escapeHtml(getAlertSetting('alerts_end_hour'))}" /></label>
          <label>Hora dos resumos e alertas diários<input type="number" name="alerts_summary_hour" min="0" max="23" value="${escapeHtml(getAlertSetting('alerts_summary_hour'))}" /></label>
          <label class="checkbox-line"><input type="checkbox" name="alerts_weekdays_only" value="1" ${getAlertSetting('alerts_weekdays_only') === '1' ? 'checked' : ''} /> Só em dias úteis</label>
        </div>
        <p class="hint">Marque em cada alerta quem recebe: <strong>G</strong> = bot do gestor, <strong>O</strong> = bot operacional.</p>
        ${groups.map(group => `
          <fieldset class="alerts-group"><legend>${escapeHtml(group)}</legend>
            ${ALERT_CATALOG.filter(r => r.group === group).map(rule => `
              <div class="alert-rule">
                <div class="alert-rule-head">
                  <strong>${escapeHtml(rule.label)}</strong>
                  <span class="alert-aud">
                    ${ALERT_AUDIENCES.map(a => `<label title="${escapeHtml(a.title)}"><input type="checkbox" name="alert_${a.key}_${rule.key}" value="1" ${getAlertSetting(`alert_${a.key}_${rule.key}`) === '1' ? 'checked' : ''} /> ${a.key === 'gestor' ? 'G' : 'O'}</label>`).join('')}
                  </span>
                </div>
                ${rule.param ? `<label class="alert-param">${rule.param.key === 'percent' ? 'acima de' : rule.param.key === 'count' ? 'mais de' : 'a partir de'} <input type="number" name="alert_param_${rule.key}" min="0" step="${rule.param.key === 'percent' ? '0.1' : '1'}" value="${escapeHtml(getAlertSetting(`alert_param_${rule.key}`))}" /> ${escapeHtml(rule.param.label)}</label>` : ''}
                <small class="hint">${escapeHtml(rule.help)} · ${freqLabel[rule.freq]}</small>
              </div>`).join('')}
          </fieldset>`).join('')}
        <div class="actions"><button class="btn" type="submit">Salvar alertas</button></div>
      </form>
    </section>`;
}

async function handleSaveAlerts(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const isOn = v => (Array.isArray(v) ? v.includes('1') : v === '1');
  const back = msg => redirect(res, `/parametros?notice=${encodeURIComponent(msg)}#alertas`);
  const fail = msg => redirect(res, `/parametros?error=${encodeURIComponent(msg)}#alertas`);
  if (form.remove_chat) {
    const [audKey, chatId] = String(form.remove_chat).split('|');
    const a = getAudience(audKey);
    setAlertSetting(a.chatsKey, JSON.stringify(getTelegramChats(a.key).filter(c => String(c.id) !== String(chatId))));
    return back('Conversa removida.');
  }
  let tokenMsg = '';
  for (const a of ALERT_AUDIENCES) {
    if (form[`clear_${a.tokenKey}`] === '1') { setAlertSetting(a.tokenKey, ''); continue; }
    const newToken = String(form[a.tokenKey] || '').trim();
    if (!newToken) continue;
    if (!/^\d{5,}:[A-Za-z0-9_-]{20,}$/.test(newToken)) return fail(`${a.title}: token inválido. Copie o token completo enviado pelo @BotFather.`);
    try {
      const me = await telegramCall(newToken, 'getMe');
      setAlertSetting(a.tokenKey, newToken);
      tokenMsg += ` ${a.title}: @${me.username || 'bot'} validado.`;
      telegramCall(newToken, 'setMyCommands', { commands: BOT_COMMANDS }).catch(() => {});
    } catch (error) {
      return fail(`${a.title}: o Telegram recusou o token (${error.message}).`);
    }
  }
  setAlertSetting('alerts_enabled', isOn(form.alerts_enabled) ? '1' : '0');
  setAlertSetting('alerts_weekdays_only', form.alerts_weekdays_only === '1' ? '1' : '0');
  for (const key of ['alerts_start_hour', 'alerts_end_hour', 'alerts_summary_hour']) {
    const n = Math.round(Number(form[key]));
    if (form[key] !== undefined && form[key] !== '' && Number.isFinite(n) && n >= 0 && n <= 23) setAlertSetting(key, n);
  }
  for (const rule of ALERT_CATALOG) {
    for (const a of ALERT_AUDIENCES) setAlertSetting(`alert_${a.key}_${rule.key}`, isOn(form[`alert_${a.key}_${rule.key}`]) ? '1' : '0');
    if (rule.param) {
      const n = Number(String(form[`alert_param_${rule.key}`] ?? '').replace(',', '.'));
      if (form[`alert_param_${rule.key}`] !== '' && Number.isFinite(n) && n >= 0) setAlertSetting(`alert_param_${rule.key}`, n);
    }
  }
  const test = String(form.action || '').match(/^test_(gestor|op)$/);
  if (test) {
    const a = getAudience(test[1]);
    if (!getAudienceToken(a.key)) return fail(`Salve o token do ${a.title.toLowerCase()} antes de testar.`);
    if (!getTelegramChats(a.key).length) return fail(`Vincule ao menos um grupo ou conversa no ${a.title.toLowerCase()} antes de testar.`);
    try {
      await sendTelegramToAll(`🔔 Teste do ${tgEscape(a.title.toLowerCase())} — ${tgEscape(getCompanyName())}. Abaixo, os alertas marcados para este bot com o que existe agora.`, a.key);
      const result = await runTenantAlerts({ force: true, only: a.key });
      return back(`Teste enviado ao ${a.title.toLowerCase()}: ${result.messages} mensagem(ns) de alerta.`);
    } catch (error) {
      return fail(`Falha no teste: ${error.message}`);
    }
  }
  back(`Alertas salvos.${tokenMsg}`);
}
// ===============================================================

// ===================== API DE LEITURA (Fiel) =====================
// Somente leitura, chave por empresa gerada em Parâmetros. Formato: agf_<empresa>_<segredo>.
// Guardamos só o hash da chave. Resultado por colaboradora só sai se a empresa permitir.
const apiRateLimit = new Map();

function generateApiKey(slug) {
  const key = `agf_${slug}_${crypto.randomBytes(24).toString('hex')}`;
  setAlertSetting('api_key_hash', crypto.createHash('sha256').update(key).digest('hex'));
  setAlertSetting('api_key_hint', key.slice(-4));
  setAlertSetting('api_key_created_at', nowPt(new Date().toISOString()));
  setAlertSetting('api_key_last_used', '');
  return key;
}

function stripTags(html) {
  return String(html || '').replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function apiOp(op) {
  const remaining = Math.max(Number(op.remaining_quantity || 0), 0);
  const daysToDelivery = op.delivery_date ? Math.round((new Date(`${op.delivery_date}T00:00:00Z`) - new Date(`${today()}T00:00:00Z`)) / 86400000) : null;
  return {
    numero: op.op_number,
    link: `${APP_BASE_URL}/ops/${op.id}`,
    produto: op.product_name || null,
    marca: op.brand || null,
    colecao: op.collection_name || null,
    tipo: op.op_type === 'mostruario' ? 'mostruario' : 'producao',
    situacao: stripTags(STATUS_TXT[op.status_color] || op.status_color).replace(/^\S+\s/, ''),
    cor_status: op.status_color,
    pecas_total: Number(op.total_pieces || 0),
    pecas_contadas: Number(op.counted_quantity || 0),
    pecas_faltam: remaining,
    pecas_com_problema: Number(op.problem_quantity || 0),
    celula: op.active_cell_name || null,
    pecas_em_celula: Math.max(Number(op.open_in_cells_quantity || 0), 0),
    minutos_por_peca: Number(op.minutes_f21 || 0),
    minutos_faltam: round2(remaining * Number(op.minutes_f21 || 0)),
    minutos_produzidos: round2(Number(op.produced_minutes || 0)),
    entrada: op.entry_date || null,
    entrega: op.delivery_date || null,
    dias_para_entrega: daysToDelivery,
    atrasada: Boolean(op.delivery_date && op.delivery_date < today() && !op.shipped_at),
    embarcada_em: op.shipped_at ? String(op.shipped_at).slice(0, 10) : null,
    cobrada: Boolean(op.is_billed)
  };
}

function apiDateRange(query, defaultDays = 30) {
  const valid = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || ''));
  const end = valid(query.fim) ? query.fim : today();
  const start = valid(query.inicio) ? query.inicio : addDaysIso(end, -(defaultDays - 1));
  return start <= end ? { start, end } : { start: end, end: start };
}

const API_ROUTES = {
  resumo() {
    const snap = getTargetSnapshot();
    const open = openOpsWithRemaining();
    const f = getQueueForecast();
    const todayMin = db.prepare(`SELECT COALESCE(SUM(p.produced_minutes), 0) AS m, COALESCE(SUM(p.produced_quantity), 0) AS q FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date = ?`).get(today());
    const lastDay = getPreviousBusinessDay(today());
    const lastMin = db.prepare(`SELECT COALESCE(SUM(p.produced_minutes), 0) AS m FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date = ?`).get(lastDay).m;
    return {
      empresa: getCompanyName(),
      data: today(),
      meta_percentual: targetPercent(),
      periodo: { inicio: snap.range.start, fim: snap.range.end, corte: snap.cutoff },
      eficiencia_ate_corte: snap.total.pct,
      minutos_ate_corte: snap.total.minutes,
      minutos_base_ate_corte: snap.total.base,
      colaboradoras_ativas: getActiveEmployees().length,
      colaboradoras_abaixo_da_meta: snap.rows.filter(r => r.pct < r.target).length,
      producao_hoje: { minutos: round2(todayMin.m), pecas: Number(todayMin.q) },
      producao_ultimo_dia_util: { data: lastDay, minutos: round2(lastMin) },
      ops_em_aberto: open.length,
      ops_atrasadas: open.filter(op => op.delivery_date && op.delivery_date < today()).length,
      ops_vencem_3_dias: open.filter(op => op.delivery_date && op.delivery_date >= today() && op.delivery_date <= addDaysIso(today(), 3)).length,
      ops_sem_data_entrega: open.filter(op => !op.delivery_date).length,
      ops_em_celula: open.filter(op => op.status_color === 'rosa').length,
      ops_com_ocorrencia: open.filter(op => op.status_color === 'amarelo').length,
      ops_prontas_aguardando_embarque: db.prepare("SELECT COUNT(*) AS n FROM ops WHERE is_reversed = 0 AND status_color = 'azul' AND shipped_at IS NULL").get().n,
      ops_embarcadas_sem_cobranca: db.prepare("SELECT COUNT(*) AS n FROM ops WHERE is_reversed = 0 AND shipped_at IS NOT NULL AND COALESCE(is_billed, 0) = 0 AND COALESCE(lifecycle_type, 'normal') = 'normal'").get().n,
      fila: { dias_uteis: f.queueDays, termino_estimado: f.finishDate || null, minutos: f.queueMinutes, pecas: f.queuePieces, capacidade_minutos_dia: f.dailyCapacity }
    };
  },
  ops(query) {
    const situacao = String(query.situacao || 'aberta');
    let list = getOpList({}).filter(op => !op.is_reversed);
    const isOpen = op => ['verde', 'amarelo', 'rosa'].includes(op.status_color) && !op.shipped_at && !isReturnedWithoutProductionLifecycle(op.lifecycle_type);
    const filters = {
      aberta: isOpen,
      atrasada: op => isOpen(op) && op.delivery_date && op.delivery_date < today(),
      celula: op => op.status_color === 'rosa',
      ocorrencia: op => op.status_color === 'amarelo',
      pronta: op => op.status_color === 'azul' && !op.shipped_at,
      embarcada: op => Boolean(op.shipped_at),
      sem_cobranca: op => Boolean(op.shipped_at) && !op.is_billed,
      todas: () => true
    };
    if (!filters[situacao]) return { erro: `situacao inválida. Use: ${Object.keys(filters).join(', ')}`, status: 400 };
    list = list.filter(filters[situacao]);
    if (query.marca) list = list.filter(op => String(op.brand || '').toLowerCase().includes(String(query.marca).toLowerCase()));
    if (query.busca) { const q = String(query.busca).toLowerCase(); list = list.filter(op => `${op.op_number} ${op.product_name} ${op.brand} ${op.collection_name}`.toLowerCase().includes(q)); }
    list.sort((a, b) => String(a.delivery_date || '9999').localeCompare(String(b.delivery_date || '9999')) || String(a.op_number).localeCompare(String(b.op_number)));
    const limit = Math.min(Math.max(Number(query.limite) || 200, 1), 1000);
    return { situacao, total: list.length, ops: list.slice(0, limit).map(apiOp) };
  },
  op(query, numero) {
    const found = getOpByNumber(numero);
    const detail = found ? getOpDetail(found.id) : null;
    if (!detail) return { erro: 'OP não encontrada', status: 404 };
    const op = { ...detail.op, active_cell_name: found.active_cell_name };
    return {
      ...apiOp(op),
      ocorrencias_abertas: detail.occurrences.filter(o => !o.is_concluded).map(o => ({ aberta_em: o.opened_at, descricao: o.description })),
      pecas_com_problema_detalhe: detail.problemHistory.map(p => ({ data: p.problem_date, quantidade: p.quantity, motivo: p.reason })),
      embarques: detail.shipmentHistory.map(s => ({ numero: s.shipment_number, data: s.shipment_date, minutos_costura: s.sewing_minutes })),
      producao_por_dia: Object.values(detail.history.reduce((acc, h) => {
        acc[h.production_date] = acc[h.production_date] || { data: h.production_date, pecas: 0, minutos: 0 };
        acc[h.production_date].pecas += Number(h.produced_quantity || 0);
        acc[h.production_date].minutos = round2(acc[h.production_date].minutos + Number(h.produced_minutes || 0));
        return acc;
      }, {})).sort((a, b) => a.data.localeCompare(b.data))
    };
  },
  producao(query) {
    const { start, end } = apiDateRange(query, 30);
    const days = db.prepare(`SELECT p.production_date AS data, ROUND(SUM(p.produced_minutes), 2) AS minutos, SUM(p.produced_quantity) AS pecas FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date BETWEEN ? AND ? GROUP BY p.production_date ORDER BY p.production_date`).all(start, end);
    const brands = db.prepare(`SELECT COALESCE(NULLIF(o.brand, ''), 'Sem marca') AS marca, ROUND(SUM(p.produced_minutes), 2) AS minutos, SUM(p.produced_quantity) AS pecas FROM op_daily_productions p JOIN ops o ON o.id = p.op_id WHERE ${COUNTED_PRODUCTION_WHERE} AND p.production_date BETWEEN ? AND ? GROUP BY 1 ORDER BY minutos DESC`).all(start, end);
    const total = days.reduce((s, d) => s + Number(d.minutos || 0), 0);
    return { inicio: start, fim: end, minutos_total: round2(total), pecas_total: days.reduce((s, d) => s + Number(d.pecas || 0), 0), por_dia: days, por_marca: brands, observacao: 'Considera só lançamentos que contam para eficiência e prêmio.' };
  },
  eficiencia(query) {
    // ?periodo=anterior traz o período fechado anterior inteiro
    let snap = getTargetSnapshot();
    if (query.periodo === 'anterior') snap = getTargetSnapshot(addDaysIso(snap.range.start, -1));
    const result = {
      periodo: { inicio: snap.range.start, fim: snap.range.end, corte: snap.cutoff },
      meta_percentual: targetPercent(),
      base_minutos_dia: baseMinutesDay(),
      empresa: { percentual: snap.total.pct, minutos: snap.total.minutes, minutos_base: snap.total.base },
      colaboradoras_total: snap.rows.length,
      colaboradoras_abaixo_da_meta: snap.rows.filter(r => r.pct < r.target).length
    };
    if (getAlertSetting('api_allow_individual') === '1') {
      result.colaboradoras = [...snap.rows].sort((a, b) => b.pct - a.pct).map(r => ({ nome: r.emp.full_name, percentual: r.pct, minutos: r.minutes, minutos_base: r.base, meta_percentual: r.target, atingiu_meta: r.pct >= r.target }));
    } else {
      result.colaboradoras = null;
      result.observacao = 'Resultado por colaboradora desativado em Parâmetros → API de leitura.';
    }
    return result;
  },
  embarques(query) {
    const { start, end } = apiDateRange(query, 30);
    const rows = db.prepare('SELECT id, shipment_number, shipment_date, total_ops, sewing_minutes, post_sewing_minutes, total_minutes FROM shipments WHERE COALESCE(is_reversed, 0) = 0 AND shipment_date BETWEEN ? AND ? ORDER BY shipment_date, id').all(start, end);
    const items = db.prepare('SELECT si.op_number FROM shipment_items si WHERE si.shipment_id = ?');
    return {
      inicio: start, fim: end,
      total_embarques: rows.length,
      total_ops: rows.reduce((s, r) => s + Number(r.total_ops || 0), 0),
      minutos_costura: round2(rows.reduce((s, r) => s + Number(r.sewing_minutes || 0), 0)),
      embarques: rows.map(r => ({ numero: r.shipment_number, data: r.shipment_date, ops: items.all(r.id).map(i => i.op_number), minutos_costura: r.sewing_minutes, minutos_pos_costura: r.post_sewing_minutes, minutos_total: r.total_minutes }))
    };
  },
  fila() {
    const f = getQueueForecast();
    return { ops_em_aberto: f.openOps, pecas: f.queuePieces, minutos: f.queueMinutes, capacidade_minutos_dia: f.dailyCapacity, dias_uteis: f.queueDays, termino_estimado: f.finishDate || null, dias_amostra: f.sampleDays };
  },
  alertas() {
    const keys = ['cell_stuck', 'delivery_late', 'delivery_soon', 'no_delivery_date', 'op_idle', 'ready_not_shipped', 'occurrence_open', 'reject_rate', 'company_below_target', 'unbilled'];
    if (getAlertSetting('api_allow_individual') === '1') keys.push('no_launch', 'below_target');
    const out = [];
    for (const key of keys) {
      const rule = ALERT_CATALOG.find(r => r.key === key);
      try {
        const items = ALERT_RULES[key]() || [];
        if (items.length) out.push({ alerta: key, titulo: rule.label, itens: items.map(i => stripTags(i.text)) });
      } catch (_) { /* regra com problema não derruba a resposta */ }
    }
    return { data: today(), alertas: out };
  }
};

async function handleReadApi(req, res, pathname, query) {
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization', 'Cache-Control': 'no-store' };
  const send = (payload, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...cors }); res.end(JSON.stringify(payload)); };
  if (req.method === 'OPTIONS') { res.writeHead(204, { ...cors, 'Access-Control-Allow-Methods': 'GET' }); return res.end(); }
  if (req.method !== 'GET') return send({ erro: 'Somente leitura (GET).' }, 405);
  const header = String(req.headers.authorization || '');
  const key = header.replace(/^Bearer\s+/i, '').trim();
  const m = key.match(/^agf_([a-z0-9-]+)_([a-f0-9]{48})$/);
  if (!m) return send({ erro: 'Chave ausente ou inválida. Envie Authorization: Bearer <chave>.' }, 401);
  const now = Date.now();
  const rl = apiRateLimit.get(key) || { start: now, count: 0 };
  if (now - rl.start > 60000) { rl.start = now; rl.count = 0; }
  rl.count += 1;
  apiRateLimit.set(key, rl);
  if (rl.count > 120) return send({ erro: 'Limite de 120 consultas por minuto.' }, 429);
  const company = masterDb.prepare('SELECT * FROM companies WHERE LOWER(slug) = ? AND is_active = 1').get(m[1]);
  if (!company) return send({ erro: 'Chave inválida.' }, 401);
  let tenantDb;
  try { tenantDb = getTenantDbForCompany(company); } catch (_) { return send({ erro: 'Empresa indisponível.' }, 503); }
  return requestContext.run({ tenantDb, auth: { company, user: null, role: 'api' } }, async () => {
    const stored = getAlertSetting('api_key_hash');
    const hash = crypto.createHash('sha256').update(key).digest('hex');
    if (!stored || stored.length !== hash.length || !crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(hash))) return send({ erro: 'Chave inválida.' }, 401);
    if (getAlertSetting('api_last_used_minute') !== String(Math.floor(now / 60000))) {
      setAlertSetting('api_last_used_minute', String(Math.floor(now / 60000)));
      setAlertSetting('api_key_last_used', nowPt(new Date().toISOString()));
    }
    const parts = pathname.replace(/^\/api\/v1\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
    const route = parts[0] || '';
    if (!route) return send({ api: 'AgilFac leitura v1', empresa: getCompanyName(), rotas: ['/api/v1/resumo', '/api/v1/ops?situacao=aberta|atrasada|celula|ocorrencia|pronta|embarcada|sem_cobranca|todas&marca=&busca=&limite=', '/api/v1/ops/<numero>', '/api/v1/producao?inicio=AAAA-MM-DD&fim=AAAA-MM-DD', '/api/v1/eficiencia?periodo=atual|anterior', '/api/v1/embarques?inicio=&fim=', '/api/v1/fila', '/api/v1/alertas'] });
    try {
      let result;
      if (route === 'ops' && parts[1]) result = API_ROUTES.op(query, parts[1]);
      else if (API_ROUTES[route] && route !== 'op') result = API_ROUTES[route](query);
      else return send({ erro: 'Rota não encontrada. Veja /api/v1' }, 404);
      if (result && result.erro) return send({ erro: result.erro }, result.status || 400);
      return send(result);
    } catch (error) {
      console.error(`API ${pathname} (${company.slug}):`, error.message);
      return send({ erro: 'Falha ao consultar.' }, 500);
    }
  });
}

function renderApiSection(slug) {
  const hint = getAlertSetting('api_key_hint');
  return `
    <section class="panel" id="api">
      <h3>API de leitura (Fiel e integrações)</h3>
      <p class="hint">Permite que o Fiel (e outros sistemas autorizados) consultem OPs, entregas, produção, eficiência, fila e embarques. Só leitura: nada é alterado no AgilFac.</p>
      <form method="post" action="/parametros/api" class="alerts-form">
        <p>${hint ? `Chave ativa terminando em <strong>…${escapeHtml(hint)}</strong> · criada em ${escapeHtml(getAlertSetting('api_key_created_at'))}${getAlertSetting('api_key_last_used') ? ` · último uso ${escapeHtml(getAlertSetting('api_key_last_used'))}` : ' · ainda não usada'}` : 'Nenhuma chave gerada.'}</p>
        <p class="hint">Endereço: <code>${escapeHtml(APP_BASE_URL)}/api/v1</code> · cabeçalho <code>Authorization: Bearer &lt;chave&gt;</code></p>
        <label class="checkbox-line"><input type="checkbox" name="api_allow_individual" value="1" ${getAlertSetting('api_allow_individual') === '1' ? 'checked' : ''} /> Permitir resultado por colaboradora (nome e eficiência)</label>
        <div class="actions">
          <button class="btn secondary" type="submit" name="action" value="save">Salvar</button>
          <button class="btn" type="submit" name="action" value="generate" ${hint ? 'onclick="return confirm(\'Gerar nova chave? A atual para de funcionar.\')"' : ''}>${hint ? 'Gerar nova chave' : 'Gerar chave'}</button>
          ${hint ? '<button class="btn secondary" type="submit" name="action" value="revoke" onclick="return confirm(\'Revogar a chave? As integrações param de funcionar.\')">Revogar</button>' : ''}
        </div>
      </form>
    </section>`;
}

function handleSaveApi(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  setAlertSetting('api_allow_individual', form.api_allow_individual === '1' ? '1' : '0');
  if (form.action === 'revoke') {
    ['api_key_hash', 'api_key_hint', 'api_key_created_at', 'api_key_last_used'].forEach(k => setAlertSetting(k, ''));
    return redirect(res, `/parametros?notice=${encodeURIComponent('Chave revogada.')}#api`);
  }
  if (form.action === 'generate') {
    const slug = String(getRequestAuth()?.company?.slug || '').toLowerCase();
    const key = generateApiKey(slug);
    return sendHtml(res, pageLayout({
      title: 'Chave da API gerada',
      role,
      content: `
        <section class="panel">
          <h3>Copie a chave agora</h3>
          <p>Ela aparece <strong>só esta vez</strong>. Cole no Fiel (módulo Gestor de produção). Não envie por mensagem nem e-mail.</p>
          <p><input type="text" readonly value="${escapeHtml(key)}" style="width:100%;font-family:monospace" onclick="this.select()" /></p>
          <div class="actions"><button class="btn secondary" type="button" onclick="navigator.clipboard.writeText('${escapeHtml(key)}');this.textContent='Copiada'">Copiar</button><a class="btn" href="/parametros#api">Voltar para Parâmetros</a></div>
        </section>`
    }));
  }
  return redirect(res, `/parametros?notice=${encodeURIComponent('API de leitura atualizada.')}#api`);
}
// ===============================================================

// ===================== IMPORTAÇÃO DE AUSÊNCIAS (Pontomais por arquivo) =====================
// O administrador exporta um relatório do Pontomais (Excel ou CSV), envia aqui, confere a prévia e confirma.
// Ausência já lançada à mão não é sobrescrita (mesma colaboradora + mesmo dia é ignorado).
const ABSENCE_IMPORT_TYPES = [
  ['atestado', 'Atestado'], ['ferias', 'Férias'], ['folga', 'Folga'], ['afastamento', 'Afastamento'], ['falta', 'Falta'], ['outro', 'Outro'], ['ignorar', 'Não importar']
];
const absenceImportSessions = new Map();

function normalizeText(value) {
  return String(value ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function shortHash(value) {
  return crypto.createHash('sha1').update(String(value)).digest('hex').slice(0, 10);
}

function parseCsvText(text) {
  // Separador: o que mais aparece nas primeiras linhas (relatórios do Pontomais começam com linhas de título)
  const sample = text.split(/\r?\n/).slice(0, 30).join('\n').replace(/"[^"]*"/g, '');
  const delimiter = [';', '\t', ','].map(d => [d, sample.split(d).length]).sort((a, b) => b[1] - a[1])[0][0];
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i += 1; }
      else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === delimiter) { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += ch;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

function readSpreadsheetRows(buffer, fileName) {
  const isZip = buffer.length > 4 && buffer[0] === 0x50 && buffer[1] === 0x4b;
  const isOldXls = buffer.length > 4 && buffer[0] === 0xd0 && buffer[1] === 0xcf;
  if (!isZip && !isOldXls) {
    let text = buffer.toString('utf8');
    if (text.includes('�')) text = buffer.toString('latin1');
    return parseCsvText(text.replace(/^﻿/, ''));
  }
  const XLSX = require('xlsx');
  const book = XLSX.read(buffer, { type: 'buffer', cellDates: false });
  let best = [];
  for (const name of book.SheetNames) {
    const rows = XLSX.utils.sheet_to_json(book.Sheets[name], { header: 1, raw: true, defval: '' });
    if (rows.length > best.length) best = rows;
  }
  return best;
}

function cellToText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'number') return String(value);
  return String(value).trim();
}

// Datas: dd/mm/aaaa, dd/mm/aa, aaaa-mm-dd ou número de data do Excel. Pode haver duas datas (período) na mesma célula.
function extractDates(value) {
  if (typeof value === 'number' && value > 20000 && value < 80000) {
    // Datas gravadas como "23:59:59 do dia anterior" (arredondamento de planilha) contam como o dia seguinte
    const serial = value % 1 > 0.99 ? Math.ceil(value) : Math.floor(value);
    const p = require('xlsx').SSF.parse_date_code(serial);
    return p ? [`${p.y}-${String(p.m).padStart(2, '0')}-${String(p.d).padStart(2, '0')}`] : [];
  }
  const text = String(value || '');
  const found = [];
  const re = /(\d{4})-(\d{2})-(\d{2})|(\d{1,2})\/(\d{1,2})\/(\d{2,4})/g;
  let m;
  while ((m = re.exec(text))) {
    let iso;
    if (m[1]) iso = `${m[1]}-${m[2]}-${m[3]}`;
    else iso = `${m[6].length === 2 ? `20${m[6]}` : m[6]}-${m[5].padStart(2, '0')}-${m[4].padStart(2, '0')}`;
    const d = new Date(`${iso}T00:00:00Z`);
    if (!Number.isNaN(d.getTime()) && iso === d.toISOString().slice(0, 10)) found.push(iso);
  }
  return found;
}

function guessAbsenceType(reason) {
  const r = normalizeText(reason);
  if (!r) return '';
  if (/atest|medic|doenc|cid\b|saude|consulta|hospital/.test(r)) return 'atestado';
  if (/ferias/.test(r)) return 'ferias';
  if (/afast|licen|inss|matern|patern|acidente|auxilio/.test(r)) return 'afastamento';
  if (/folga|compens|banco de horas|abono|dispensa|day ?off/.test(r)) return 'folga';
  if (/falta|ausencia|nao compareceu/.test(r)) return 'falta';
  return 'outro';
}

function guessColumns(headers) {
  const find = re => { const i = headers.findIndex(h => re.test(normalizeText(h))); return i >= 0 ? String(i) : ''; };
  return {
    emp: find(/colaborador|funcionari|nome|empregado/),
    start: find(/inicio|data inicial|^de$|periodo|^data$|data da|dia/),
    end: find(/fim|final|termino|^ate$|data final|retorno/),
    reason: find(/motivo|tipo|justific|ocorrencia|excec|descri|nota|observ|evento/),
    flag: find(/atestado\?|e atestado|eh atestado/)
  };
}

function detectHeaderRow(rows) {
  const keywords = /colaborador|funcionari|nome|data|inicio|motivo|tipo|periodo/;
  for (let i = 0; i < Math.min(rows.length, 20); i += 1) {
    const cells = rows[i].map(cellToText).filter(Boolean);
    if (cells.length >= 2 && cells.some(c => keywords.test(normalizeText(c)))) return i;
  }
  return 0;
}

function matchEmployee(name, employees) {
  const n = normalizeText(name).replace(/^\d+\s*[-–]\s*/, '');
  if (!n) return null;
  const exact = employees.find(e => normalizeText(e.full_name) === n);
  if (exact) return exact;
  const byCode = employees.find(e => e.registration_code && normalizeText(e.registration_code) === n);
  if (byCode) return byCode;
  const parts = n.split(' ');
  if (parts.length >= 2) {
    const firstLast = employees.filter(e => { const p = normalizeText(e.full_name).split(' '); return p[0] === parts[0] && p[p.length - 1] === parts[parts.length - 1]; });
    if (firstLast.length === 1) return firstLast[0];
  }
  const contains = employees.filter(e => normalizeText(e.full_name).includes(n) || n.includes(normalizeText(e.full_name)));
  return contains.length === 1 ? contains[0] : null;
}

function buildAbsenceImportPreview(session, form) {
  const cols = {
    emp: form.col_emp ?? session.guess.emp,
    start: form.col_start ?? session.guess.start,
    end: form.col_end ?? session.guess.end,
    reason: form.col_reason ?? session.guess.reason,
    flag: form.col_flag ?? session.guess.flag
  };
  const isYes = v => /^(sim|s|yes|true|1|x)$/i.test(normalizeText(v));
  const defaultType = form.default_type || 'atestado';
  const employees = db.prepare('SELECT id, full_name, registration_code, start_date, termination_date FROM employees ORDER BY full_name').all();
  const existing = db.prepare('SELECT 1 FROM employee_absences WHERE employee_id = ? AND absence_date = ?');
  const reasons = new Map();
  const names = new Map();
  const lines = [];
  let lastName = '';
  for (const raw of session.rows) {
    const nameCell = cols.emp !== '' ? cellToText(raw[Number(cols.emp)]) : '';
    if (nameCell) lastName = nameCell;
    const name = nameCell || lastName;
    const startDates = cols.start !== '' ? extractDates(raw[Number(cols.start)]) : [];
    if (!name || !startDates.length) continue;
    const endDates = cols.end !== '' ? extractDates(raw[Number(cols.end)]) : [];
    let start = startDates[0];
    let end = endDates[0] || startDates[1] || '';
    if (!end) {
      // Sem término (ex.: afastamento INSS em aberto): vale até o fim do período do relatório
      const endCellEmpty = cols.end !== '' && !cellToText(raw[Number(cols.end)]);
      end = endCellEmpty ? (session.period?.end || today()) : start;
      if (endCellEmpty && session.period?.start && start < session.period.start) start = session.period.start;
    }
    if (end < start) end = start;
    if (enumerateDates(start, end).length > 200) end = addDaysIso(start, 199);
    const note = cols.reason !== '' ? cellToText(raw[Number(cols.reason)]) : '';
    const flagged = cols.flag !== '' ? isYes(raw[Number(cols.flag)]) : false;
    const reason = cols.flag !== '' && flagged ? `Atestado${note ? ` (${note})` : ''}` : note;
    // Agrupa motivos parecidos ("2 DIAS", "3 DIAS" com atestado = Sim viram um grupo só)
    const groupText = flagged ? 'Atestado (É atestado? = Sim)' : (note || '(sem motivo)');
    const reasonKey = shortHash(normalizeText(groupText));
    const guessed = flagged ? 'atestado' : (note ? guessAbsenceType(note) : (cols.flag !== '' ? 'outro' : defaultType));
    if (!reasons.has(reasonKey)) reasons.set(reasonKey, { key: reasonKey, text: groupText, count: 0, type: form[`type_${reasonKey}`] || guessed });
    reasons.get(reasonKey).count += 1;
    const nameKey = shortHash(normalizeText(name));
    if (!names.has(nameKey)) {
      const override = form[`emp_${nameKey}`];
      const auto = matchEmployee(name, employees);
      const chosen = override === 'ignorar' ? null : (override ? employees.find(e => String(e.id) === String(override)) : auto);
      names.set(nameKey, { key: nameKey, text: name, auto, employee: chosen || null, ignored: override === 'ignorar', count: 0 });
    }
    names.get(nameKey).count += 1;
    lines.push({ name, nameKey, reason, reasonKey, start, end });
  }
  let toInsert = [];
  let skippedExisting = 0;
  let skippedIgnored = 0;
  let skippedNoEmployee = 0;
  for (const line of lines) {
    const person = names.get(line.nameKey);
    const type = reasons.get(line.reasonKey).type;
    const days = enumerateDates(line.start, line.end).filter(isBusinessDay);
    line.days = days.length;
    line.type = type;
    line.employee = person.employee;
    if (!person.employee) { skippedNoEmployee += days.length; line.status = person.ignored ? 'ignorada' : 'sem colaboradora'; continue; }
    if (type === 'ignorar') { skippedIgnored += days.length; line.status = 'não importar'; continue; }
    let added = 0;
    for (const day of days) {
      if (existing.get(person.employee.id, day) || toInsert.some(t => t.employee_id === person.employee.id && t.day === day)) { skippedExisting += 1; continue; }
      toInsert.push({ employee_id: person.employee.id, day, type, reason: line.reason });
      added += 1;
    }
    line.status = added ? `${added} dia(s) novo(s)` : 'já lançado';
  }
  return { cols, defaultType, employees, reasons: [...reasons.values()], names: [...names.values()], lines, toInsert, skippedExisting, skippedIgnored, skippedNoEmployee };
}

function renderAbsenceImportUpload(role, error = '') {
  const content = `
    <section class="page-header">
      <div>
        <h2>Importar ausências do Pontomais</h2>
        <p>Envie o relatório exportado do Pontomais (Excel ou CSV). Você confere a prévia antes de gravar. Ausências já lançadas à mão não são alteradas.</p>
      </div>
    </section>
    <section class="panel">
      <form method="post" action="/ausencias/importar" id="absence-upload">
        <input type="hidden" name="action" value="upload" />
        <input type="hidden" name="file_b64" id="file_b64" />
        <input type="hidden" name="file_name" id="file_name" />
        <label>Arquivo (.xlsx, .xls ou .csv)
          <input type="file" id="file_input" accept=".xlsx,.xls,.csv,text/csv" required />
        </label>
        <div class="actions"><button class="btn" type="submit" id="upload_btn">Enviar e ver prévia</button></div>
        <p class="hint">No Pontomais: relatório de afastamentos/ausências ou "Exceções de jornada e atestados" de um período fechado, exportado em Excel ou CSV. O relatório precisa ter o nome da colaboradora, a data (ou início e fim) e, de preferência, o motivo.</p>
      </form>
    </section>
    <script>
      (function () {
        const form = document.getElementById('absence-upload');
        form.addEventListener('submit', function (event) {
          event.preventDefault();
          const file = document.getElementById('file_input').files[0];
          if (!file) return;
          if (file.size > 8 * 1024 * 1024) { alert('Arquivo maior que 8 MB. Exporte um período menor.'); return; }
          const reader = new FileReader();
          reader.onload = function () {
            document.getElementById('file_b64').value = String(reader.result).split(',')[1] || '';
            document.getElementById('file_name').value = file.name;
            document.getElementById('upload_btn').disabled = true;
            document.getElementById('upload_btn').textContent = 'Lendo arquivo…';
            form.submit();
          };
          reader.readAsDataURL(file);
        });
      })();
    </script>`;
  return pageLayout({ title: 'Importar ausências', content, error, role });
}

function renderAbsenceImportPreview(sessionId, session, preview, role, error = '') {
  const colSelect = (name, value, optional) => `
    <select name="${name}">
      ${optional ? `<option value="" ${value === '' ? 'selected' : ''}>— não usar —</option>` : ''}
      ${session.headers.map((h, i) => `<option value="${i}" ${String(value) === String(i) ? 'selected' : ''}>${escapeHtml(h || `Coluna ${i + 1}`)}</option>`).join('')}
    </select>`;
  const typeSelect = (name, value) => `<select name="${name}">${ABSENCE_IMPORT_TYPES.map(([k, l]) => `<option value="${k}" ${value === k ? 'selected' : ''}>${l}</option>`).join('')}</select>`;
  const unmatched = preview.names.filter(n => !n.auto);
  const typeLabel = Object.fromEntries(ABSENCE_IMPORT_TYPES);
  const content = `
    <section class="page-header">
      <div>
        <h2>Importar ausências · prévia</h2>
        <p>Arquivo <strong>${escapeHtml(session.fileName)}</strong> · ${session.rows.length} linha(s) lida(s). Nada foi gravado ainda.</p>
      </div>
    </section>
    <form method="post" action="/ausencias/importar">
      <input type="hidden" name="session" value="${escapeHtml(sessionId)}" />
      <section class="panel">
        <h3>1. Colunas do arquivo</h3>
        <div class="form-grid">
          <label>Colaboradora${colSelect('col_emp', preview.cols.emp, false)}</label>
          <label>Data ou início${colSelect('col_start', preview.cols.start, false)}</label>
          <label>Data final${colSelect('col_end', preview.cols.end, true)}</label>
          <label>Motivo / notas${colSelect('col_reason', preview.cols.reason, true)}</label>
          <label>"É atestado?" (Sim/Não)${colSelect('col_flag', preview.cols.flag, true)}</label>
          ${preview.cols.reason === '' && preview.cols.flag === '' ? `<label>Tipo para todas as linhas${typeSelect('default_type', preview.defaultType)}</label>` : ''}
        </div>
        ${session.period ? `<p class="hint">Período do relatório: ${formatDatePtBr(session.period.start)} a ${formatDatePtBr(session.period.end)}. Afastamento sem data de término vale até ${formatDatePtBr(session.period.end)}.</p>` : ''}
        <p class="hint">Quando o relatório traz o nome numa linha e as datas embaixo, as linhas sem nome usam o último nome acima. Só entram dias úteis.</p>
      </section>
      ${preview.cols.reason !== '' || preview.cols.flag !== '' ? `
      <section class="panel">
        <h3>2. Como lançar cada motivo</h3>
        <div class="table-wrap"><table>
          <thead><tr><th>Motivo no Pontomais</th><th>Linhas</th><th>Lançar como</th></tr></thead>
          <tbody>${preview.reasons.map(r => `<tr><td>${escapeHtml(r.text)}</td><td>${r.count}</td><td>${typeSelect(`type_${r.key}`, r.type)}</td></tr>`).join('')}</tbody>
        </table></div>
      </section>` : ''}
      ${unmatched.length ? `
      <section class="panel">
        <h3>${preview.cols.reason !== '' || preview.cols.flag !== '' ? '3' : '2'}. Nomes não encontrados (${unmatched.length})</h3>
        <p class="hint">Escolha a colaboradora certa ou deixe "Não importar".</p>
        <div class="table-wrap"><table>
          <thead><tr><th>Nome no arquivo</th><th>Linhas</th><th>Colaboradora no AgilFac</th></tr></thead>
          <tbody>${unmatched.map(n => `<tr><td>${escapeHtml(n.text)}</td><td>${n.count}</td><td><select name="emp_${n.key}"><option value="ignorar">Não importar</option>${preview.employees.map(e => `<option value="${e.id}" ${n.employee && n.employee.id === e.id ? 'selected' : ''}>${escapeHtml(e.full_name)}${e.termination_date ? ' (desligada)' : ''}</option>`).join('')}</select></td></tr>`).join('')}</tbody>
        </table></div>
      </section>` : ''}
      <section class="panel">
        <h3>Resultado</h3>
        <div class="cards">
          <div class="mini-card"><span>Dias a gravar</span><strong>${preview.toInsert.length}</strong></div>
          <div class="mini-card"><span>Já lançados (mantidos)</span><strong>${preview.skippedExisting}</strong></div>
          <div class="mini-card"><span>Sem colaboradora</span><strong>${preview.skippedNoEmployee}</strong></div>
          <div class="mini-card"><span>Não importar</span><strong>${preview.skippedIgnored}</strong></div>
        </div>
        <div class="table-wrap"><table>
          <thead><tr><th>Nome no arquivo</th><th>Colaboradora</th><th>Período</th><th>Dias úteis</th><th>Motivo</th><th>Lançar como</th><th>Situação</th></tr></thead>
          <tbody>${preview.lines.slice(0, 400).map(l => `<tr><td>${escapeHtml(l.name)}</td><td>${l.employee ? escapeHtml(l.employee.full_name) : '<span class="hint">—</span>'}</td><td>${formatDatePtBr(l.start)}${l.end !== l.start ? ` a ${formatDatePtBr(l.end)}` : ''}</td><td>${l.days}</td><td>${escapeHtml(l.reason || '-')}</td><td>${escapeHtml(typeLabel[l.type] || l.type)}</td><td>${escapeHtml(l.status)}</td></tr>`).join('') || '<tr><td colspan="7">Nenhuma linha com nome e data. Confira as colunas acima.</td></tr>'}</tbody>
        </table></div>
        ${preview.lines.length > 400 ? `<p class="hint">Mostrando 400 de ${preview.lines.length} linhas.</p>` : ''}
        <div class="actions">
          <button class="btn secondary" type="submit" name="action" value="preview">Atualizar prévia</button>
          <button class="btn" type="submit" name="action" value="apply" ${preview.toInsert.length ? '' : 'disabled'} onclick="return confirm('Gravar ${preview.toInsert.length} dia(s) de ausência?')">Gravar ${preview.toInsert.length} dia(s)</button>
          <a class="btn secondary" href="/ausencias/importar">Outro arquivo</a>
        </div>
      </section>
    </form>`;
  return pageLayout({ title: 'Importar ausências', content, error, role });
}

async function handleAbsenceImport(req, res, role) {
  if (!isAdminRole(role)) return requireAdmin(req, res, role);
  const form = await parseBody(req, 12 * 1024 * 1024);
  const slug = String(getRequestAuth()?.company?.slug || '');
  for (const [key, value] of absenceImportSessions) if (Date.now() - value.createdAt > 3600000) absenceImportSessions.delete(key);
  if (form.action === 'upload') {
    let rows;
    try {
      const buffer = Buffer.from(String(form.file_b64 || ''), 'base64');
      if (!buffer.length) return sendHtml(res, renderAbsenceImportUpload(role, 'Selecione um arquivo.'));
      rows = readSpreadsheetRows(buffer, String(form.file_name || ''));
    } catch (error) {
      return sendHtml(res, renderAbsenceImportUpload(role, `Não consegui ler o arquivo: ${error.message}`));
    }
    rows = rows.filter(r => Array.isArray(r) && r.some(c => cellToText(c)));
    if (rows.length < 2) return sendHtml(res, renderAbsenceImportUpload(role, 'O arquivo não tem linhas suficientes.'));
    const headerIndex = detectHeaderRow(rows);
    const width = Math.max(...rows.map(r => r.length));
    const headers = Array.from({ length: width }, (_, i) => cellToText(rows[headerIndex][i]) || `Coluna ${i + 1}`);
    const session = { slug, fileName: String(form.file_name || 'arquivo'), headers, rows: rows.slice(headerIndex + 1), createdAt: Date.now() };
    const titleText = rows.slice(0, headerIndex).map(r => r.map(cellToText).join(' ')).join(' ');
    const periodMatch = titleText.match(/\bde\s+(\d{1,2}\/\d{1,2}\/\d{2,4})\s+(?:at[eé]|a)\s+(\d{1,2}\/\d{1,2}\/\d{2,4})/i);
    if (periodMatch) {
      const [ps] = extractDates(periodMatch[1]);
      const [pe] = extractDates(periodMatch[2]);
      if (ps && pe) session.period = { start: ps, end: pe };
    }
    session.guess = guessColumns(headers);
    const id = crypto.randomBytes(12).toString('hex');
    absenceImportSessions.set(id, session);
    return sendHtml(res, renderAbsenceImportPreview(id, session, buildAbsenceImportPreview(session, {}), role));
  }
  const id = String(form.session || '');
  const session = absenceImportSessions.get(id);
  if (!session || session.slug !== slug) return sendHtml(res, renderAbsenceImportUpload(role, 'A prévia expirou. Envie o arquivo de novo.'));
  const preview = buildAbsenceImportPreview(session, form);
  if (form.action !== 'apply') return sendHtml(res, renderAbsenceImportPreview(id, session, preview, role));
  const insert = db.prepare(`INSERT OR IGNORE INTO employee_absences (employee_id, absence_date, absence_type, justification, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`);
  const note = `Importado do Pontomais (${session.fileName}) em ${formatDatePtBr(today())}`;
  let inserted = 0;
  db.exec('BEGIN');
  try {
    for (const item of preview.toInsert) {
      const r = insert.run(item.employee_id, item.day, item.type, item.reason ? `Pontomais: ${item.reason}`.slice(0, 200) : 'Pontomais', note);
      inserted += Number(r.changes || 0);
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    return sendHtml(res, renderAbsenceImportPreview(id, session, preview, role, `Nada foi gravado: ${error.message}`));
  }
  absenceImportSessions.delete(id);
  setAlertSetting(`absence_import_log_${Date.now()}`, JSON.stringify({ file: session.fileName, inserted, user: getRequestAuth()?.user?.username || '', at: new Date().toISOString() }));
  return redirect(res, `/closures?notice=${encodeURIComponent(`${inserted} dia(s) de ausência importado(s) do Pontomais.`)}`);
}
// ===============================================================

// ===================== LANÇAMENTO HORA EXTRA / RETROATIVO =====================
// Lançamento único (como o rápido), com data livre (passada), tempo trabalhado e a flag decidindo
// se conta na meta/eficiência e nos minutos do mês. A flag vale sempre, mesmo dentro da jornada.
// Eficiência da hora extra = minutos produzidos ÷ minutos trabalhados.

// Aceita "150", "2:30", "2h30", "2h", "1,5h"
function parseWorkedMinutes(value) {
  const t = String(value || '').trim().toLowerCase().replace(/\s+/g, '');
  if (!t) return 0;
  let m = t.match(/^(\d{1,2}):(\d{1,2})$/) || t.match(/^(\d{1,2})h(\d{1,2})?(?:m|min)?$/);
  if (m) return Number(m[1]) * 60 + Number(m[2] || 0);
  m = t.match(/^(\d+(?:[.,]\d+)?)h$/);
  if (m) return Math.round(Number(m[1].replace(',', '.')) * 60);
  m = t.match(/^(\d+)(?:m|min)?$/);
  return m ? Number(m[1]) : NaN;
}

function fmtHoursMinutes(minutes) {
  const total = Math.round(Number(minutes || 0));
  const h = Math.floor(total / 60);
  const m = total % 60;
  return h ? `${h}h${String(m).padStart(2, '0')}` : `${m} min`;
}

function extraEffClass(pct) {
  if (pct === null) return '';
  return pct >= targetPercent() ? 'perf-high' : (pct >= targetPercent() * 0.8 ? 'perf-mid' : 'perf-low');
}

function getExtraEfficiencyReport(start, end, employeeId = '') {
  const params = [start, end];
  let where = "p.launch_kind = 'hora_extra' AND p.is_reversed = 0 AND p.production_date BETWEEN ? AND ?";
  if (employeeId) { where += ' AND p.employee_id = ?'; params.push(Number(employeeId)); }
  const rows = db.prepare(`
    SELECT p.id, p.production_date, p.produced_quantity, p.produced_minutes, p.worked_minutes, p.counts_for_prize, p.created_at,
      o.op_number, e.id AS employee_id, e.full_name
    FROM op_daily_productions p JOIN ops o ON o.id = p.op_id JOIN employees e ON e.id = p.employee_id
    WHERE ${where}
    ORDER BY p.production_date DESC, p.id DESC`).all(...params);
  const byEmp = new Map();
  for (const r of rows) {
    if (!byEmp.has(r.employee_id)) byEmp.set(r.employee_id, { employee_id: r.employee_id, name: r.full_name, launches: 0, pieces: 0, produced: 0, worked: 0, producedWithTime: 0, days: new Set(), counted: 0, notCounted: 0 });
    const a = byEmp.get(r.employee_id);
    a.launches += 1;
    a.pieces += Number(r.produced_quantity || 0);
    a.produced += Number(r.produced_minutes || 0);
    a.days.add(r.production_date);
    if (Number(r.worked_minutes) > 0) { a.worked += Number(r.worked_minutes); a.producedWithTime += Number(r.produced_minutes || 0); }
    if (r.counts_for_prize) a.counted += Number(r.produced_minutes || 0); else a.notCounted += Number(r.produced_minutes || 0);
  }
  const summary = [...byEmp.values()].map(a => ({ ...a, days: a.days.size, pct: a.worked > 0 ? round2((a.producedWithTime / a.worked) * 100) : null }))
    .sort((x, y) => (y.pct ?? -1) - (x.pct ?? -1) || x.name.localeCompare(y.name));
  const worked = summary.reduce((s, a) => s + a.worked, 0);
  const producedWithTime = summary.reduce((s, a) => s + a.producedWithTime, 0);
  const total = {
    launches: rows.length,
    pieces: summary.reduce((s, a) => s + a.pieces, 0),
    produced: round2(summary.reduce((s, a) => s + a.produced, 0)),
    worked,
    pct: worked > 0 ? round2((producedWithTime / worked) * 100) : null
  };
  return { rows, summary, total };
}

function renderExtraLaunchPage(values = {}, error = '', notice = '', role = 'adm') {
  const employees = db.prepare('SELECT id, registration_code, full_name, start_date, termination_date FROM employees ORDER BY full_name').all()
    .filter(emp => !emp.termination_date || emp.termination_date >= addDaysIso(today(), -60));
  const selectedEmployeeId = String(values.employee_id || '');
  const counts = values.counts_for_prize === undefined ? true : parseCountsForPrizeFlag(values.counts_for_prize) === 1;
  // Relatório: período atual por padrão, filtro por colaboradora
  const period = getPeriodRange('month', today());
  const rStart = /^\d{4}-\d{2}-\d{2}$/.test(String(values.r_start || '')) ? values.r_start : period.start;
  const rEnd = /^\d{4}-\d{2}-\d{2}$/.test(String(values.r_end || '')) ? values.r_end : period.end;
  const rEmp = String(values.r_employee || '');
  const report = getExtraEfficiencyReport(rStart, rEnd, rEmp);
  const effCell = pct => pct === null ? '<span class="hint">sem tempo</span>' : `<strong class="${extraEffClass(pct)}">${fmtNum(pct, 1)}%</strong>`;
  const backQuery = new URLSearchParams({ r_employee: rEmp, r_start: rStart, r_end: rEnd }).toString();
  const missingTime = report.rows.filter(r => !(Number(r.worked_minutes) > 0)).length;
  const content = `
    <section class="page-header">
      <div>
        <h2>Lançamento hora extra / retroativo</h2>
        <p>Peças feitas em hora extra ou esquecidas em outro dia. Informe o tempo trabalhado para medir a eficiência da hora extra.</p>
      </div>
      <div class="header-actions"><a class="btn secondary" href="/productions/new">Lançamento rápido</a></div>
    </section>
    <section class="panel quick-launch-panel">
      <form class="form-grid quick-launch-form" method="post" action="/productions/extra" data-extra-launch>
        <label>Colaborador
          <select name="employee_id" required data-x="employee">
            <option value="">Selecione</option>
            ${employees.map(emp => `<option value="${emp.id}" ${selectedEmployeeId === String(emp.id) ? 'selected' : ''}>${escapeHtml(emp.registration_code)} - ${escapeHtml(emp.full_name)}${emp.termination_date ? ' (desligada)' : ''}</option>`).join('')}
          </select>
        </label>
        <label>Data
          <input type="date" name="production_date" required max="${today()}" value="${escapeHtml(values.production_date || '')}" data-x="date" />
        </label>
        <label>OP
          <span class="scan-input"><input name="op_number" required autocomplete="off" placeholder="Bipe ou digite a OP" value="${escapeHtml(values.op_number || '')}" data-x="op" data-scan-input /><button class="btn secondary scan-btn" type="button" data-scan-camera title="Ler com a câmera">📷</button></span>
        </label>
        <label>Quantidade de peças
          <input type="number" inputmode="numeric" min="1" name="produced_quantity" required value="${escapeHtml(values.produced_quantity || '')}" data-x="quantity" />
        </label>
        <label>Tempo trabalhado
          <input name="worked_time" required inputmode="numeric" placeholder="Ex.: 2:00 ou 120" value="${escapeHtml(values.worked_time || '')}" data-x="worked" />
        </label>
        <div class="extra-flag">
          <input type="hidden" name="counts_for_prize" value="0" />
          <label class="extra-flag-line"><input type="checkbox" name="counts_for_prize" value="1" ${counts ? 'checked' : ''} /> Conta na meta</label>
          <small class="hint">Marcado: minutos entram na eficiência, no prêmio e na soma do mês. Desmarcado: só baixa as peças da OP.</small>
        </div>
        <div class="full extra-calc" data-x="calc" hidden></div>
        <div class="full actions"><button class="btn" type="submit">Salvar lançamento</button></div>
      </form>
      <div class="quick-op-preview" data-x="preview" hidden></div>
      <p class="hint">Hora extra em mais de uma OP: lance cada OP separada e divida o tempo trabalhado entre elas.</p>
    </section>

    <section class="panel" style="margin-top:14px" id="relatorio">
      <h3>Eficiência em hora extra</h3>
      <form class="inline-form" method="get" action="/productions/extra#relatorio">
        <label>Colaboradora
          <select name="r_employee"><option value="">Todas</option>${employees.map(emp => `<option value="${emp.id}" ${rEmp === String(emp.id) ? 'selected' : ''}>${escapeHtml(emp.full_name)}</option>`).join('')}</select>
        </label>
        <label>De<input type="date" name="r_start" value="${escapeHtml(rStart)}" /></label>
        <label>Até<input type="date" name="r_end" value="${escapeHtml(rEnd)}" /></label>
        <div class="actions" style="align-self:flex-end"><button class="btn" type="submit">Filtrar</button><a class="btn secondary" href="/productions/extra#relatorio">Período atual</a></div>
      </form>
      <div class="cards" style="margin-top:12px">
        <div class="mini-card"><span>Eficiência hora extra</span><strong class="${extraEffClass(report.total.pct)}">${report.total.pct === null ? '—' : `${fmtNum(report.total.pct, 1)}%`}</strong></div>
        <div class="mini-card"><span>Tempo trabalhado</span><strong>${fmtHoursMinutes(report.total.worked)}</strong></div>
        <div class="mini-card"><span>Minutos produzidos</span><strong>${fmtNum(report.total.produced, 0)}</strong></div>
        <div class="mini-card"><span>Lançamentos · peças</span><strong>${report.total.launches} · ${fmtNum(report.total.pieces, 0)}</strong></div>
      </div>
      ${rEmp ? '' : `
      <div class="table-wrap"><table>
        <thead><tr><th>Colaboradora</th><th>Dias</th><th>Peças</th><th>Trabalhado</th><th>Min produzidos</th><th>Eficiência</th><th>Conta / não conta (min)</th><th></th></tr></thead>
        <tbody>${report.summary.map(a => `<tr><td>${escapeHtml(a.name)}</td><td>${a.days}</td><td>${fmtNum(a.pieces, 0)}</td><td>${a.worked ? fmtHoursMinutes(a.worked) : '—'}</td><td>${fmtNum(a.produced, 0)}</td><td>${effCell(a.pct)}</td><td>${fmtNum(a.counted, 0)} / ${fmtNum(a.notCounted, 0)}</td><td><a class="btn secondary" href="/productions/extra?r_employee=${a.employee_id}&r_start=${rStart}&r_end=${rEnd}#relatorio">Ver</a></td></tr>`).join('') || '<tr><td colspan="8">Nenhuma hora extra no período.</td></tr>'}</tbody>
      </table></div>`}
      <h3 style="margin-top:14px">${rEmp ? 'Lançamentos da colaboradora' : 'Lançamentos do período'}</h3>
      <div class="table-wrap"><table>
        <thead><tr><th>Data</th>${rEmp ? '' : '<th>Colaboradora</th>'}<th>OP</th><th>Peças</th><th>Trabalhado</th><th>Min produzidos</th><th>Eficiência</th><th>Meta</th></tr></thead>
        <tbody>${report.rows.slice(0, 200).map(r => { const pct = Number(r.worked_minutes) > 0 ? round2((Number(r.produced_minutes) / Number(r.worked_minutes)) * 100) : null; return `<tr><td>${formatDatePtBr(r.production_date)}</td>${rEmp ? '' : `<td>${escapeHtml(r.full_name)}</td>`}<td>${escapeHtml(r.op_number)}</td><td>${fmtNum(r.produced_quantity, 0)}</td><td><form class="worked-edit" method="post" action="/productions/extra/worked"><input type="hidden" name="id" value="${r.id}" /><input type="hidden" name="back" value="${escapeHtml(backQuery)}" /><input name="worked_time" value="${Number(r.worked_minutes) > 0 ? escapeHtml(fmtHoursMinutes(r.worked_minutes).replace('h', ':').replace(' min', '')) : ''}" placeholder="—" aria-label="Tempo trabalhado" /><button class="btn secondary" type="submit" title="Salvar tempo">✔</button></form></td><td>${fmtNum(r.produced_minutes, 2)}</td><td>${effCell(pct)}</td><td>${r.counts_for_prize ? '✅ Conta' : '— Não conta'}</td></tr>`; }).join('') || `<tr><td colspan="${rEmp ? 7 : 8}">Nenhum lançamento.</td></tr>`}</tbody>
      </table></div>
      ${missingTime ? `
      <form class="inline-form worked-bulk" method="post" action="/productions/extra/worked-bulk" onsubmit="return confirm('Preencher o tempo nos ${missingTime} lançamento(s) sem tempo deste filtro?')">
        <input type="hidden" name="r_employee" value="${escapeHtml(rEmp)}" /><input type="hidden" name="r_start" value="${escapeHtml(rStart)}" /><input type="hidden" name="r_end" value="${escapeHtml(rEnd)}" />
        <label>${missingTime} lançamento(s) sem tempo trabalhado: preencher com<input name="worked_time" required placeholder="Ex.: 120 ou 2:00" /></label>
        <div class="actions" style="align-self:flex-end"><button class="btn" type="submit">Aplicar</button></div>
      </form>` : ''}
      <p class="hint">Eficiência da hora extra = minutos produzidos ÷ tempo trabalhado. Lançamentos sem tempo informado não entram no percentual. O tempo pode ser corrigido direto na tabela (✔ salva). Para corrigir peças ou OP, use Estornos.</p>
    </section>
    ${renderScannerScript()}
    <script>
      (() => {
        const form = document.querySelector('[data-extra-launch]');
        if (!form) return;
        const q = k => form.querySelector('[data-x="' + k + '"]');
        const op = q('op'), quantity = q('quantity'), worked = q('worked'), calc = q('calc');
        const preview = document.querySelector('[data-x="preview"]');
        const target = ${targetPercent()};
        let perPiece = 0;
        const ordered = [q('employee'), q('date'), op, quantity, worked];
        if (!location.hash) (ordered.find(f => f && !f.value) || quantity).focus();
        const parseWorked = v => {
          const t = String(v || '').trim().toLowerCase().replace(/\\s+/g, '');
          let m = t.match(/^(\\d{1,2}):(\\d{1,2})$/) || t.match(/^(\\d{1,2})h(\\d{1,2})?(?:m|min)?$/);
          if (m) return Number(m[1]) * 60 + Number(m[2] || 0);
          m = t.match(/^(\\d+(?:[.,]\\d+)?)h$/); if (m) return Math.round(Number(m[1].replace(',', '.')) * 60);
          m = t.match(/^(\\d+)(?:m|min)?$/); return m ? Number(m[1]) : 0;
        };
        const fmt = (n, d) => Number(n).toLocaleString('pt-BR', { minimumFractionDigits: d, maximumFractionDigits: d });
        const updateCalc = () => {
          const qty = Number(quantity.value || 0), w = parseWorked(worked.value);
          if (!perPiece || !qty) { calc.hidden = true; return; }
          const produced = qty * perPiece;
          calc.hidden = false;
          if (!w) { calc.className = 'full extra-calc'; calc.textContent = 'Produção: ' + fmt(produced, 2) + ' min. Informe o tempo trabalhado para ver a eficiência.'; return; }
          const pct = produced / w * 100;
          calc.className = 'full extra-calc ' + (pct >= target ? 'is-good' : 'is-bad');
          calc.innerHTML = '<strong></strong><span></span>';
          calc.querySelector('strong').textContent = 'Eficiência da hora extra: ' + fmt(pct, 1) + '%';
          calc.querySelector('span').textContent = fmt(produced, 2) + ' min produzidos em ' + w + ' min trabalhados (' + fmt(perPiece, 3) + ' min/pç) · meta ' + target + '%';
        };
        const show = async () => {
          const n = (op.value || '').trim();
          if (!n) { preview.hidden = true; perPiece = 0; updateCalc(); return; }
          try {
            const r = await fetch('/api/op-preview?op_number=' + encodeURIComponent(n), { headers: { Accept: 'application/json' } });
            const d = await r.json();
            preview.hidden = false;
            if (!d.found) { perPiece = 0; preview.className = 'quick-op-preview is-missing'; preview.innerHTML = '<strong>OP não encontrada.</strong>'; updateCalc(); return; }
            perPiece = Number(d.total_launch_minutes_per_piece || 0);
            preview.className = 'quick-op-preview' + (d.remaining_quantity <= 0 ? ' is-finished' : '');
            preview.innerHTML = '<strong></strong><span></span>';
            preview.querySelector('strong').textContent = d.op_number + ' · ' + (d.product_name || '');
            preview.querySelector('span').textContent = 'Saldo: ' + d.remaining_quantity + ' peça(s) · Produzido: ' + d.produced_quantity + '/' + d.total_pieces + ' · Total/pç: ' + perPiece.toFixed(3) + ' min';
            updateCalc();
          } catch (_) {}
        };
        op.addEventListener('change', show);
        op.addEventListener('blur', show);
        op.addEventListener('scan', () => { show(); quantity.focus(); });
        [quantity, worked].forEach(el => el.addEventListener('input', updateCalc));
        ordered.forEach((field, i) => field && field.addEventListener('keydown', e => {
          if (e.key !== 'Enter' || field === worked) return;
          e.preventDefault();
          if (field === op) show();
          const next = ordered[i + 1]; if (next) next.focus();
        }));
        if (op.value) show();
      })();
    </script>`;
  return pageLayout({ title: 'Lançamento hora extra', content, notice, error, role });
}

function handleUpdateWorkedTime(form, res, role) {
  const back = String(form.back || '');
  const go = (msg, isError) => redirect(res, `/productions/extra?${back}&${isError ? 'error' : 'notice'}=${encodeURIComponent(msg)}#relatorio`);
  const minutes = String(form.worked_time || '').trim() === '' ? 0 : parseWorkedMinutes(form.worked_time);
  if (Number.isNaN(minutes) || minutes < 0 || minutes > 16 * 60) return go('Tempo inválido. Use 120, 2:00 ou 1h30.', true);
  const row = db.prepare("SELECT id FROM op_daily_productions WHERE id = ? AND launch_kind = 'hora_extra' AND is_reversed = 0").get(Number(form.id));
  if (!row) return go('Lançamento não encontrado.', true);
  db.prepare('UPDATE op_daily_productions SET worked_minutes = ? WHERE id = ?').run(minutes || null, row.id);
  go(minutes ? `Tempo trabalhado salvo: ${fmtHoursMinutes(minutes)}.` : 'Tempo trabalhado removido.');
}

function handleBulkWorkedTime(form, res, role) {
  const minutes = parseWorkedMinutes(form.worked_time);
  const back = new URLSearchParams({ r_employee: String(form.r_employee || ''), r_start: String(form.r_start || ''), r_end: String(form.r_end || '') }).toString();
  if (!(minutes > 0) || minutes > 16 * 60) return redirect(res, `/productions/extra?${back}&error=${encodeURIComponent('Tempo inválido. Use 120, 2:00 ou 1h30.')}#relatorio`);
  const valid = d => /^\d{4}-\d{2}-\d{2}$/.test(String(d || ''));
  if (!valid(form.r_start) || !valid(form.r_end)) return redirect(res, `/productions/extra?error=${encodeURIComponent('Período inválido.')}#relatorio`);
  const params = [minutes, form.r_start, form.r_end];
  let where = "launch_kind = 'hora_extra' AND is_reversed = 0 AND (worked_minutes IS NULL OR worked_minutes <= 0) AND production_date BETWEEN ? AND ?";
  if (form.r_employee) { where += ' AND employee_id = ?'; params.push(Number(form.r_employee)); }
  const result = db.prepare(`UPDATE op_daily_productions SET worked_minutes = ? WHERE ${where}`).run(...params);
  redirect(res, `/productions/extra?${back}&notice=${encodeURIComponent(`Tempo de ${fmtHoursMinutes(minutes)} preenchido em ${result.changes} lançamento(s).`)}#relatorio`);
}

function handleCreateExtraLaunch(form, res, role) {
  const fail = (msg, status = 422) => sendHtml(res, renderExtraLaunchPage(form, msg, '', role), status);
  const employeeId = Number(form.employee_id);
  const producedQuantity = Number(form.produced_quantity);
  const productionDate = String(form.production_date || '').trim();
  const counts = parseCountsForPrizeFlag(form.counts_for_prize);
  const workedMinutes = parseWorkedMinutes(form.worked_time);
  if (!employeeId || !productionDate || !String(form.op_number || '').trim() || !(producedQuantity > 0) || !Number.isInteger(producedQuantity)) return fail('Preencha colaborador, data, OP e quantidade de peças.');
  if (!(workedMinutes > 0) || workedMinutes > 16 * 60) return fail('Informe o tempo trabalhado (ex.: 2:00 ou 120 minutos, até 16 horas).');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(productionDate) || productionDate > today()) return fail('A data não pode ser futura.');
  const found = getOpByNumber(form.op_number);
  if (!found) return fail('OP não encontrada.', 404);
  const op = db.prepare('SELECT * FROM ops WHERE id = ?').get(found.id);
  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  if (!op || !employee) return fail('OP ou colaborador não encontrado.', 404);
  if (employee.start_date && productionDate < employee.start_date) return fail(`A colaboradora foi admitida em ${formatDatePtBr(employee.start_date)}. Confira a data.`);
  if (employee.termination_date && productionDate > employee.termination_date) return fail(`A colaboradora foi desligada em ${formatDatePtBr(employee.termination_date)}. Confira a data.`);
  // OP na célula só bloqueia se o envio for anterior à data do lançamento
  const cell = getCurrentCellTransfer(op.id);
  if (cell && String(cell.sent_at || '').slice(0, 10) <= productionDate) return fail('Esta OP está em célula desde antes dessa data. Faça o retorno da célula antes de lançar.');
  const totals = db.prepare(`
    SELECT
      COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0), 0) AS produced_total,
      COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS problem_total
  `).get(op.id, op.id);
  const futureTotal = Number(totals.produced_total || 0) + Number(totals.problem_total || 0) + producedQuantity;
  if (futureTotal > Number(op.total_pieces || 0)) return fail(`Lançamento bloqueado: a OP ultrapassaria o total em ${futureTotal - Number(op.total_pieces || 0)} peça(s).`);
  const launchF21 = round3(Number(op.minutes_f21 || 0));
  if (!(launchF21 > 0)) return fail('A OP não tem minuto F21 cadastrado.');
  const metrics = calculateProductionLaunchMetrics(op, producedQuantity, launchF21, productionDate);
  db.prepare(`
    INSERT INTO op_daily_productions (
      op_id, employee_id, production_date, produced_quantity, used_minutes_f21, normal_minutes, extra_minutes, produced_minutes,
      extra_time_id, extra_reason_snapshot, extra_description_snapshot, extra_effective_date_snapshot, extra_minutes_per_piece_snapshot,
      counts_for_prize, launch_kind, worked_minutes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'hora_extra', ?)
  `).run(
    op.id, employeeId, productionDate, producedQuantity, launchF21, metrics.normalMinutes, metrics.extraMinutes, metrics.totalMinutes,
    metrics.extraSnapshot.extra_time_id, metrics.extraSnapshot.extra_reason_snapshot, metrics.extraSnapshot.extra_description_snapshot,
    metrics.extraSnapshot.extra_effective_date_snapshot, metrics.extraSnapshot.extra_minutes_per_piece_snapshot, counts, workedMinutes
  );
  recalculateOpStatus(op.id);
  const pct = round2((metrics.totalMinutes / workedMinutes) * 100);
  const msg = `Lançado: ${employee.full_name} · ${op.op_number} · ${producedQuantity} pç · ${fmtNum(metrics.totalMinutes, 2)} min produzidos em ${fmtHoursMinutes(workedMinutes)} → eficiência ${fmtNum(pct, 1)}% · ${formatDatePtBr(productionDate)} · ${counts ? 'conta na meta' : 'não conta na meta'}.`;
  const back = new URLSearchParams({ notice: msg, employee_id: String(employeeId), production_date: productionDate, counts_for_prize: String(counts) });
  redirect(res, `/productions/extra?${back.toString()}`);
}
// ===============================================================


// ===================== QUADRO POR HORA =====================
// Grade por costureira com as horas da jornada dela: OP (vem da hora anterior), peças, % e minutos.
// 0 = hora zero (pede motivo). Cada quadro tem o seu botão Salvar.
const ZERO_HOUR_REASONS = ['Troca de OP', 'Não entregou peça', 'Sem peça / aguardando OP', 'Máquina parada / manutenção', 'Falta de material / aviamento', 'Retrabalho / conserto', 'Ajudando outro setor', 'Treinamento', 'Problema de saúde no trabalho'];
const DEFAULT_GRID_SCHEDULE = { start_time: '07:00', end_time: '16:48', break_start: '12:00', break_end: '13:00' };

function minutesToTime(total) {
  return `${String(Math.floor(total / 60)).padStart(2, '0')}:${String(total % 60).padStart(2, '0')}`;
}

function getEmployeeHourBlocks(employee) {
  const schedule = (employee.work_schedule_id && db.prepare('SELECT * FROM work_schedules WHERE id = ?').get(employee.work_schedule_id)) || DEFAULT_GRID_SCHEDULE;
  const t = getScheduleTimes(schedule);
  const blocks = [];
  let cursor = t.start;
  let guard = 0;
  while (cursor < t.end && guard < 48) {
    guard += 1;
    if (t.breakStart !== null && cursor >= t.breakStart && cursor < t.breakEnd) { cursor = t.breakEnd; continue; }
    let blockEnd = Math.min((Math.floor(cursor / 60) + 1) * 60, t.end);
    if (t.breakStart !== null && cursor < t.breakStart) blockEnd = Math.min(blockEnd, t.breakStart);
    const slot = `${String(Math.floor(cursor / 60)).padStart(2, '0')}:00`;
    const last = blocks[blocks.length - 1];
    if (last && last.slot === slot) { last.minutes += blockEnd - cursor; last.label = minutesToTime(blockEnd); }
    else blocks.push({ slot, from: minutesToTime(cursor), label: minutesToTime(blockEnd), minutes: blockEnd - cursor });
    cursor = blockEnd;
  }
  return blocks;
}

function getGridEmployees(productionDate) {
  return db.prepare(`
    SELECT * FROM employees
    WHERE is_active = 1 AND COALESCE(termination_date, '9999-12-31') >= ? AND COALESCE(start_date, '0000-01-01') <= ?
      AND UPPER(TRIM(COALESCE(job_role, ''))) LIKE 'COSTUREIRA%'
    ORDER BY full_name COLLATE NOCASE`).all(productionDate, productionDate);
}

function renderHourlyGridPage(query = {}, error = '', notice = '', role = getRequestRole() || 'adm') {
  const productionDate = /^\d{4}-\d{2}-\d{2}$/.test(String(query.production_date || '')) ? query.production_date : today();
  const employees = getGridEmployees(productionDate);
  const rows = db.prepare(`
    SELECT hp.*, o.op_number FROM hourly_productions hp JOIN ops o ON o.id = hp.op_id
    WHERE hp.production_date = ? AND hp.is_reversed = 0`).all(productionDate);
  const zeros = db.prepare('SELECT * FROM hourly_zero_hours WHERE production_date = ? AND is_reversed = 0').all(productionDate);
  const byKey = new Map(rows.map(r => [`${r.employee_id}|${r.hour_slot}`, r]));
  const zeroByKey = new Map(zeros.map(z => [`${z.employee_id}|${z.hour_slot}`, z]));
  const base = baseMinutesDay();
  const target = targetPercent();
  const pctClass = pct => pct >= target ? 'perf-high' : (pct >= 40 ? 'perf-mid' : 'perf-low');
  const summary = employees.map(emp => {
    const own = rows.filter(r => r.employee_id === emp.id);
    const minutes = round3(own.reduce((s, r) => s + Number(r.produced_minutes || 0), 0));
    const pieces = own.reduce((s, r) => s + Number(r.produced_quantity || 0), 0);
    // Eficiência até agora: minutos ÷ minutos das horas já lançadas (com peças ou hora zero)
    const launchedSlots = new Set([...own.map(r => r.hour_slot), ...zeros.filter(z => z.employee_id === emp.id).map(z => z.hour_slot)]);
    const elapsedBase = getEmployeeHourBlocks(emp).filter(b => launchedSlots.has(b.slot)).reduce((sum, b) => sum + b.minutes, 0);
    return { emp, minutes, pieces, pct: base > 0 ? (minutes / base) * 100 : 0, nowPct: elapsedBase > 0 ? (minutes / elapsedBase) * 100 : null, elapsedBase, hours: launchedSlots.size };
  }).sort((a, b) => b.pct - a.pct || a.emp.full_name.localeCompare(b.emp.full_name));

  // Lista primeiro; ao clicar numa costureira abre só o quadro dela
  const selectedId = Number(query.employee_id || 0);
  const selected = employees.find(e => e.id === selectedId) || null;
  const grids = (selected ? [selected] : []).map(emp => {
    const blocks = getEmployeeHourBlocks(emp);
    const lastOp = getLastHourlyOpForEmployee(emp.id, productionDate)?.op_number || '';
    let carryOp = '';
    const cells = blocks.map(b => {
      const row = byKey.get(`${emp.id}|${b.slot}`);
      const zero = zeroByKey.get(`${emp.id}|${b.slot}`);
      const op = row ? row.op_number : carryOp;
      if (row) carryOp = row.op_number;
      const minutes = row ? Number(row.produced_minutes || 0) : 0;
      const pct = row ? round2((minutes / b.minutes) * 100) : (zero ? 0 : null);
      return { b, row, zero, op, minutes, pct, locked: Boolean(row && row.is_validated) };
    });
    // Primeira hora sem OP: usa a última OP do dia (ou fica em branco)
    if (cells.length && !cells[0].op) cells[0].op = lastOp;
    const own = summary.find(s => s.emp.id === emp.id);
    return `
      <section class="panel grid-card" id="emp-${emp.id}">
        <div class="grid-card-head">
          <h3>${escapeHtml(emp.full_name)}</h3>
          <span class="hint">${escapeHtml(emp.work_schedule_id ? (getWorkSchedules().find(w => w.id === emp.work_schedule_id)?.name || '') : 'Sem jornada (07:00–16:48)')}</span>
          <span class="grid-head-pcts"><span>Até agora <strong class="${own.nowPct === null ? '' : pctClass(own.nowPct)}" data-now-pct>${own.nowPct === null ? '—' : `${fmtNum(own.nowPct, 1)}%`}</strong></span><span>Dia <strong class="${pctClass(own.pct)}" data-day-pct>${fmtNum(own.pct, 1)}%</strong></span></span>
        </div>
        <form method="post" action="/productions/hourly/quadro" data-grid-form>
          <input type="hidden" name="production_date" value="${escapeHtml(productionDate)}" />
          <input type="hidden" name="employee_id" value="${emp.id}" />
          <div class="table-wrap"><table class="hour-grid">
            <tbody>
              <tr class="row-op"><th>OP</th>${cells.map(c => `<td><input name="op_${c.b.slot}" value="${escapeHtml(c.op || '')}" ${c.locked ? 'disabled' : ''} data-op data-slot="${c.b.slot}" autocomplete="off" placeholder="OP" /></td>`).join('')}<td class="grid-total" rowspan="2">Total</td></tr>
              <tr class="row-hour"><th>Hora</th>${cells.map(c => `<td title="${c.b.from}–${c.b.label} (${c.b.minutes} min)">${c.b.label}</td>`).join('')}</tr>
              <tr class="row-qty"><th>Peças</th>${cells.map(c => `<td class="${c.zero ? 'is-zero' : ''}${c.locked ? ' is-locked' : ''}"><input type="number" min="0" step="1" inputmode="numeric" name="qty_${c.b.slot}" value="${c.row ? c.row.produced_quantity : (c.zero ? '0' : '')}" ${c.locked ? 'disabled title="Validado — corrija em Lanç. hora"' : ''} data-qty data-slot="${c.b.slot}" data-block="${c.b.minutes}" /></td>`).join('')}<td class="grid-total" data-total-pieces>${own.pieces}</td></tr>
              <tr class="row-reason" ${cells.some(c => c.zero) ? '' : 'hidden'}><th>Motivo (0)</th>${cells.map(c => `<td><input name="reason_${c.b.slot}" value="${escapeHtml(c.zero?.reason || '')}" list="zero-reasons" placeholder="motivo" data-reason data-slot="${c.b.slot}" ${c.zero ? '' : 'hidden'} /></td>`).join('')}<td></td></tr>
              <tr class="row-min"><th>Min</th>${cells.map(c => `<td data-min data-slot="${c.b.slot}">${c.row ? fmtNum(c.minutes, 1) : ''}</td>`).join('')}<td class="grid-total" data-total-min>${fmtNum(own.minutes, 1)}</td></tr>
              <tr class="row-pct"><th>%</th>${cells.map(c => `<td data-pct data-slot="${c.b.slot}" class="${c.pct === null ? '' : pctClass(c.pct)}">${c.pct === null ? '' : `${fmtNum(c.pct, 0)}%`}</td>`).join('')}<td class="grid-total ${pctClass(own.pct)}" data-total-pct>${fmtNum(own.pct, 1)}%</td></tr>
              <tr class="row-now"><th>Até agora</th><td colspan="${cells.length}" class="grid-now-note" data-now-note>${own.nowPct === null ? 'Sem horas lançadas' : `${fmtNum(own.minutes, 1)} min em ${own.elapsedBase} min lançados`}</td><td class="grid-total ${own.nowPct === null ? '' : pctClass(own.nowPct)}" data-total-now>${own.nowPct === null ? '—' : `${fmtNum(own.nowPct, 1)}%`}</td></tr>
            </tbody>
          </table></div>
          <div class="actions grid-actions"><button class="btn" type="submit">Salvar ${escapeHtml(String(emp.full_name).split(' ')[0])}</button><a class="btn secondary" href="/productions/hourly/quadro?production_date=${encodeURIComponent(productionDate)}">Voltar à lista</a><span class="hint">0 = hora zero (informe o motivo). Apagar a quantidade remove a hora. Horas validadas ficam travadas.</span></div>
        </form>
      </section>`;
  }).join('');

  const content = `
    <section class="page-header">
      <div><h2>Quadro por hora</h2><p>Uma grade por costureira com as horas da jornada dela. A OP vem da hora anterior; troque quando mudar de OP.</p></div>
      <form class="inline-form" method="get" action="/productions/hourly/quadro">
        <label>Data<input type="date" name="production_date" value="${escapeHtml(productionDate)}" ${launchDateAttrs(role)} onchange="this.form.submit()" />${launchDateHint(role)}</label>
        ${selected ? `<input type="hidden" name="employee_id" value="${selected.id}" />` : ''}
      </form>
    </section>
    ${selected ? '' : `<section class="panel section-gap">
      <h3>Clique na costureira para lançar as horas dela</h3>
      ${summary.length ? `<div class="hourly-list-head"><span>#</span><span>Colaboradora</span><span>Andamento do dia</span><span>% dia</span><span>Peças</span><span>Min</span><span>Horas</span><span>Até agora</span></div>
      <div class="hourly-list">${summary.map((s, i) => `<a class="hourly-row" href="/productions/hourly/quadro?production_date=${encodeURIComponent(productionDate)}&employee_id=${s.emp.id}"><span class="hourly-rank">${i + 1}</span><strong class="hourly-name">${escapeHtml(s.emp.full_name)}</strong><span class="hourly-bar"><span style="width:${Math.max(2, Math.min(s.pct, 100))}%;background:${s.pct >= target ? '#16a34a' : (s.pct >= 40 ? '#f59e0b' : '#ef4444')}"></span></span><strong class="hourly-pct ${pctClass(s.pct)}">${fmtNum(s.pct, 1)}%</strong><span>${s.pieces}</span><span>${fmtNum(s.minutes, 0)}</span><span>${s.hours}h</span><strong class="${s.nowPct === null ? '' : pctClass(s.nowPct)}">${s.nowPct === null ? '—' : `${fmtNum(s.nowPct, 1)}%`}</strong></a>`).join('')}</div>` : '<p class="hint">Nenhuma costureira ativa (função "Costureira") para esta data.</p>'}
      <p class="hint">% dia = minutos ÷ ${fmtNum(base, 0)} min. Até agora = minutos ÷ minutos das horas já lançadas (com peças ou hora zero). % da hora = minutos ÷ minutos da hora (60, ou menos na última hora).</p>
    </section>`}
    <datalist id="zero-reasons">${ZERO_HOUR_REASONS.map(r => `<option value="${r}"></option>`).join('')}</datalist>
    ${grids}
    <script>
      (() => {
        const cache = {};
        const target = ${target};
        const cls = p => p >= target ? 'perf-high' : (p >= 40 ? 'perf-mid' : 'perf-low');
        const fmt = (n, d) => Number(n).toLocaleString('pt-BR', { minimumFractionDigits: d, maximumFractionDigits: d });
        const perPiece = async op => {
          op = String(op || '').trim();
          if (!op) return 0;
          if (cache[op] === undefined) {
            cache[op] = fetch('/api/op-preview?op_number=' + encodeURIComponent(op), { headers: { Accept: 'application/json' } })
              .then(r => r.json()).then(d => d && d.found ? Number(d.total_launch_minutes_per_piece || 0) : 0).catch(() => 0);
          }
          return cache[op];
        };
        document.querySelectorAll('[data-grid-form]').forEach(form => {
          const ops = Array.from(form.querySelectorAll('[data-op]'));
          const qtys = Array.from(form.querySelectorAll('[data-qty]'));
          const reasonRow = form.querySelector('.row-reason');
          const recalc = async () => {
            let totalMin = 0, totalPcs = 0, elapsed = 0;
            for (let i = 0; i < qtys.length; i++) {
              const q = qtys[i], slot = q.dataset.slot;
              const pctCell = form.querySelector('[data-pct][data-slot="' + slot + '"]');
              const minCell = form.querySelector('[data-min][data-slot="' + slot + '"]');
              const reason = form.querySelector('[data-reason][data-slot="' + slot + '"]');
              const v = q.value.trim();
              q.parentElement.classList.toggle('is-zero', v === '0');
              if (reason) reason.hidden = v !== '0';
              if (v === '' ) { pctCell.textContent = ''; minCell.textContent = ''; pctCell.className = ''; continue; }
              const n = Number(v);
              elapsed += Number(q.dataset.block || 60);
              const m = n * await perPiece(ops[i].value);
              const p = m / Number(q.dataset.block || 60) * 100;
              totalMin += m; totalPcs += n;
              pctCell.textContent = fmt(p, 0) + '%'; pctCell.className = cls(p);
              minCell.textContent = n ? fmt(m, 1) : '';
            }
            reasonRow.hidden = !qtys.some(q => q.value.trim() === '0');
            const dayPct = totalMin / ${base} * 100;
            form.querySelector('[data-total-pieces]').textContent = totalPcs;
            form.querySelector('[data-total-min]').textContent = fmt(totalMin, 1);
            const tp = form.querySelector('[data-total-pct]'); tp.textContent = fmt(dayPct, 1) + '%'; tp.className = 'grid-total ' + cls(dayPct);
            const nowPct = elapsed > 0 ? totalMin / elapsed * 100 : null;
            const tn = form.querySelector('[data-total-now]'); tn.textContent = nowPct === null ? '—' : fmt(nowPct, 1) + '%'; tn.className = 'grid-total ' + (nowPct === null ? '' : cls(nowPct));
            form.querySelector('[data-now-note]').textContent = nowPct === null ? 'Sem horas lançadas' : fmt(totalMin, 1) + ' min em ' + elapsed + ' min lançados';
            const card = form.closest('.grid-card');
            const hn = card.querySelector('[data-now-pct]'); if (hn) { hn.textContent = nowPct === null ? '—' : fmt(nowPct, 1) + '%'; hn.className = nowPct === null ? '' : cls(nowPct); }
            const hd = card.querySelector('[data-day-pct]'); if (hd) { hd.textContent = fmt(dayPct, 1) + '%'; hd.className = cls(dayPct); }
          };
          // OP digitada passa para as horas seguintes que ainda não têm peça lançada
          ops.forEach((op, i) => op.addEventListener('change', () => {
            for (let j = i + 1; j < ops.length; j++) {
              if (ops[j].disabled || qtys[j].value.trim() !== '') break;
              ops[j].value = op.value;
            }
            recalc();
          }));
          qtys.forEach((q, i) => {
            q.addEventListener('input', recalc);
            q.addEventListener('keydown', e => {
              if (e.key !== 'Enter') return;
              e.preventDefault();
              if (q.value.trim() === '0') { const r = form.querySelector('[data-reason][data-slot="' + q.dataset.slot + '"]'); if (r) { r.hidden = false; r.focus(); return; } }
              const next = qtys.slice(i + 1).find(x => !x.disabled);
              if (next) next.focus(); else form.querySelector('button[type=submit]').focus();
            });
          });
          form.querySelectorAll('[data-reason]').forEach(r => r.addEventListener('keydown', e => {
            if (e.key !== 'Enter') return;
            e.preventDefault();
            const i = qtys.findIndex(q => q.dataset.slot === r.dataset.slot);
            const next = qtys.slice(i + 1).find(x => !x.disabled);
            if (next) next.focus(); else form.querySelector('button[type=submit]').focus();
          }));
          form.addEventListener('submit', e => {
            const missing = qtys.find(q => q.value.trim() === '0' && !form.querySelector('[data-reason][data-slot="' + q.dataset.slot + '"]').value.trim());
            if (missing) { e.preventDefault(); const r = form.querySelector('[data-reason][data-slot="' + missing.dataset.slot + '"]'); reasonRow.hidden = false; r.hidden = false; r.focus(); r.classList.add('is-invalid'); }
          });
          recalc();
        });
        const firstEmpty = Array.from(document.querySelectorAll('[data-qty]')).find(q => !q.disabled && q.value.trim() === '');
        if (firstEmpty) firstEmpty.focus();
      })();
    </script>`;
  return pageLayout({ title: 'Quadro por hora', content, notice, error, role });
}

function handleSaveHourlyGrid(form, res, role) {
  const productionDate = String(form.production_date || '').trim();
  const employeeId = Number(form.employee_id || 0);
  // Sucesso volta para a lista (próxima costureira); erro volta para o quadro dela
  const back = (msg, isError) => redirect(res, buildRedirectWithFlash(`/productions/hourly/quadro?production_date=${encodeURIComponent(productionDate)}${isError ? `&employee_id=${employeeId}` : ''}`, msg, isError));
  const dateError = checkLaunchDate(productionDate, role);
  if (dateError) return back(dateError, true);
  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  if (!employee) return back('Costureira não encontrada.', true);
  const blocks = getEmployeeHourBlocks(employee);
  const errors = [];
  let changed = 0;
  const touchedOps = new Set();
  for (const b of blocks) {
    if (!(`qty_${b.slot}` in form)) continue; // célula travada (validada) não é enviada
    const qtyRaw = String(form[`qty_${b.slot}`] ?? '').trim();
    const opNumber = normalizeOpNumberInput(form[`op_${b.slot}`] || '');
    const reason = String(form[`reason_${b.slot}`] || '').trim().slice(0, 200);
    const existing = db.prepare('SELECT * FROM hourly_productions WHERE employee_id = ? AND production_date = ? AND hour_slot = ? AND is_reversed = 0').get(employeeId, productionDate, b.slot);
    const zero = db.prepare('SELECT * FROM hourly_zero_hours WHERE employee_id = ? AND production_date = ? AND hour_slot = ? AND is_reversed = 0').get(employeeId, productionDate, b.slot);
    if (existing && existing.is_validated) continue;
    const removeExisting = () => {
      if (existing) { db.prepare("UPDATE hourly_productions SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = 'Alterado no quadro por hora', updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(existing.id); touchedOps.add(existing.op_id); }
    };
    const removeZero = () => { if (zero) db.prepare('UPDATE hourly_zero_hours SET is_reversed = 1 WHERE id = ?').run(zero.id); };
    if (qtyRaw === '') {
      if (existing || zero) { removeExisting(); removeZero(); changed += 1; }
      continue;
    }
    const qty = Number(qtyRaw);
    if (!Number.isInteger(qty) || qty < 0) { errors.push(`${b.label}: quantidade inválida`); continue; }
    if (qty === 0) {
      if (!reason) { errors.push(`${b.label}: informe o motivo da hora zero`); continue; }
      if (zero && zero.reason === reason && !existing) continue;
      removeExisting();
      if (zero) db.prepare('UPDATE hourly_zero_hours SET reason = ? WHERE id = ?').run(reason, zero.id);
      else db.prepare('INSERT INTO hourly_zero_hours (employee_id, production_date, hour_slot, reason) VALUES (?, ?, ?, ?)').run(employeeId, productionDate, b.slot, reason);
      changed += 1;
      continue;
    }
    if (!opNumber) { errors.push(`${b.label}: informe a OP`); continue; }
    const found = getOpByNumber(opNumber);
    if (!found) { errors.push(`${b.label}: OP ${opNumber} não encontrada`); continue; }
    const op = db.prepare('SELECT * FROM ops WHERE id = ?').get(found.id);
    if (existing && existing.op_id === op.id && Number(existing.produced_quantity) === qty) { if (zero) removeZero(); continue; }
    if (getCurrentCellTransfer(op.id)) { errors.push(`${b.label}: OP ${op.op_number} está em célula`); continue; }
    const used = Number(db.prepare(`
      SELECT
        COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0), 0)
        + COALESCE((SELECT SUM(produced_quantity) FROM hourly_productions WHERE op_id = ? AND is_reversed = 0 AND validated_daily_production_id IS NULL), 0)
        + COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS n`).get(op.id, op.id, op.id).n || 0)
      - (existing && existing.op_id === op.id ? Number(existing.produced_quantity || 0) : 0);
    if (used + qty > Number(op.total_pieces || 0)) { errors.push(`${b.label}: OP ${op.op_number} passaria do total em ${used + qty - Number(op.total_pieces || 0)} peça(s)`); continue; }
    const metrics = calculateProductionLaunchMetrics(op, qty, round3(Number(op.minutes_f21 || 0)), productionDate);
    const snap = metrics.extraSnapshot;
    removeZero();
    if (existing) {
      db.prepare(`UPDATE hourly_productions SET op_id = ?, produced_quantity = ?, used_minutes_f21 = ?, normal_minutes = ?, extra_minutes = ?, produced_minutes = ?,
        extra_time_id = ?, extra_reason_snapshot = ?, extra_description_snapshot = ?, extra_effective_date_snapshot = ?, extra_minutes_per_piece_snapshot = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`)
        .run(op.id, qty, metrics.launchF21, metrics.normalMinutes, metrics.extraMinutes, metrics.totalMinutes, snap.extra_time_id, snap.extra_reason_snapshot, snap.extra_description_snapshot, snap.extra_effective_date_snapshot, snap.extra_minutes_per_piece_snapshot, existing.id);
      touchedOps.add(existing.op_id);
    } else {
      db.prepare(`
        INSERT INTO hourly_productions (
          op_id, employee_id, production_date, hour_slot, produced_quantity, used_minutes_f21,
          normal_minutes, extra_minutes, produced_minutes, extra_time_id,
          extra_reason_snapshot, extra_description_snapshot, extra_effective_date_snapshot,
          extra_minutes_per_piece_snapshot, notes, created_by_user_id, updated_at, counts_for_prize
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, ?)`)
        .run(op.id, employeeId, productionDate, b.slot, qty, metrics.launchF21, metrics.normalMinutes, metrics.extraMinutes, metrics.totalMinutes,
          snap.extra_time_id, snap.extra_reason_snapshot, snap.extra_description_snapshot, snap.extra_effective_date_snapshot, snap.extra_minutes_per_piece_snapshot,
          'Quadro por hora', resolveCountsForPrize({}, employee, productionDate, b.slot));
    }
    touchedOps.add(op.id);
    changed += 1;
  }
  touchedOps.forEach(id => recalculateOpStatus(id));
  const first = String(employee.full_name).split(' ')[0];
  if (errors.length) return back(`${first}: ${changed} hora(s) salva(s). Não salvas: ${errors.join('; ')}.`, true);
  back(changed ? `${first}: ${changed} hora(s) salva(s).` : `${first}: nada mudou.`);
}
// ===============================================================

// ===================== TELA PARÂMETROS =====================
const ABSENCE_TYPE_LABELS = { falta: 'Falta', atestado: 'Atestado', ferias: 'Férias', folga: 'Folga', afastamento: 'Afastamento', outro: 'Outro' };

function renderParametersPage(query = {}, values = null, error = '', role = 'adm') {
  const v = values || getParams();
  const workdays = new Set(String(v.workdays).split(','));
  const excluded = new Set(String(v.absence_types_excluded_from_base).split(','));
  const num = (key, attrs = '') => `<input type="number" name="${key}" value="${escapeHtml(String(v[key] ?? ''))}" ${attrs} />`;
  const content = `
    <section class="page-header"><div><h2>Parâmetros</h2><p>Regras de cálculo desta empresa. Alterações valem para todas as telas (Dashboard, Acompanhamento, Fechamento e Prêmio) a partir de agora.</p></div></section>
    <form class="params-form" method="post" action="/parametros">
      <section class="panel">
        <h3>Base e meta</h3>
        <div class="form-grid">
          <label>Minutos de base por dia útil ${num('base_minutes_day', 'min="1" max="1440" step="1" required')}<small class="hint">Padrão 528 (8h48).</small></label>
          <label>Meta de eficiência (%) ${num('target_percent', 'min="1" max="200" step="0.01" required')}<small class="hint">Padrão 60%.</small></label>
        </div>
      </section>

      <section class="panel">
        <h3>Período e dias úteis</h3>
        <div class="form-grid">
          <label>Dia de início do mês operacional ${num('period_start_day', 'min="1" max="28" step="1" required')}<small class="hint">Ex.: 26 = período de 26 a 25. Use 1 para mês civil.</small></label>
          <label>Lançar no dia anterior até (hora) ${num('launch_previous_day_until_hour', 'min="0" max="23" step="1" required')}<small class="hint">Lançamento rápido e por hora: até essa hora dá para escolher o dia anterior. 0 = só o dia de hoje. Administrador não tem trava.</small></label>
        </div>
        <fieldset><legend>Dias úteis (entram na base de cálculo)</legend>
          ${[1, 2, 3, 4, 5, 6, 0].map(d => `<label class="checkbox-line"><input type="checkbox" name="workdays" value="${d}" ${workdays.has(String(d)) ? 'checked' : ''} /> ${WEEKDAY_LABELS[d]}</label>`).join('')}
        </fieldset>
      </section>

      <section class="panel">
        <h3>Prêmio de produção</h3>
        <table class="params-table">
          <thead><tr><th>Faixa</th><th>A partir de (% de eficiência)</th><th>Valor (R$)</th></tr></thead>
          <tbody>
            ${[1, 2, 3].map(i => `<tr><td>Faixa ${i}</td><td>${num(`prize_tier${i}_percent`, 'min="0" max="200" step="0.01"')}</td><td>${num(`prize_tier${i}_value`, 'min="0" step="0.01"')}</td></tr>`).join('')}
          </tbody>
        </table>
        <p class="hint">Vale a maior faixa atingida. Deixe 0 no percentual para desativar a faixa.</p>
        <div class="form-grid">
          <label>Prêmio ao atingir a meta (R$) ${num('prize_target_value', 'min="0" step="0.01"')}</label>
          <label>Prêmio extra (R$) ${num('prize_extra_value', 'min="0" step="0.01"')}</label>
          <label>A cada (minutos acima da meta) ${num('prize_extra_block_minutes', 'min="0" step="1"')}</label>
        </div>
      </section>

      <section class="panel">
        <h3>Ausências que tiram o dia da base</h3>
        <fieldset><legend>O dia sai da base de cálculo (não conta contra a eficiência)</legend>
          ${Object.entries(ABSENCE_TYPE_LABELS).map(([key, label]) => `<label class="checkbox-line"><input type="checkbox" name="absence_types_excluded_from_base" value="${key}" ${excluded.has(key) ? 'checked' : ''} /> ${label}</label>`).join('')}
        </fieldset>
        <p class="hint">Tipos desmarcados continuam contando como dia sem produção.</p>
      </section>

      <section class="panel">
        <h3>Feriados</h3>
        <div class="form-grid">
          <label class="full">Feriados com data (um por linha, AAAA-MM-DD)<textarea name="holiday_dates" rows="4" placeholder="2026-11-20">${escapeHtml(String(v.holiday_dates || '').split(/[,;\n]/).map(x => x.trim()).filter(Boolean).join('\n'))}</textarea></label>
          <label>Feriados fixos todo ano (MM-DD)<textarea name="holiday_recurring_mmdd" rows="4" placeholder="01-01&#10;04-21&#10;12-25">${escapeHtml(String(v.holiday_recurring_mmdd || '').split(/[,;\n]/).map(x => x.trim()).filter(Boolean).join('\n'))}</textarea></label>
          <label>Feriados trabalhados (AAAA-MM-DD)<textarea name="worked_holiday_dates" rows="4" placeholder="2026-11-02">${escapeHtml(String(v.worked_holiday_dates || '').split(/[,;\n]/).map(x => x.trim()).filter(Boolean).join('\n'))}</textarea><small class="hint">Datas de feriado em que a empresa trabalhou normalmente.</small></label>
        </div>
      </section>

      <section class="panel">
        <p class="hint">Jornadas de trabalho (horários e intervalos) ficam em <a href="/cadastros#jornadas">Cadastros → Jornadas</a>.</p>
        <div class="actions"><button class="btn" type="submit">Salvar parâmetros</button><a class="btn secondary" href="/parametros">Descartar alterações</a></div>
      </section>
    </form>
    ${renderAlertsSection()}
    ${renderApiSection()}`;
  return pageLayout({ title: 'Parâmetros', content, notice: query.notice || '', error: error || query.error || '', role });
}

function handleSaveParameters(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const list = v => (Array.isArray(v) ? v : [v]).filter(x => x !== undefined && x !== '');
  const lines = v => String(v || '').split(/[,;\n\r]+/).map(x => x.trim()).filter(Boolean);
  const values = {};
  const errors = [];
  const number = (key, label, { min = 0, max = Infinity, integer = false } = {}) => {
    const n = Number(String(form[key] ?? '').replace(',', '.'));
    if (!Number.isFinite(n) || n < min || n > max || (integer && !Number.isInteger(n))) errors.push(`${label} inválido.`);
    values[key] = String(n);
  };
  number('base_minutes_day', 'Minutos de base por dia', { min: 1, max: 1440, integer: true });
  number('target_percent', 'Meta de eficiência', { min: 1, max: 200 });
  number('period_start_day', 'Dia de início do período', { min: 1, max: 28, integer: true });
  number('launch_previous_day_until_hour', 'Hora limite para lançar no dia anterior', { min: 0, max: 23, integer: true });
  for (const i of [1, 2, 3]) {
    number(`prize_tier${i}_percent`, `Percentual da faixa ${i}`, { min: 0, max: 200 });
    number(`prize_tier${i}_value`, `Valor da faixa ${i}`, { min: 0 });
  }
  number('prize_target_value', 'Prêmio da meta', { min: 0 });
  number('prize_extra_value', 'Prêmio extra', { min: 0 });
  number('prize_extra_block_minutes', 'Minutos do prêmio extra', { min: 0, integer: true });
  const workdays = list(form.workdays).map(Number).filter(d => d >= 0 && d <= 6);
  if (!workdays.length) errors.push('Marque ao menos um dia útil.');
  values.workdays = [...new Set(workdays)].sort().join(',');
  values.absence_types_excluded_from_base = list(form.absence_types_excluded_from_base).filter(k => ABSENCE_TYPE_LABELS[k]).join(',');
  const dates = lines(form.holiday_dates);
  const recurring = lines(form.holiday_recurring_mmdd);
  const worked = lines(form.worked_holiday_dates);
  const badDate = [...dates, ...worked].find(d => !/^\d{4}-\d{2}-\d{2}$/.test(d));
  const badMmdd = recurring.find(d => !/^\d{2}-\d{2}$/.test(d));
  if (badDate) errors.push(`Data inválida em feriados: ${badDate} (use AAAA-MM-DD).`);
  if (badMmdd) errors.push(`Feriado fixo inválido: ${badMmdd} (use MM-DD).`);
  values.holiday_dates = dates.join(',');
  values.holiday_recurring_mmdd = recurring.join(',');
  values.worked_holiday_dates = worked.join(',');
  if (errors.length) return sendHtml(res, renderParametersPage({}, { ...getParams(), ...values }, errors.join(' '), role), 422);

  const before = getParams();
  const changed = Object.keys(values).filter(key => String(before[key]) !== String(values[key]));
  db.exec('BEGIN');
  try {
    const upsert = db.prepare(`INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`);
    for (const key of changed) upsert.run(key, values[key]);
    if (changed.length) {
      upsert.run(`params_log_${Date.now()}`, JSON.stringify({ user: getRequestAuth()?.user?.username || '', changed: Object.fromEntries(changed.map(k => [k, { de: before[k], para: values[k] }])) }));
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    return sendHtml(res, renderParametersPage({}, { ...before, ...values }, `Erro ao salvar: ${err.message}`, role), 500);
  }
  invalidateParams();
  redirect(res, `/parametros?notice=${encodeURIComponent(changed.length ? `Parâmetros salvos (${changed.length} alteração(ões)).` : 'Nenhuma alteração.')}`);
}
// ===============================================================

function handleCreateBrand(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const validationError = validateBrandName(form.name);
  if (validationError) {
    return sendHtml(res, renderCadastrosPage({}, form, validationError, role), 422);
  }
  try {
    const normalized = String(form.name || '').trim();
    const existing = findBrandByName(normalized);
    if (existing) {
      return sendHtml(res, renderCadastrosPage({}, form, 'Essa marca já está cadastrada.', role), 422);
    }
    db.prepare('INSERT INTO brands (name, is_active, created_at, updated_at) VALUES (?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)').run(normalized);
    redirect(res, `/cadastros?notice=${encodeURIComponent('Marca cadastrada com sucesso.')}`);
  } catch (error) {
    sendHtml(res, renderCadastrosPage({}, form, `Erro ao salvar marca: ${error.message}`, role), 422);
  }
}

function handleCreateCollection(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const validationError = validateCollectionName(form.name);
  if (validationError) {
    return sendHtml(res, renderCadastrosPage({}, { collection_name_form: form.name || '' }, validationError, role), 422);
  }
  try {
    const normalized = String(form.name || '').trim();
    const existing = findCollectionByName(normalized);
    if (existing) {
      return sendHtml(res, renderCadastrosPage({}, { collection_name_form: form.name || '' }, 'Essa coleção já está cadastrada.', role), 422);
    }
    db.prepare('INSERT INTO collections (name, is_active, created_at, updated_at) VALUES (?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)').run(normalized);
    redirect(res, `/cadastros?notice=${encodeURIComponent('Coleção cadastrada com sucesso.')}`);
  } catch (error) {
    sendHtml(res, renderCadastrosPage({}, { collection_name_form: form.name || '' }, `Erro ao salvar coleção: ${error.message}`, role), 422);
  }
}


function handleCreateCell(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const validationError = validateCellName(form.cell_name);
  if (validationError) return sendHtml(res, renderCadastrosPage({}, form, validationError, role), 422);
  try {
    const normalized = String(form.cell_name || '').trim();
    if (findCellByName(normalized)) return sendHtml(res, renderCadastrosPage({}, form, 'Essa célula já está cadastrada.', role), 422);
    db.prepare('INSERT INTO sewing_cells (name, notes, is_active, created_at, updated_at) VALUES (?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)').run(normalized, String(form.cell_notes || '').trim() || null);
    redirect(res, `/cadastros?notice=${encodeURIComponent('Célula cadastrada com sucesso.')}`);
  } catch (error) {
    sendHtml(res, renderCadastrosPage({}, form, `Erro ao salvar célula: ${error.message}`, role), 422);
  }
}

function handleToggleCell(id, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const cell = getCellById(id);
  if (!cell) return redirect(res, `/cadastros?error=${encodeURIComponent('Célula não encontrada.')}`);
  db.prepare('UPDATE sewing_cells SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(cell.is_active ? 0 : 1, id);
  redirect(res, `/cadastros?notice=${encodeURIComponent(`Célula ${cell.is_active ? 'inativada' : 'ativada'} com sucesso.`)}`);
}

function handleSendOpToCell(opId, form, res, role) {
  if (!userCanManageCells(role)) return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Seu perfil não pode movimentar OP para célula.')}`);
  const op = db.prepare('SELECT * FROM ops WHERE id = ? AND is_reversed = 0').get(Number(opId));
  const cell = getCellById(form.cell_id);
  if (!op) return redirect(res, '/ops?error=' + encodeURIComponent('OP não encontrada.'));
  if (!cell || !cell.is_active) return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Selecione uma célula ativa.')}`);
  if (op.shipped_at) return redirect(res, `/ops/${opId}?error=${encodeURIComponent('OP já embarcada não pode ser enviada para célula.')}`);

  const opDetail = getOpDetail(Number(opId));
  const availableToSend = Math.max(Number(opDetail?.op?.remaining_quantity || 0) - Number(opDetail?.cellBalance?.total_open || 0), 0);
  const quantityToSend = Number.parseInt(form.quantity_sent, 10);
  if (!Number.isInteger(quantityToSend) || quantityToSend <= 0) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe uma quantidade válida para enviar à célula.')}`);
  }
  if (quantityToSend > availableToSend) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent(`Quantidade acima do saldo disponível. Restam ${availableToSend} peça(s) liberadas para novo envio.`)}`);
  }

  db.prepare(`INSERT INTO op_cell_transfers (op_id, cell_id, quantity_sent, quantity_returned, sent_at, sent_notes, created_by_user_id, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`).run(Number(opId), Number(form.cell_id), quantityToSend, form.sent_at || today(), String(form.sent_notes || '').trim() || null);
  recalculateOpStatus(opId);
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent(`${quantityToSend} peça(s) enviadas para a célula ${cell.name}.`)}`);
}

function handleReturnOpFromCell(opId, form, res, role) {
  if (!userCanManageCells(role)) return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Seu perfil não pode registrar retorno de célula.')}`);
  const transferId = Number(form.transfer_id || 0);
  const activeTransfers = getOpenCellTransfers(opId);
  const active = activeTransfers.find(item => Number(item.id) === transferId) || (transferId ? null : activeTransfers[0] || null);
  if (!active) return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Este envio não está mais pendente em célula.')}`);

  const openQuantity = getOpenQuantityFromCellTransfer(active);
  const returnQuantity = Number.parseInt(form.quantity_returned, 10);
  if (!Number.isInteger(returnQuantity) || returnQuantity <= 0) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent('Informe uma quantidade válida para retorno da célula.')}`);
  }
  if (returnQuantity > openQuantity) {
    return redirect(res, `/ops/${opId}?error=${encodeURIComponent(`O retorno informado ultrapassa o saldo aberto desse envio (${openQuantity} peça(s)).`)}`);
  }

  const nextReturned = Number(active.quantity_returned || 0) + returnQuantity;
  const fullyReturned = nextReturned >= Number(active.quantity_sent || 0);
  const previousNotes = String(active.return_notes || '').trim();
  const currentNotes = String(form.return_notes || '').trim();
  const mergedNotes = [previousNotes, currentNotes].filter(Boolean).join(' | ') || null;

  db.prepare(`
    UPDATE op_cell_transfers
    SET quantity_returned = ?,
        returned_at = CASE WHEN ? THEN ? ELSE returned_at END,
        return_notes = ?,
        returned_by_user_id = NULL,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(nextReturned, fullyReturned ? 1 : 0, form.returned_at || today(), mergedNotes, active.id);
  recalculateOpStatus(opId);
  redirect(res, `/ops/${opId}?notice=${encodeURIComponent(`Retorno de ${returnQuantity} peça(s) da célula ${active.cell_name} registrado.`)}`);
}

function getCellReportData(filters = {}) {
  const startDate = filters.start_date || today();
  const endDate = filters.end_date || today();
  const cellId = Number(filters.cell_id || 0);
  const opType = String(filters.op_type || '').trim();

  const rangeWhere = ['o.is_reversed = 0'];
  const rangeParams = [];
  if (startDate) {
    rangeWhere.push("(t.sent_at >= ? OR COALESCE(t.returned_at, '') >= ?)");
    rangeParams.push(startDate, startDate);
  }
  if (endDate) {
    rangeWhere.push('(t.sent_at <= ? OR COALESCE(t.returned_at, t.sent_at) <= ?)');
    rangeParams.push(endDate, endDate);
  }
  if (cellId) {
    rangeWhere.push('t.cell_id = ?');
    rangeParams.push(cellId);
  }
  if (opType) {
    rangeWhere.push('o.op_type = ?');
    rangeParams.push(opType);
  }

  const rows = db.prepare(`
    SELECT
      t.id,
      t.sent_at,
      t.returned_at,
      t.sent_notes,
      t.return_notes,
      t.quantity_sent,
      t.quantity_returned,
      (t.quantity_sent - t.quantity_returned) AS quantity_open,
      c.name AS cell_name,
      o.id AS op_id,
      o.op_number,
      o.product_name,
      o.op_type,
      o.brand,
      o.total_pieces,
      o.status_color,
      o.shipped_at,
      CAST((julianday(COALESCE(t.returned_at, DATE('now', '-3 hours'))) - julianday(t.sent_at)) AS INTEGER) + 1 AS days_in_cell,
      ROUND(t.quantity_sent * COALESCE(o.minutes_f21, 0), 2) AS sent_sewing_minutes,
      ROUND(t.quantity_returned * COALESCE(o.minutes_f21, 0), 2) AS returned_sewing_minutes,
      ROUND((t.quantity_sent - t.quantity_returned) * COALESCE(o.minutes_f21, 0), 2) AS open_sewing_minutes
    FROM op_cell_transfers t
    JOIN ops o ON o.id = t.op_id
    JOIN sewing_cells c ON c.id = t.cell_id
    WHERE ${rangeWhere.join(' AND ')}
    ORDER BY COALESCE(t.returned_at, t.sent_at) DESC, t.id DESC
  `).all(...rangeParams);

  const inCellNowWhere = ['o.is_reversed = 0', 'COALESCE(t.quantity_sent, 0) > COALESCE(t.quantity_returned, 0)'];
  const inCellNowParams = [];
  if (cellId) { inCellNowWhere.push('t.cell_id = ?'); inCellNowParams.push(cellId); }
  if (opType) { inCellNowWhere.push('o.op_type = ?'); inCellNowParams.push(opType); }
  const inCellNow = db.prepare(`
    SELECT COUNT(*) AS total, COALESCE(SUM(t.quantity_sent - t.quantity_returned), 0) AS pieces
    FROM op_cell_transfers t
    JOIN ops o ON o.id = t.op_id
    WHERE ${inCellNowWhere.join(' AND ')}
  `).get(...inCellNowParams);

  const summary = {
    sentCount: rows.length,
    returnedCount: rows.filter(item => Number(item.quantity_returned || 0) > 0).length,
    inCellCount: Number(inCellNow.total || 0),
    inCellPieces: Number(inCellNow.pieces || 0),
    inCellMinutes: rows.reduce((acc, item) => acc + Number(item.open_sewing_minutes || 0), 0),
    sentPieces: rows.reduce((acc, item) => acc + Number(item.quantity_sent || 0), 0),
    returnedPieces: rows.reduce((acc, item) => acc + Number(item.quantity_returned || 0), 0),
    returnedMinutes: rows.reduce((acc, item) => acc + Number(item.returned_sewing_minutes || 0), 0),
    uniqueOpsInPeriod: new Set(rows.map(item => item.op_id)).size
  };

  const byCell = [];
  const grouped = new Map();
  for (const row of rows) {
    const key = row.cell_name;
    if (!grouped.has(key)) grouped.set(key, { cell_name: row.cell_name, sent_moves: 0, sent_pieces: 0, returned_pieces: 0, open_pieces: 0, open_moves: 0, returned_minutes: 0, production_ops: 0, sample_ops: 0 });
    const item = grouped.get(key);
    item.sent_moves += 1;
    item.sent_pieces += Number(row.quantity_sent || 0);
    item.returned_pieces += Number(row.quantity_returned || 0);
    item.open_pieces += Number(row.quantity_open || 0);
    if (Number(row.quantity_open || 0) > 0) item.open_moves += 1;
    item.returned_minutes += Number(row.returned_sewing_minutes || 0);
    if (row.op_type === 'producao') item.production_ops += 1;
    if (row.op_type === 'mostruario') item.sample_ops += 1;
  }
  byCell.push(...grouped.values());
  byCell.sort((a, b) => (b.open_pieces - a.open_pieces) || (b.sent_pieces - a.sent_pieces) || a.cell_name.localeCompare(b.cell_name));

  return { filters: { startDate, endDate, cellId, opType }, rows, summary, byCell, cells: getCellList() };
}

function renderCellReportPage(query = {}, role = 'adm') {
  const data = getCellReportData(query);
  const content = `
    <section class="page-header">
      <div><h2>Célula - relatórios e acompanhamento</h2><p>Visão própria do módulo de costura em célula. Os registros daqui não entram na eficiência diária normal.</p></div>
    </section>

    <form class="panel inline-form" method="get" action="/cells/report">
      <label>De<input type="date" name="start_date" value="${escapeHtml(data.filters.startDate)}" /></label>
      <label>Até<input type="date" name="end_date" value="${escapeHtml(data.filters.endDate)}" /></label>
      <label>Célula<select name="cell_id"><option value="">Todas</option>${data.cells.map(cell => `<option value="${cell.id}" ${Number(data.filters.cellId) === Number(cell.id) ? 'selected' : ''}>${escapeHtml(cell.name)}</option>`).join('')}</select></label>
      <label>Tipo da OP<select name="op_type"><option value="">Todos</option><option value="producao" ${data.filters.opType === 'producao' ? 'selected' : ''}>Produção</option><option value="mostruario" ${data.filters.opType === 'mostruario' ? 'selected' : ''}>Mostruário</option></select></label>
      <button class="btn" type="submit">Filtrar</button>
      <a class="btn secondary" href="/cells/report">Hoje</a>
    </form>

    <div class="cards">
      <article class="card status-card bg-pink"><span>Movimentos no período</span><strong>${data.summary.sentCount}</strong><small>${data.summary.sentPieces} peças enviadas no filtro</small></article>
      <article class="card status-card bg-yellow"><span>Em célula agora</span><strong>${data.summary.inCellCount}</strong><small>${data.summary.inCellPieces} peças ainda abertas · ${fmtNum(data.summary.inCellMinutes, 2)} min F21</small></article>
      <article class="card status-card bg-blue"><span>Devolvidas pelas células</span><strong>${data.summary.returnedCount}</strong><small>${data.summary.returnedPieces} peças · ${fmtNum(data.summary.returnedMinutes, 2)} min F21</small></article>
      <article class="card"><span>Células no filtro</span><strong>${data.byCell.length}</strong><small>${data.summary.uniqueOpsInPeriod} OPs distintas movimentadas no período</small></article>
    </div>

    <div class="two-columns">
      <section class="panel">
        <h3>Resumo por célula</h3>
        <table><thead><tr><th>Célula</th><th>Mov.</th><th>Recebeu</th><th>Devolveu</th><th>Saldo aberto</th><th>Envios abertos</th><th>Min. devolvidos</th><th>Produção</th><th>Mostruário</th></tr></thead><tbody>
          ${data.byCell.map(item => `<tr><td>${escapeHtml(item.cell_name)}</td><td>${item.sent_moves}</td><td>${item.sent_pieces}</td><td>${item.returned_pieces}</td><td>${item.open_pieces}</td><td>${item.open_moves}</td><td>${fmtNum(item.returned_minutes, 2)}</td><td>${item.production_ops}</td><td>${item.sample_ops}</td></tr>`).join('') || '<tr><td colspan="9">Sem movimentos de célula no período.</td></tr>'}
        </tbody></table>
      </section>

      <section class="panel">
        <h3>Visão consolidada</h3>
        <ul>
          <li><strong>Recebeu</strong>: soma das peças enviadas para cada célula.</li>
          <li><strong>Devolveu</strong>: soma do que já retornou de cada célula.</li>
          <li><strong>Saldo aberto</strong>: peças ainda pendentes de retorno naquela célula.</li>
          <li>Fechamento azul só acontece quando não existe saldo aberto em célula e a OP já teve todo o total considerado.</li>
        </ul>
      </section>
    </div>

    <section class="panel">
      <h3>Movimentos detalhados</h3>
      <table><thead><tr><th>OP</th><th>Produto</th><th>Célula</th><th>Tipo</th><th>Envio</th><th>Retorno final</th><th>Dias</th><th>Status</th><th>Recebeu</th><th>Devolveu</th><th>Aberto</th><th>Min. F21 aberto</th></tr></thead><tbody>
        ${data.rows.map(row => `<tr><td><a href="/ops/${row.op_id}">${escapeHtml(row.op_number)}</a></td><td>${escapeHtml(row.product_name)}</td><td>${escapeHtml(row.cell_name)}</td><td>${escapeHtml(row.op_type)}</td><td>${escapeHtml(nowPt(row.sent_at))}</td><td>${escapeHtml(nowPt(row.returned_at))}</td><td>${Number(row.days_in_cell || 0)}</td><td>${row.shipped_at ? '<span class="badge vermelho">embarcada</span>' : (Number(row.quantity_open || 0) > 0 ? '<span class="badge rosa">pendente</span>' : '<span class="badge azul">retornado</span>')}</td><td>${Number(row.quantity_sent || 0)}</td><td>${Number(row.quantity_returned || 0)}</td><td>${Number(row.quantity_open || 0)}</td><td>${fmtNum(Number(row.open_sewing_minutes || 0), 2)}</td></tr>`).join('') || '<tr><td colspan="12">Nenhum movimento encontrado.</td></tr>'}
      </tbody></table>
    </section>
  `;
  return pageLayout({ title: 'Célula - relatórios', content, notice: query.notice || '', error: query.error || '', role });
}

function handleSaveCompanyName(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const companyName = String(form.company_name || '').trim();
  if (!companyName) {
    return sendHtml(res, renderCadastrosPage({}, {}, 'Informe o nome da empresa para as etiquetas.', role), 422);
  }
  setAppSetting('company_name', companyName);
  const auth = getRequestAuth();
  if (auth?.company?.id) {
    masterDb.prepare('UPDATE companies SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(companyName, auth.company.id);
    auth.company.name = companyName;
  }
  redirect(res, `/cadastros?notice=${encodeURIComponent('Nome da empresa atualizado com sucesso.')}`);
}

function getCompanyUsersByCompany(companyId) {
  return masterDb.prepare(`
    SELECT u.id, u.company_id, u.username, u.full_name, u.role, u.is_active, u.created_at
    FROM company_users u
    WHERE u.company_id = ?
    ORDER BY u.username COLLATE NOCASE
  `).all(Number(companyId));
}

function renderAccessAdminPage(query = {}, values = {}, error = '', notice = '') {
  const auth = getRequestAuth();
  const users = auth?.company?.id ? getCompanyUsersByCompany(auth.company.id) : [];
  const usersHtml = users.length
    ? `<div class="table-wrapper"><table><thead><tr><th>Usuário</th><th>Nome</th><th>Perfil</th></tr></thead><tbody>${users.map(user => `
        <tr>
          <td>${escapeHtml(user.username)}</td>
          <td>${escapeHtml(user.full_name)}</td>
          <td>${escapeHtml(ROLE_LABELS[user.role] || user.role)}</td>
        </tr>
      `).join('')}</tbody></table></div>`
    : '<p class="hint">Nenhum usuário cadastrado para esta empresa.</p>';

  const content = `
    <section class="page-header"><div><h2>Usuários e acessos</h2><p>Gerencie somente os usuários da empresa atual: <strong>${escapeHtml(auth?.company?.name || '')}</strong>.</p></div></section>
    <section class="panel form-grid">
      <div class="full"><h3 style="margin-top:0;">Novo usuário</h3></div>
      <form class="full form-grid" method="post" action="/admin/access/users">
        <label>Usuário<input name="username" required value="${escapeHtml(values.username || '')}" /></label>
        <label>Nome completo<input name="full_name" required value="${escapeHtml(values.full_name || '')}" /></label>
        <label>Perfil<select name="role" required>
          ${Object.entries(ROLE_LABELS).map(([value, label]) => `<option value="${value}" ${String(values.role || 'operacional') === value ? 'selected' : ''}>${escapeHtml(label)}</option>`).join('')}
        </select></label>
        <label>Senha inicial<input type="password" name="password" required /></label>
        <div class="full actions"><button class="btn" type="submit">Cadastrar usuário</button></div>
      </form>
    </section>
    <section class="panel form-grid">
      <div class="full"><h3 style="margin-top:0;">Redefinir senha</h3></div>
      <form class="full form-grid" method="post" action="/admin/access/password">
        <label>Usuário<select name="user_id" required><option value="">Selecione</option>${users.map(user => `<option value="${user.id}">${escapeHtml(user.username)} · ${escapeHtml(user.full_name)}</option>`).join('')}</select></label>
        <label>Nova senha<input type="password" name="password" required /></label>
        <div class="full actions"><button class="btn secondary" type="submit">Atualizar senha</button></div>
      </form>
    </section>
    <section class="panel"><h3 style="margin-top:0;">Usuários cadastrados</h3>${usersHtml}</section>
    <section class="panel"><p class="hint">Cadastro de novas empresas foi movido para o painel separado de superadmin.</p></section>
  `;

  return pageLayout({ title: 'Usuários e acessos', content, error, notice, role: getRequestRole() });
}

function handleCreateCompanyUser(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  try {
    const auth = getRequestAuth();
    createCompanyUser({
      companyId: auth.company.id,
      username: form.username,
      fullName: form.full_name,
      password: form.password,
      role: form.role
    });
    redirect(res, `/admin/access?notice=${encodeURIComponent('Usuário criado com sucesso.')}`);
  } catch (error) {
    sendHtml(res, renderAccessAdminPage({}, form, error.message), 422);
  }
}

function handleResetCompanyUserPassword(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  try {
    const auth = getRequestAuth();
    const allowed = getCompanyUsersByCompany(auth.company.id).some(user => Number(user.id) === Number(form.user_id));
    if (!allowed) throw new Error('Você só pode redefinir senhas da sua própria empresa.');
    updateCompanyUserPassword({ userId: form.user_id, password: form.password });
    redirect(res, `/admin/access?notice=${encodeURIComponent('Senha atualizada com sucesso.')}`);
  } catch (error) {
    sendHtml(res, renderAccessAdminPage({}, form, error.message), 422);
  }
}

function renderEmployeeForm(values = {}, error = '') {
  const content = `
    <section class="page-header"><div><h2>Cadastro de colaboradores</h2><p>Registro único por colaborador.</p></div></section>
    <form class="panel form-grid" method="post" action="/employees">
      <label>Registro<input name="registration_code" required value="${escapeHtml(values.registration_code || '')}" /></label>
      <label>Nome completo<input name="full_name" required value="${escapeHtml(values.full_name || '')}" /></label>
      <label class="full">Observações<textarea name="notes" rows="4">${escapeHtml(values.notes || '')}</textarea></label>
      <div class="full actions"><button class="btn" type="submit">Salvar colaborador</button><a class="btn secondary" href="/employees">Ver lista</a></div>
    </form>
  `;
  return pageLayout({ title: 'Novo colaborador', content, error, role: 'adm' });
}

// Envio em sequência do resultado do período por WhatsApp (uma conversa por clique)
function renderEmployeeWhatsAppQueuePage(role = 'adm') {
  const all = db.prepare('SELECT * FROM employees').all()
    .filter(emp => describeEmployeeStatus(emp) === 'Ativo')
    .sort((a, b) => String(a.full_name).localeCompare(String(b.full_name), 'pt-BR', { sensitivity: 'base' }));
  const context = getEmployeeResultContext(all);
  const queue = [];
  const withoutPhone = [];
  for (const emp of all) {
    const message = buildEmployeeResultMessage(emp, context);
    if (!emp.phone) { withoutPhone.push(emp); continue; }
    if (!message) continue;
    queue.push({ id: emp.id, name: emp.full_name, phone: formatPhone(emp.phone), url: `https://wa.me/55${emp.phone}?text=${encodeURIComponent(message)}` });
  }
  const storageKey = `agilfac_wa_${context.range.start}_${context.cutoff}`;
  const content = `
    <section class="page-header"><div><h2>Enviar resultado por WhatsApp</h2><p>Período ${formatDatePtBr(context.range.start)} a ${formatDatePtBr(context.range.end)}, até ${formatDatePtBr(context.cutoff)}. Clique em <strong>Abrir próxima</strong>, envie no WhatsApp e volte aqui.</p></div><a class="btn secondary" href="/employees">Voltar</a></section>
    <section class="panel wa-queue">
      <div class="wa-queue-head">
        <button class="btn" type="button" data-wa-next>Abrir próxima</button>
        <span class="active-count-pill" data-wa-progress>0 de ${queue.length}</span>
        <button class="btn secondary" type="button" data-wa-reset>Recomeçar</button>
      </div>
      <table class="table-zebra">
        <thead><tr><th>Colaboradora</th><th>WhatsApp</th><th>Situação</th><th></th></tr></thead>
        <tbody>
          ${queue.map(item => `<tr data-wa-row="${item.id}"><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.phone)}</td><td data-wa-status><span class="status-tag off">Pendente</span></td><td><button class="btn secondary" type="button" data-wa-open="${item.id}">Abrir</button></td></tr>`).join('') || '<tr><td colspan="4">Nenhuma colaboradora ativa com telefone cadastrado.</td></tr>'}
        </tbody>
      </table>
      ${withoutPhone.length ? `<p class="hint">Sem telefone cadastrado (${withoutPhone.length}): ${withoutPhone.map(emp => escapeHtml(emp.full_name)).join(', ')}.</p>` : ''}
    </section>
    <script>
      (() => {
        const queue = ${JSON.stringify(queue.map(({ id, url }) => ({ id, url })))};
        const key = ${JSON.stringify(storageKey)};
        let sent = new Set();
        try { sent = new Set(JSON.parse(localStorage.getItem(key) || '[]')); } catch (_) {}
        const save = () => { try { localStorage.setItem(key, JSON.stringify([...sent])); } catch (_) {} };
        const progress = document.querySelector('[data-wa-progress]');
        const nextBtn = document.querySelector('[data-wa-next]');
        const render = () => {
          queue.forEach(item => {
            const cell = document.querySelector('[data-wa-row="' + item.id + '"] [data-wa-status]');
            if (cell) cell.innerHTML = sent.has(item.id) ? '<span class="status-tag ok">Aberto</span>' : '<span class="status-tag off">Pendente</span>';
          });
          progress.textContent = sent.size + ' de ' + queue.length;
          const done = queue.every(item => sent.has(item.id));
          nextBtn.textContent = done ? 'Todas abertas ✓' : 'Abrir próxima';
          nextBtn.disabled = done;
        };
        const open = item => {
          window.open(item.url, 'agilfac_whatsapp');
          sent.add(item.id); save(); render();
        };
        nextBtn.addEventListener('click', () => { const item = queue.find(q => !sent.has(q.id)); if (item) open(item); });
        document.querySelectorAll('[data-wa-open]').forEach(btn => btn.addEventListener('click', () => {
          const item = queue.find(q => String(q.id) === btn.dataset.waOpen); if (item) open(item);
        }));
        document.querySelector('[data-wa-reset]').addEventListener('click', () => { if (confirm('Marcar todas como pendentes de novo?')) { sent.clear(); save(); render(); } });
        render();
      })();
    </script>`;
  return pageLayout({ title: 'Enviar resultado por WhatsApp', content, role });
}

function renderEmployeeList(query = {}, values = {}, error = '', role = 'adm') {
  // Ativas primeiro; desligadas/inativas no fim. Cada grupo em ordem alfabética.
  const search = String(query.q || '').trim().toLowerCase();
  const showInactive = query.status === 'todas';
  const allEmployees = db.prepare('SELECT * FROM employees').all();
  const employees = allEmployees.filter(emp => {
    if (!showInactive && describeEmployeeStatus(emp) !== 'Ativo' && Number(query.edit || 0) !== emp.id) return false;
    if (!search) return true;
    return String(emp.full_name || '').toLowerCase().includes(search) || String(emp.registration_code || '').toLowerCase().includes(search);
  }).sort((a, b) => {
    const ia = describeEmployeeStatus(a) === 'Ativo' ? 0 : 1;
    const ib = describeEmployeeStatus(b) === 'Ativo' ? 0 : 1;
    return ia - ib || String(a.full_name).localeCompare(String(b.full_name), 'pt-BR', { sensitivity: 'base' });
  });
  const scheduleNames = new Map(getWorkSchedules().map(item => [item.id, item.name]));
  const activeCount = allEmployees.filter(emp => describeEmployeeStatus(emp) === 'Ativo').length;
  const inactiveCount = allEmployees.length - activeCount;
  const resultContext = getEmployeeResultContext(employees);
  const editingId = Number(query.edit || 0);
  const showForm = query.new === '1' || Boolean(error);
  const content = `
    <section class="page-header"><div><h2>Colaboradores <span class="active-count-pill">${activeCount} ativas</span></h2><p>Base de apoio para lançamentos diários.</p></div><div class="actions"><a class="btn secondary" href="/employees/whatsapp-resultados">Enviar resultado para todas</a><a class="btn" href="/employees?new=1">Novo colaborador</a></div></section>
    <form class="panel inline-form employees-filter" method="get" action="/employees">
      <label>Buscar<input name="q" value="${escapeHtml(query.q || '')}" placeholder="Nome ou registro" autocomplete="off" /></label>
      <label class="checkbox-line"><input type="checkbox" name="status" value="todas" ${showInactive ? 'checked' : ''} onchange="this.form.submit()" /> Mostrar desligadas (${inactiveCount})</label>
      <button class="btn" type="submit">Buscar</button>
      ${search || showInactive ? '<a class="btn secondary" href="/employees">Limpar</a>' : ''}
    </form>
    ${showForm ? `
    <section class="panel">
      <h3>Cadastro de colaborador</h3>
      <form class="form-grid" method="post" action="/employees">
        <label>Registro<input name="registration_code" required value="${escapeHtml(values.registration_code || '')}" /></label>
        <label>Nome completo *<input name="full_name" required value="${escapeHtml(values.full_name || '')}" /></label>
        <label>Telefone (WhatsApp) *<input type="tel" name="phone" inputmode="numeric" required data-phone-mask maxlength="15" pattern="\\(\\d{2}\\) \\d{4,5}-\\d{4}" title="Informe DDD + número, ex.: (47) 99999-9999" placeholder="(47) 99999-9999" value="${escapeHtml(formatPhone(normalizePhone(values.phone)))}" /></label>
        <label>Data de nascimento *<input type="date" name="birth_date" required value="${formatDateInput(values.birth_date)}" /></label>
        <label>Data de admissão *<input type="date" name="start_date" required value="${formatDateInput(values.start_date)}" /></label>
        <label>Data de rescisão<input type="date" name="termination_date" value="${formatDateInput(values.termination_date)}" /></label>
        <label>Função *<input name="job_role" required value="${escapeHtml(values.job_role || '')}" /></label>
        ${renderWorkScheduleSelect(values.work_schedule_id, true)}
        <label>Meta de cobrança (%)<input type="number" name="target_percent" min="1" max="200" step="0.01" inputmode="decimal" placeholder="Padrão: ${tp()}" value="${escapeHtml(values.target_percent ?? '')}" /><small class="hint">Em branco: ${tp()}%. Vale para acompanhamento e mensagens; o prêmio segue a regra geral.</small></label>
        <label class="full">Observações<textarea name="notes" rows="3">${escapeHtml(values.notes || '')}</textarea></label>
        <div class="full actions"><button class="btn" type="submit">Salvar colaborador</button><a class="btn secondary" href="/employees">Cancelar</a></div>
      </form>
      <p class="hint">Se as datas ficarem em branco, o sistema trata o colaborador como ativo em todo o período dos relatórios até que sejam preenchidas.</p>
    </section>` : ''}
    <section class="panel">
      <table class="table-zebra employees-table">
        <thead><tr><th>Registro</th><th>Nome</th><th>WhatsApp</th><th>Nascimento</th><th>Início</th><th>Rescisão</th><th>Status</th><th>Função</th><th>Jornada</th><th>Meta cobrança</th><th>Observações</th><th>Ações</th></tr></thead>
        <tbody>
          ${employees.map(emp => {
            const isEditing = editingId === emp.id;
            const req = emp.termination_date ? '' : 'required';
            if (isEditing) {
              return `<tr>
                <td colspan="12">
                  <form class="form-grid" method="post" action="/employees/${emp.id}">
                    <label>Registro<input name="registration_code" required value="${escapeHtml(emp.registration_code || '')}" /></label>
                    <label>Nome completo *<input name="full_name" required value="${escapeHtml(emp.full_name || '')}" /></label>
                    <label>Telefone (WhatsApp)${emp.termination_date ? '' : ' *'}<input type="tel" name="phone" inputmode="numeric" ${emp.termination_date ? '' : 'required'} data-phone-mask maxlength="15" pattern="\\(\\d{2}\\) \\d{4,5}-\\d{4}" title="Informe DDD + número, ex.: (47) 99999-9999" placeholder="(47) 99999-9999" value="${escapeHtml(formatPhone(emp.phone))}" /></label>
                    <label>Data de nascimento${req ? ' *' : ''}<input type="date" name="birth_date" ${req} value="${formatDateInput(emp.birth_date)}" /></label>
                    <label>Data de admissão${req ? ' *' : ''}<input type="date" name="start_date" ${req} value="${formatDateInput(emp.start_date)}" /></label>
                    <label>Data de rescisão<input type="date" name="termination_date" value="${formatDateInput(emp.termination_date)}" /></label>
                    <label>Função${req ? ' *' : ''}<input name="job_role" ${req} value="${escapeHtml(emp.job_role || '')}" /></label>
                    ${renderWorkScheduleSelect(emp.work_schedule_id, Boolean(req))}
                    <label>Meta de cobrança (%)<input type="number" name="target_percent" min="1" max="200" step="0.01" inputmode="decimal" placeholder="Padrão: ${tp()}" value="${escapeHtml(emp.target_percent ?? '')}" /><small class="hint">Em branco: ${tp()}%. Vale para acompanhamento e mensagens; o prêmio segue a regra geral.</small></label>
                    <label class="full">Observações<textarea name="notes" rows="3">${escapeHtml(emp.notes || '')}</textarea></label>
                    <div class="full actions"><button class="btn" type="submit">Salvar edição</button><a class="btn secondary" href="/employees">Cancelar</a></div>
                  </form>
                </td>
              </tr>`;
            }
            const status = describeEmployeeStatus(emp);
            return `<tr class="${status === 'Ativo' ? 'is-active' : 'is-inactive'}"><td>${escapeHtml(emp.registration_code)}</td><td>${escapeHtml(emp.full_name)}</td><td>${renderWhatsAppLink(emp.phone, status === 'Ativo' ? buildEmployeeResultMessage(emp, resultContext) : '')}</td><td>${escapeHtml(nowPt(emp.birth_date))}</td><td>${escapeHtml(nowPt(emp.start_date))}</td><td>${escapeHtml(nowPt(emp.termination_date))}</td><td><span class="status-tag ${status === 'Ativo' ? 'ok' : 'off'}">${escapeHtml(status)}</span></td><td>${escapeHtml(emp.job_role || '-')}</td><td>${escapeHtml(scheduleNames.get(emp.work_schedule_id) || 'Sem jornada')}</td><td title="Meta por dia: ${fmtNum(round2(baseMinutesDay() * employeeTargetRatio(emp)), 1)} min">${Number(emp.target_percent) > 0 ? `<strong>${fmtPct(emp.target_percent)}%</strong>` : `${tp()}% <small class="hint">padrão</small>`}</td><td>${escapeHtml(emp.notes || '-')}</td><td><a href="/employees?edit=${emp.id}">Editar</a></td></tr>`;
          }).join('') || '<tr><td colspan="12">Nenhum colaborador cadastrado.</td></tr>'}
          ${PHONE_MASK_SCRIPT}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'Colaboradores', content, notice: query.notice || '', error: error || query.error || '', role });
}


function getHourlyProductionRows(productionDate = today(), employeeId = '') {
  const where = ['hp.is_reversed = 0', 'hp.production_date = ?'];
  const params = [productionDate];
  if (employeeId) {
    where.push('hp.employee_id = ?');
    params.push(Number(employeeId));
  }
  return db.prepare(`
    SELECT
      hp.*,
      o.op_number,
      o.product_name,
      e.registration_code,
      e.full_name,
      COALESCE(v.produced_quantity, 0) AS validated_quantity,
      ROUND(COALESCE(v.produced_minutes, 0), 3) AS validated_minutes
    FROM hourly_productions hp
    JOIN ops o ON o.id = hp.op_id
    JOIN employees e ON e.id = hp.employee_id
    LEFT JOIN op_daily_productions v ON v.id = hp.validated_daily_production_id
    WHERE ${where.join(' AND ')}
    ORDER BY hp.hour_slot ASC, e.full_name ASC, hp.created_at DESC
  `).all(...params).map(item => ({
    ...item,
    hour_efficiency_percent: round2((Number(item.produced_minutes || 0) / (baseMinutesDay() / 8)) * 100)
  }));
}

function getHourlyValidationSummary(productionDate = today()) {
  return db.prepare(`
    SELECT
      e.id AS employee_id,
      e.registration_code,
      e.full_name,
      COUNT(hp.id) AS total_rows,
      COUNT(DISTINCT hp.hour_slot) AS launched_hours,
      COALESCE(SUM(hp.produced_quantity), 0) AS total_quantity,
      ROUND(COALESCE(SUM(hp.produced_minutes), 0), 3) AS total_minutes,
      SUM(CASE WHEN hp.is_validated = 1 THEN 1 ELSE 0 END) AS validated_rows,
      SUM(CASE WHEN hp.is_validated = 0 THEN 1 ELSE 0 END) AS pending_rows
    FROM employees e
    LEFT JOIN hourly_productions hp
      ON hp.employee_id = e.id
      AND hp.production_date = ?
      AND hp.is_reversed = 0
    WHERE COALESCE(e.termination_date, '9999-12-31') >= ?
    GROUP BY e.id
    HAVING total_rows > 0
    ORDER BY e.full_name ASC
  `).all(productionDate, productionDate).map(item => ({
    ...item,
    launched_hours: Number(item.launched_hours || 0) + (zeroHourCountByEmployee(productionDate).get(item.employee_id) || 0),
    day_efficiency_percent: round2((Number(item.total_minutes || 0) / baseMinutesDay()) * 100)
  }));
}

function getHourlyEmployeeDaySummary(employeeId, productionDate = today(), currentHourSlot = currentHourSlot()) {
  if (!employeeId) return null;
  const rows = db.prepare(`
    SELECT hour_slot, produced_quantity, produced_minutes
    FROM hourly_productions
    WHERE employee_id = ?
      AND production_date = ?
      AND is_reversed = 0
      AND hour_slot <= ?
    ORDER BY hour_slot ASC, id ASC
  `).all(Number(employeeId), productionDate, currentHourSlot);
  const totalMinutes = round3(rows.reduce((sum, item) => sum + Number(item.produced_minutes || 0), 0));
  const totalQuantity = rows.reduce((sum, item) => sum + Number(item.produced_quantity || 0), 0);
  const zeroSlots = db.prepare('SELECT hour_slot FROM hourly_zero_hours WHERE employee_id = ? AND production_date = ? AND is_reversed = 0').all(Number(employeeId), productionDate).map(r => r.hour_slot);
  const launchedHours = new Set([...rows.map(item => item.hour_slot), ...zeroSlots]).size;
  const zeroHours = zeroSlots.length;
  const expectedHours = 8;
  // Eficiência do dia sempre sobre a base cheia do dia (528 min)
  const expectedBaseMinutes = baseMinutesDay();
  const dayEfficiencyPercent = expectedBaseMinutes > 0 ? round2((totalMinutes / expectedBaseMinutes) * 100) : 0;
  return {
    totalMinutes,
    totalQuantity,
    launchedHours,
    zeroHours,
    expectedHours,
    expectedBaseMinutes,
    dayEfficiencyPercent
  };
}

function getLastHourlyOpForEmployee(employeeId, productionDate = today()) {
  if (!employeeId) return null;
  return db.prepare(`
    SELECT hp.op_id, o.op_number, o.product_name
    FROM hourly_productions hp
    JOIN ops o ON o.id = hp.op_id
    WHERE hp.employee_id = ?
      AND hp.production_date = ?
      AND hp.is_reversed = 0
    ORDER BY hp.hour_slot DESC, hp.id DESC
    LIMIT 1
  `).get(Number(employeeId), productionDate) || null;
}

// Colaboradoras ativas, em dia útil delas, sem nenhum lançamento no dia (hora, hora zero ou diário)
function getEmployeesWithoutLaunch(productionDate = today()) {
  const employees = db.prepare('SELECT * FROM employees').all()
    .filter(emp => describeEmployeeStatus(emp) === 'Ativo' && getEmployeeBusinessDaysInRange(emp, productionDate, productionDate).length);
  const launched = new Set([
    ...db.prepare('SELECT DISTINCT employee_id FROM hourly_productions WHERE production_date = ? AND is_reversed = 0').all(productionDate),
    ...db.prepare('SELECT DISTINCT employee_id FROM hourly_zero_hours WHERE production_date = ? AND is_reversed = 0').all(productionDate),
    ...db.prepare('SELECT DISTINCT employee_id FROM op_daily_productions WHERE production_date = ? AND is_reversed = 0').all(productionDate)
  ].map(r => r.employee_id));
  const absences = new Map(db.prepare('SELECT employee_id, absence_type FROM employee_absences WHERE absence_date = ?').all(productionDate).map(r => [r.employee_id, r.absence_type]));
  const list = employees.filter(emp => !launched.has(emp.id)).map(emp => ({ id: emp.id, name: emp.full_name, absence: absences.get(emp.id) || '' }))
    .sort((a, b) => Number(Boolean(a.absence)) - Number(Boolean(b.absence)) || a.name.localeCompare(b.name));
  return { list, active: employees.length, withAbsence: list.filter(i => i.absence).length };
}

function getHourlyDashboardData(productionDate = today()) {
  const zeroCounts = zeroHourCountByEmployee(productionDate);
  const rows = db.prepare(`
    SELECT
      e.id AS employee_id,
      e.registration_code,
      e.full_name,
      e.termination_date,
      MIN(hp.hour_slot) AS first_hour_slot,
      MAX(hp.hour_slot) AS last_hour_slot,
      COUNT(DISTINCT hp.hour_slot) AS launched_hours,
      COALESCE(SUM(hp.produced_quantity), 0) AS total_quantity,
      ROUND(COALESCE(SUM(hp.produced_minutes), 0), 3) AS total_minutes
    FROM employees e
    JOIN hourly_productions hp
      ON hp.employee_id = e.id
      AND hp.production_date = ?
      AND hp.is_reversed = 0
    WHERE COALESCE(e.termination_date, '9999-12-31') >= ?
    GROUP BY e.id
    ORDER BY e.full_name ASC
  `).all(productionDate, productionDate).map(item => ({
    ...item,
    total_minutes: round3(item.total_minutes || 0),
    total_quantity: Number(item.total_quantity || 0),
    launched_hours: Number(item.launched_hours || 0) + (zeroCounts.get(item.employee_id) || 0),
    first_hour_number: Number(String(item.first_hour_slot || '00:00').split(':')[0] || 0),
    last_hour_number: Number(String(item.last_hour_slot || '00:00').split(':')[0] || 0)
  }));

  const totalMinutes = round3(rows.reduce((sum, item) => sum + Number(item.total_minutes || 0), 0));
  const totalQuantity = rows.reduce((sum, item) => sum + Number(item.total_quantity || 0), 0);

  return {
    rows,
    totalMinutes,
    totalQuantity,
    seamstressCount: rows.length
  };
}

function getZeroHours(productionDate, employeeId = '') {
  const params = [productionDate];
  let where = 'z.production_date = ? AND z.is_reversed = 0';
  if (employeeId) { where += ' AND z.employee_id = ?'; params.push(Number(employeeId)); }
  return db.prepare(`SELECT z.*, e.registration_code, e.full_name FROM hourly_zero_hours z JOIN employees e ON e.id = z.employee_id WHERE ${where} ORDER BY z.hour_slot, e.full_name`).all(...params);
}

function zeroHourCountByEmployee(productionDate) {
  return new Map(db.prepare('SELECT employee_id, COUNT(*) AS n FROM hourly_zero_hours WHERE production_date = ? AND is_reversed = 0 GROUP BY employee_id').all(productionDate).map(r => [r.employee_id, Number(r.n)]));
}

function handleCreateZeroHour(form, res) {
  const productionDate = String(form.production_date || today()).trim() || today();
  const hourSlot = normalizeHourSlotInput(form.hour_slot);
  const employeeId = Number(form.employee_id || 0);
  if (!employeeId || !hourSlot) return sendHtml(res, renderHourlyProductionPage(form, 'Para a hora zero, informe a costureira e a hora.', '', getRequestRole()), 422);
  const zeroReason = String(form.zero_reason || '').trim().slice(0, 200);
  if (!zeroReason) return sendHtml(res, renderHourlyProductionPage(form, 'Informe o motivo da hora zero.', '', getRequestRole()), 422);
  const dateError = checkLaunchDate(productionDate, getRequestRole());
  if (dateError) return sendHtml(res, renderHourlyProductionPage(form, dateError, '', getRequestRole()), 422);
  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  if (!employee) return sendHtml(res, renderHourlyProductionPage(form, 'Costureira não encontrada.', '', getRequestRole()), 404);
  const taken = db.prepare('SELECT 1 FROM hourly_productions WHERE employee_id = ? AND production_date = ? AND hour_slot = ? AND is_reversed = 0').get(employeeId, productionDate, hourSlot)
    || db.prepare('SELECT 1 FROM hourly_zero_hours WHERE employee_id = ? AND production_date = ? AND hour_slot = ? AND is_reversed = 0').get(employeeId, productionDate, hourSlot);
  if (taken) return sendHtml(res, renderHourlyProductionPage(form, `A hora ${hourSlot} já foi lançada para essa costureira.`, '', getRequestRole()), 422);
  db.prepare('INSERT INTO hourly_zero_hours (employee_id, production_date, hour_slot, reason) VALUES (?, ?, ?, ?)').run(employeeId, productionDate, hourSlot, zeroReason);
  const q = new URLSearchParams({ production_date: productionDate, employee_id: String(employeeId), notice: `Hora ${hourSlot} registrada como hora zero para ${employee.full_name}. Motivo: ${zeroReason}.` });
  redirect(res, `/productions/hourly?${q.toString()}`);
}

function handleDeleteZeroHour(id, form, res, role) {
  const row = db.prepare('SELECT * FROM hourly_zero_hours WHERE id = ? AND is_reversed = 0').get(Number(id));
  const backUrl = row ? `/productions/hourly?production_date=${encodeURIComponent(row.production_date)}${form.back_employee ? `&employee_id=${encodeURIComponent(form.back_employee)}` : ''}` : '/productions/hourly';
  if (!row) return redirect(res, buildRedirectWithFlash(backUrl, 'Hora zero não encontrada.', true));
  db.prepare('UPDATE hourly_zero_hours SET is_reversed = 1 WHERE id = ?').run(row.id);
  redirect(res, buildRedirectWithFlash(backUrl, `Hora zero das ${row.hour_slot} excluída.`));
}

function handleCreateHourlyProduction(form, res) {
  if (form.zero_hour === '1') return handleCreateZeroHour(form, res);
  const productionDate = String(form.production_date || today()).trim() || today();
  const hourSlot = normalizeHourSlotInput(form.hour_slot);
  const employeeId = Number(form.employee_id || 0);
  const producedQuantity = Number(form.produced_quantity || 0);
  const opNumber = normalizeOpNumberInput(form.op_number || '');
  const notes = String(form.notes || '').trim() || null;
  const redirectQuery = new URLSearchParams({ production_date: productionDate });
  if (employeeId) redirectQuery.set('employee_id', String(employeeId));

  if (!employeeId || !hourSlot || !opNumber || !producedQuantity || producedQuantity <= 0) {
    return sendHtml(res, renderHourlyProductionPage(form, 'Preencha costureira, hora, OP e quantidade.', '', getRequestRole()), 422);
  }
  const dateError = checkLaunchDate(productionDate, getRequestRole());
  if (dateError) return sendHtml(res, renderHourlyProductionPage(form, dateError, '', getRequestRole()), 422);

  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  const op = getOpByNumber(opNumber);
  if (!employee || !op) {
    return sendHtml(res, renderHourlyProductionPage(form, 'Costureira ou OP não encontrada.'), 404);
  }
  if (getCurrentCellTransfer(op.id)) {
    return sendHtml(res, renderHourlyProductionPage(form, 'Esta OP está em célula. Faça o retorno antes do lançamento por hora.'), 422);
  }

  const existingHour = db.prepare(`
    SELECT hp.id, o.op_number
    FROM hourly_productions hp
    JOIN ops o ON o.id = hp.op_id
    WHERE hp.employee_id = ?
      AND hp.production_date = ?
      AND hp.hour_slot = ?
      AND hp.is_reversed = 0
    LIMIT 1
  `).get(employeeId, productionDate, hourSlot);
  if (existingHour) {
    return sendHtml(res, renderHourlyProductionPage(form, `A hora ${hourSlot} já foi lançada para essa costureira na OP ${existingHour.op_number}.`), 422);
  }
  if (db.prepare('SELECT 1 FROM hourly_zero_hours WHERE employee_id = ? AND production_date = ? AND hour_slot = ? AND is_reversed = 0').get(employeeId, productionDate, hourSlot)) {
    return sendHtml(res, renderHourlyProductionPage(form, `A hora ${hourSlot} está marcada como hora zero. Exclua a hora zero na lista antes de lançar peças nela.`), 422);
  }

  const totals = db.prepare(`
    SELECT
      COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0), 0) AS produced_total_daily,
      COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS problem_total,
      COALESCE((SELECT SUM(produced_quantity) FROM hourly_productions WHERE op_id = ? AND is_reversed = 0 AND validated_daily_production_id IS NULL), 0) AS produced_total_hourly_pending
  `).get(op.id, op.id, op.id);
  const futureTotal = Number(totals.produced_total_daily || 0) + Number(totals.problem_total || 0) + Number(totals.produced_total_hourly_pending || 0) + producedQuantity;
  if (futureTotal > Number(op.total_pieces || 0)) {
    const excess = futureTotal - Number(op.total_pieces || 0);
    return sendHtml(res, renderHourlyProductionPage(form, `Lançamento bloqueado: a OP ultrapassaria o limite em ${excess} peça(s).`), 422);
  }

  const metrics = calculateProductionLaunchMetrics(op, producedQuantity, round3(Number(op.minutes_f21 || 0)), productionDate);
  db.prepare(`
    INSERT INTO hourly_productions (
      op_id, employee_id, production_date, hour_slot, produced_quantity, used_minutes_f21,
      normal_minutes, extra_minutes, produced_minutes, extra_time_id,
      extra_reason_snapshot, extra_description_snapshot, extra_effective_date_snapshot,
      extra_minutes_per_piece_snapshot, notes, created_by_user_id, updated_at, counts_for_prize
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, CURRENT_TIMESTAMP, ?)
  `).run(
    op.id,
    employeeId,
    productionDate,
    hourSlot,
    producedQuantity,
    metrics.launchF21,
    metrics.normalMinutes,
    metrics.extraMinutes,
    metrics.totalMinutes,
    metrics.extraSnapshot.extra_time_id,
    metrics.extraSnapshot.extra_reason_snapshot,
    metrics.extraSnapshot.extra_description_snapshot,
    metrics.extraSnapshot.extra_effective_date_snapshot,
    metrics.extraSnapshot.extra_minutes_per_piece_snapshot,
    notes,
    resolveCountsForPrize(form, employee, productionDate, hourSlot)
  );

  redirectQuery.set('notice', `Lançamento da hora ${hourSlot} salvo para ${employee.full_name}.`);
  redirect(res, `/productions/hourly?${redirectQuery.toString()}`);
}

// Estorna a validação do dia: tira do diário oficial o que veio dos lançamentos por hora
// e volta esses lançamentos para "pendente" (podem ser corrigidos e validados de novo).
function handleUnvalidateHourlyProductionDay(form, res, role) {
  const productionDate = String(form.production_date || '').trim();
  const back = (msg, isError) => redirect(res, buildRedirectWithFlash(`/productions/hourly?production_date=${encodeURIComponent(productionDate)}`, msg, isError));
  if (!isAdminRole(role)) return back('Somente o administrador pode estornar a validação.', true);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(productionDate)) return back('Informe a data.', true);
  const reason = normalizeReason(form.reason) || 'Estorno da validação do lançamento por hora';
  const rows = db.prepare(`
    SELECT * FROM hourly_productions
    WHERE production_date = ? AND is_reversed = 0 AND is_validated = 1 AND validated_daily_production_id IS NOT NULL
    ORDER BY validated_daily_production_id, id`).all(productionDate);
  if (!rows.length) return back('Nenhum lançamento por hora validado neste dia.', true);
  const byDaily = new Map();
  for (const row of rows) {
    if (!byDaily.has(row.validated_daily_production_id)) byDaily.set(row.validated_daily_production_id, []);
    byDaily.get(row.validated_daily_production_id).push(row);
  }
  const ops = new Set();
  let removedDaily = 0;
  try {
    db.exec('BEGIN');
    for (const [dailyId, list] of byDaily) {
      const daily = db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(dailyId);
      const sum = list.reduce((acc, r) => ({
        qty: acc.qty + Number(r.produced_quantity || 0),
        normal: acc.normal + Number(r.normal_minutes || 0),
        extra: acc.extra + Number(r.extra_minutes || 0),
        total: acc.total + Number(r.produced_minutes || 0)
      }), { qty: 0, normal: 0, extra: 0, total: 0 });
      if (daily && !daily.is_reversed) {
        const remainingQty = Number(daily.produced_quantity || 0) - sum.qty;
        if (remainingQty <= 0) {
          db.prepare('UPDATE op_daily_productions SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = ? WHERE id = ?').run(reason, daily.id);
          removedDaily += 1;
        } else {
          // O lançamento diário tinha também peças lançadas direto (lançamento rápido): só tira a parte do lançamento por hora
          db.prepare(`
            UPDATE op_daily_productions
            SET produced_quantity = ?, normal_minutes = ROUND(MAX(COALESCE(normal_minutes, 0) - ?, 0), 3),
                extra_minutes = ROUND(MAX(COALESCE(extra_minutes, 0) - ?, 0), 3), produced_minutes = ROUND(MAX(COALESCE(produced_minutes, 0) - ?, 0), 3)
            WHERE id = ?`).run(remainingQty, sum.normal, sum.extra, sum.total, daily.id);
        }
        logAuditEntry('production', daily.id, 'estorno', reason, daily, db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(daily.id));
        ops.add(daily.op_id);
      }
      db.prepare(`UPDATE hourly_productions SET is_validated = 0, validated_at = NULL, validated_daily_production_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE id IN (${list.map(() => '?').join(',')})`).run(...list.map(r => r.id));
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    return back(`Nada foi alterado: ${error.message}`, true);
  }
  ops.forEach(opId => recalculateOpStatus(opId));
  back(`Validação de ${formatDatePtBr(productionDate)} estornada: ${rows.length} lançamento(s) por hora voltaram para pendente (${removedDaily} lançamento(s) diário(s) estornado(s)). Corrija o que precisar e valide o dia de novo.`);
}

// Corrige a quantidade de um lançamento por hora (0 = exclui). Se já validado, ajusta o diário junto (só administrador).
function handleFixHourlyProduction(id, form, res, role) {
  const row = db.prepare('SELECT * FROM hourly_productions WHERE id = ? AND is_reversed = 0').get(Number(id));
  const backUrl = row ? `/productions/hourly?production_date=${encodeURIComponent(row.production_date)}${form.back_employee ? `&employee_id=${encodeURIComponent(form.back_employee)}` : ''}` : '/productions/hourly';
  const back = (msg, isError) => redirect(res, buildRedirectWithFlash(backUrl, msg, isError));
  if (!row) return back('Lançamento não encontrado.', true);
  if (row.is_validated && !isAdminRole(role)) return back('Lançamento já validado: só o administrador pode corrigir.', true);
  const newQty = Number(form.produced_quantity);
  if (!Number.isInteger(newQty) || newQty < 0) return back('Informe a quantidade correta (0 para excluir).', true);
  const oldQty = Number(row.produced_quantity || 0);
  if (newQty === oldQty) return back('Quantidade igual à lançada; nada mudou.');
  const op = db.prepare('SELECT * FROM ops WHERE id = ?').get(row.op_id);
  if (newQty > oldQty) {
    const used = db.prepare(`
      SELECT
        COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0), 0)
        + COALESCE((SELECT SUM(produced_quantity) FROM hourly_productions WHERE op_id = ? AND is_reversed = 0 AND is_validated = 0), 0)
        + COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS n`).get(row.op_id, row.op_id, row.op_id).n;
    if (Number(used) + (newQty - oldQty) > Number(op.total_pieces || 0)) return back(`Correção bloqueada: a OP ${op.op_number} passaria do total de peças.`, true);
  }
  const ratio = oldQty > 0 ? newQty / oldQty : 0;
  const next = {
    normal: round3(Number(row.normal_minutes || 0) * ratio),
    extra: round3(Number(row.extra_minutes || 0) * ratio),
    total: round3(Number(row.produced_minutes || 0) * ratio)
  };
  const delta = { qty: newQty - oldQty, normal: next.normal - Number(row.normal_minutes || 0), extra: next.extra - Number(row.extra_minutes || 0), total: next.total - Number(row.produced_minutes || 0) };
  const reason = `Correção do lançamento por hora ${row.hour_slot}: ${oldQty} → ${newQty} peça(s)`;
  try {
    db.exec('BEGIN');
    if (newQty === 0) {
      db.prepare('UPDATE hourly_productions SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(reason, row.id);
    } else {
      db.prepare('UPDATE hourly_productions SET produced_quantity = ?, normal_minutes = ?, extra_minutes = ?, produced_minutes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(newQty, next.normal, next.extra, next.total, row.id);
    }
    if (row.is_validated && row.validated_daily_production_id) {
      const daily = db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(row.validated_daily_production_id);
      if (daily && !daily.is_reversed) {
        const dailyQty = Number(daily.produced_quantity || 0) + delta.qty;
        if (dailyQty <= 0) {
          db.prepare('UPDATE op_daily_productions SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = ? WHERE id = ?').run(reason, daily.id);
        } else {
          db.prepare(`UPDATE op_daily_productions SET produced_quantity = ?, normal_minutes = ROUND(MAX(COALESCE(normal_minutes, 0) + ?, 0), 3),
            extra_minutes = ROUND(MAX(COALESCE(extra_minutes, 0) + ?, 0), 3), produced_minutes = ROUND(MAX(COALESCE(produced_minutes, 0) + ?, 0), 3) WHERE id = ?`)
            .run(dailyQty, delta.normal, delta.extra, delta.total, daily.id);
        }
        logAuditEntry('production', daily.id, 'correcao', reason, daily, db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(daily.id));
      }
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    return back(`Nada foi alterado: ${error.message}`, true);
  }
  recalculateOpStatus(row.op_id);
  back(newQty === 0 ? `Lançamento das ${row.hour_slot} excluído.` : `Lançamento das ${row.hour_slot} corrigido: ${oldQty} → ${newQty} peça(s) (${fmtNum(next.total, 2)} min)${row.is_validated ? '. O diário validado também foi ajustado.' : '.'}`);
}

function handleValidateHourlyProductionDay(form, res) {
  const productionDate = String(form.production_date || today()).trim() || today();
  const pendingRows = db.prepare(`
    SELECT *
    FROM hourly_productions
    WHERE production_date = ?
      AND is_reversed = 0
      AND is_validated = 0
    ORDER BY employee_id, op_id, hour_slot, id
  `).all(productionDate);
  if (!pendingRows.length) {
    return redirect(res, buildRedirectWithFlash(`/productions/hourly?production_date=${encodeURIComponent(productionDate)}`, 'Nenhum lançamento por hora pendente para validar neste dia.'));
  }

  const grouped = new Map();
  for (const row of pendingRows) {
    const countsForPrize = Number(row.counts_for_prize ?? 1) === 1 ? 1 : 0;
    const key = `${row.employee_id}|${row.op_id}|${countsForPrize}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        employee_id: row.employee_id,
        op_id: row.op_id,
        counts_for_prize: countsForPrize,
        production_date: row.production_date,
        produced_quantity: 0,
        used_minutes_f21: Number(row.used_minutes_f21 || 0),
        normal_minutes: 0,
        extra_minutes: 0,
        produced_minutes: 0,
        extra_time_id: row.extra_time_id || null,
        extra_reason_snapshot: row.extra_reason_snapshot || null,
        extra_description_snapshot: row.extra_description_snapshot || null,
        extra_effective_date_snapshot: row.extra_effective_date_snapshot || null,
        extra_minutes_per_piece_snapshot: row.extra_minutes_per_piece_snapshot || null,
        row_ids: []
      });
    }
    const item = grouped.get(key);
    item.produced_quantity += Number(row.produced_quantity || 0);
    item.normal_minutes += Number(row.normal_minutes || 0);
    item.extra_minutes += Number(row.extra_minutes || 0);
    item.produced_minutes += Number(row.produced_minutes || 0);
    item.row_ids.push(row.id);
  }

  try {
    db.exec('BEGIN');
    for (const item of grouped.values()) {
      const existing = db.prepare(`
        SELECT *
        FROM op_daily_productions
        WHERE op_id = ? AND employee_id = ? AND production_date = ? AND is_reversed = 0
          AND COALESCE(counts_for_prize, 1) = ?
        LIMIT 1
      `).get(item.op_id, item.employee_id, item.production_date, item.counts_for_prize);
      let dailyId = existing?.id || null;
      if (existing) {
        db.prepare(`
          UPDATE op_daily_productions
          SET produced_quantity = produced_quantity + ?,
              normal_minutes = ROUND(COALESCE(normal_minutes, 0) + ?, 3),
              extra_minutes = ROUND(COALESCE(extra_minutes, 0) + ?, 3),
              produced_minutes = ROUND(COALESCE(produced_minutes, 0) + ?, 3),
              used_minutes_f21 = ?,
              extra_time_id = COALESCE(?, extra_time_id),
              extra_reason_snapshot = COALESCE(?, extra_reason_snapshot),
              extra_description_snapshot = COALESCE(?, extra_description_snapshot),
              extra_effective_date_snapshot = COALESCE(?, extra_effective_date_snapshot),
              extra_minutes_per_piece_snapshot = COALESCE(?, extra_minutes_per_piece_snapshot)
          WHERE id = ?
        `).run(
          item.produced_quantity,
          round3(item.normal_minutes),
          round3(item.extra_minutes),
          round3(item.produced_minutes),
          item.used_minutes_f21,
          item.extra_time_id,
          item.extra_reason_snapshot,
          item.extra_description_snapshot,
          item.extra_effective_date_snapshot,
          item.extra_minutes_per_piece_snapshot,
          existing.id
        );
      } else {
        const result = db.prepare(`
          INSERT INTO op_daily_productions (
            op_id, employee_id, production_date, produced_quantity, used_minutes_f21,
            normal_minutes, extra_minutes, produced_minutes, extra_time_id,
            extra_reason_snapshot, extra_description_snapshot, extra_effective_date_snapshot,
            extra_minutes_per_piece_snapshot, counts_for_prize
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          item.op_id,
          item.employee_id,
          item.production_date,
          item.produced_quantity,
          item.used_minutes_f21,
          round3(item.normal_minutes),
          round3(item.extra_minutes),
          round3(item.produced_minutes),
          item.extra_time_id,
          item.extra_reason_snapshot,
          item.extra_description_snapshot,
          item.extra_effective_date_snapshot,
          item.extra_minutes_per_piece_snapshot,
          item.counts_for_prize
        );
        dailyId = Number(result.lastInsertRowid);
      }

      db.prepare(`
        UPDATE hourly_productions
        SET is_validated = 1,
            validated_at = CURRENT_TIMESTAMP,
            validated_daily_production_id = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id IN (${item.row_ids.map(() => '?').join(',')})
      `).run(dailyId, ...item.row_ids);
      recalculateOpStatus(item.op_id);
    }
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch (_error) {}
    return redirect(res, buildRedirectWithFlash(`/productions/hourly?production_date=${encodeURIComponent(productionDate)}`, `Erro ao validar o dia: ${error.message}`, true));
  }

  redirect(res, buildRedirectWithFlash(`/productions/hourly?production_date=${encodeURIComponent(productionDate)}`, 'Dia validado com sucesso. Os lançamentos por hora foram consolidados no diário.'));
}

function renderHourlyProductionPage(values = {}, error = '', notice = '', role = getRequestRole() || 'adm') {
  const employees = db.prepare(`
    SELECT id, registration_code, full_name, start_date, termination_date
    FROM employees
    WHERE is_active = 1
      AND COALESCE(termination_date, '9999-12-31') >= ?
      AND UPPER(TRIM(COALESCE(job_role, ''))) LIKE 'COSTUREIRA%'
    ORDER BY full_name COLLATE NOCASE
  `).all(values.production_date || today());
  const selectedEmployeeId = String(values.employee_id || '');
  const productionDate = values.production_date || today();
  const hourSlot = normalizeHourSlotInput(values.hour_slot || '') || currentHourSlot();
  const selectedEmployee = employees.find(item => String(item.id) === selectedEmployeeId) || null;
  const lastHourlyOp = selectedEmployee ? getLastHourlyOpForEmployee(selectedEmployee.id, productionDate) : null;
  const suggestedOpNumber = normalizeOpNumberInput(values.op_number || '') || lastHourlyOp?.op_number || '';
  const quickPreview = getOpQuickPreview(suggestedOpNumber || '');
  const summary = getHourlyValidationSummary(productionDate);
  const recent = getHourlyProductionRows(productionDate, selectedEmployeeId || '');
  const selectedEmployeeLabel = selectedEmployee ? `${selectedEmployee.registration_code} - ${selectedEmployee.full_name}` : String(values.employee_label || '').trim();
  const employeeSuggestions = employees.map(emp => ({
    id: String(emp.id),
    label: `${emp.registration_code} - ${emp.full_name}`,
    full_name: emp.full_name,
    registration_code: emp.registration_code
  }));
  const totalSelectedMinutes = round3(recent.reduce((sum, item) => sum + Number(item.produced_minutes || 0), 0));
  const totalSelectedQty = recent.reduce((sum, item) => sum + Number(item.produced_quantity || 0), 0);
  const selectedEmployeeDaySummary = selectedEmployee ? getHourlyEmployeeDaySummary(selectedEmployee.id, productionDate, hourSlot) : null;

  const content = `
    <section class="page-header"><div><h2>Lançamento por hora</h2><p>Nova origem operacional do lançamento: uma costureira, uma OP, uma hora cheia por registro.</p></div></section>

    <section class="panel quick-launch-panel">
      <div class="quick-launch-header">
        <div>
          <h3>Digitação rápida por costureira</h3>
          <p>Selecione a costureira, confirme data/hora atual, informe OP e quantidade, e salve rápido.</p>
        </div>
        <a class="btn secondary" href="/productions/new">Abrir lançamento diário antigo</a>
      </div>
      <form class="form-grid quick-launch-form" method="post" action="/productions/hourly" data-hourly-launch>
        <label>Costureira
          <input name="employee_label" list="hourly-employee-suggestions" required autocomplete="off" value="${escapeHtml(selectedEmployeeLabel)}" placeholder="Comece a digitar o nome da costureira" data-hourly-field="employee-label" />
          <datalist id="hourly-employee-suggestions">
            ${employeeSuggestions.map(emp => `<option value="${escapeHtml(emp.label)}"></option>`).join('')}
          </datalist>
          <input type="hidden" name="employee_id" value="${escapeHtml(selectedEmployeeId)}" data-hourly-field="employee-id" />
        </label>
        <label>Data do lançamento
          <input type="date" name="production_date" value="${escapeHtml(productionDate)}" ${launchDateAttrs(role)} data-hourly-field="date" onchange="window.location.href='/productions/hourly?employee_id=' + encodeURIComponent(document.querySelector('[data-hourly-field=employee-id]')?.value || '') + '&production_date=' + encodeURIComponent(this.value)" />
          ${launchDateHint(role)}
        </label>
        <label>Hora atual
          <input name="hour_slot" value="${escapeHtml(hourSlot)}" data-hourly-field="hour" placeholder="Ex.: 15:00" />
        </label>
        <label>OP
          <span class="scan-input"><input name="op_number" required autocomplete="off" placeholder="Bipe a etiqueta ou digite a OP" value="${escapeHtml(suggestedOpNumber)}" data-hourly-field="op" data-scan-input /><button class="btn secondary scan-btn" type="button" data-scan-camera title="Ler com a câmera">📷</button></span>
        </label>
        <label>Quantidade
          <input type="number" inputmode="numeric" min="1" name="produced_quantity" required value="${escapeHtml(values.produced_quantity || '')}" data-hourly-field="quantity" />
        </label>
        <label>Observação
          <input name="notes" value="${escapeHtml(values.notes || '')}" placeholder="Opcional" />
        </label>
        <div class="full">${renderPrizeFlagField(values)}</div>
        <div class="full zero-box" data-zero-box hidden>
          <input type="hidden" name="zero_hour" value="" data-zero-flag />
          <label>Motivo da hora zero *
            <input name="zero_reason" list="zero-reasons" autocomplete="off" placeholder="Ex.: máquina parada — Enter salva" data-zero-reason />
            <datalist id="zero-reasons">
              ${ZERO_HOUR_REASONS.map(r => `<option value="${r}"></option>`).join('')}
            </datalist>
          </label>
          <div class="actions"><button class="btn" type="button" data-zero-save>Salvar hora zero</button><button class="btn secondary" type="button" data-zero-cancel>Cancelar</button></div>
        </div>
        <div class="full actions">
          <button class="btn" type="submit">Salvar rápido</button>
          <button class="btn secondary" type="button" data-zero-open title="A costureira não produziu peça nesta hora">⓪ Hora zero</button>
          <button class="btn secondary" type="button" onclick="window.location.href='/productions/hourly?employee_id=' + encodeURIComponent(document.querySelector('[data-hourly-field=employee-id]').value) + '&production_date=' + encodeURIComponent(document.querySelector('[data-hourly-field=date]').value)">Atualizar tela</button>
        </div>
      </form>
      ${renderPrizeFlagScript({ formSelector: '[data-hourly-launch]', employeeFieldSelector: '[name=employee_id]', dateFieldSelector: '[name=production_date]', hourFieldSelector: '[name=hour_slot]' })}
      <script>
        (() => {
          const form = document.querySelector('[data-hourly-launch]');
          if (!form) return;
          const box = form.querySelector('[data-zero-box]');
          const reason = form.querySelector('[data-zero-reason]');
          const flag = form.querySelector('[data-zero-flag]');
          const open = () => { box.hidden = false; reason.focus(); reason.select(); };
          const close = () => { box.hidden = true; flag.value = ''; };
          const save = () => {
            const text = reason.value.trim();
            if (!form.employee_id.value) { alert('Selecione a costureira.'); return; }
            if (!form.hour_slot.value.trim()) { alert('Informe a hora.'); return; }
            if (!text) { reason.focus(); reason.classList.add('is-invalid'); return; }
            flag.value = '1';
            form.noValidate = true;
            form.submit();
          };
          form.querySelector('[data-zero-open]').addEventListener('click', open);
          form.querySelector('[data-zero-cancel]').addEventListener('click', close);
          form.querySelector('[data-zero-save]').addEventListener('click', save);
          reason.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); save(); } if (e.key === 'Escape') close(); });
          reason.addEventListener('input', () => reason.classList.remove('is-invalid'));
        })();
      </script>
      ${renderScannerScript()}
      ${quickPreview ? `
        <div class="quick-op-preview ${quickPreview.is_in_cell ? 'is-blocked' : (quickPreview.remaining_quantity <= 0 ? 'is-finished' : '')}">
          <strong>${escapeHtml(quickPreview.op_number)} · ${escapeHtml(quickPreview.product_name)}</strong>
          <span>Saldo atual: ${quickPreview.remaining_quantity} peça(s) · Produzido: ${quickPreview.produced_quantity}/${quickPreview.total_pieces}</span>
          <span>Min. base hora: ${fmtNum(quickPreview.effective_launch_minutes, 3)} · Normal/pç: ${fmtNum(quickPreview.launch_normal_minutes_per_piece, 3)} · Extra/pç: ${fmtNum(quickPreview.extra_minutes_per_piece, 3)} · Total/pç: ${fmtNum(quickPreview.total_launch_minutes_per_piece, 3)} · Status: ${escapeHtml(quickPreview.status_color)}</span>
          ${quickPreview.extra_reason ? `<span>Tempo extra ativo: ${quickPreview.extra_reason}</span>` : ''}
          ${quickPreview.is_in_cell ? `<span><strong>Bloqueada para lançamento.</strong> Está na célula ${escapeHtml(quickPreview.active_cell_name || '-')}.</span>` : ''}
        </div>
      ` : values.op_number ? '<div class="quick-op-preview is-missing"><strong>OP não encontrada.</strong><span>Confira o número digitado antes de salvar.</span></div>' : ''}
      ${selectedEmployee ? `<p class="hint">Costureira selecionada: <strong>${escapeHtml(selectedEmployee.full_name)}</strong>. Total do dia nessa seleção: <strong>${totalSelectedQty} peça(s)</strong> · <strong>${fmtNum(totalSelectedMinutes, 3)} min</strong>.${lastHourlyOp ? ` Última OP sugerida: <strong>${escapeHtml(lastHourlyOp.op_number)}</strong>.` : ''}</p>` : '<p class="hint">Selecione a costureira para acompanhar os lançamentos dela no dia.</p>'}
      ${selectedEmployeeDaySummary ? `<div class="shipment-summary-grid section-gap"><article class="mini-card"><span>Peças do dia</span><strong>${selectedEmployeeDaySummary.totalQuantity}</strong></article><article class="mini-card"><span>Minutos do dia</span><strong>${fmtNum(selectedEmployeeDaySummary.totalMinutes, 3)}</strong></article><article class="mini-card"><span>Horas lançadas</span><strong>${selectedEmployeeDaySummary.launchedHours}${selectedEmployeeDaySummary.zeroHours ? ` <small class="hint">(${selectedEmployeeDaySummary.zeroHours} zero)</small>` : ''}</strong></article><article class="mini-card"><span>% do dia (base ${fmtNum(baseMinutesDay(), 0)} min)</span><strong>${fmtNum(selectedEmployeeDaySummary.dayEfficiencyPercent, 2)}%</strong></article></div>` : ''}
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Lançamentos do dia</h3><span class="hint">${formatDatePtBr(productionDate)} · ${selectedEmployee ? escapeHtml(selectedEmployee.full_name) : 'todas as costureiras com filtro selecionado'}</span></div>
      <table>
        <thead><tr><th>Hora</th><th>OP</th><th>Produto</th><th>Costureira</th><th>Qtd</th><th>Normal</th><th>Extra</th><th>Total</th><th>% hora</th><th>Status</th><th>Corrigir</th></tr></thead>
        <tbody>
          ${getZeroHours(productionDate, selectedEmployeeId || '').map(z => `<tr class="zero-hour-row"><td>${escapeHtml(z.hour_slot)}</td><td>—</td><td><span class="status-pill pending">Hora zero</span></td><td>${escapeHtml(z.registration_code)} - ${escapeHtml(z.full_name)}</td><td>0</td><td>0</td><td>0</td><td>0</td><td>0%</td><td>${escapeHtml(z.reason || 'Sem produção')}</td><td><form class="hourly-fix" method="post" action="/productions/hourly/zero/${z.id}/delete" onsubmit="return confirm('Excluir a hora zero das ${escapeHtml(z.hour_slot)}?')"><input type="hidden" name="back_employee" value="${escapeHtml(selectedEmployeeId || '')}" /><button class="btn secondary" type="submit" title="Excluir hora zero">Excluir</button></form></td></tr>`).join('')}
          ${recent.map(item => { const canFix = !item.is_validated || isAdminRole(role); return `<tr><td>${escapeHtml(item.hour_slot)}</td><td>${escapeHtml(item.op_number)}</td><td>${escapeHtml(item.product_name)}</td><td>${escapeHtml(item.registration_code)} - ${escapeHtml(item.full_name)}</td><td>${item.produced_quantity}</td><td>${fmtNum(round3(item.normal_minutes || 0), 3)}</td><td>${fmtNum(round3(item.extra_minutes || 0), 3)}</td><td>${fmtNum(round3(item.produced_minutes || 0), 3)}</td><td>${fmtNum(Number(item.hour_efficiency_percent || 0), 2)}%</td><td>${item.is_validated ? `<span class="status-pill ok">Validado</span>` : `<span class="status-pill pending">Pendente</span>`}</td><td>${canFix ? `<form class="hourly-fix" method="post" action="/productions/hourly/${item.id}/fix" onsubmit="return confirm('Corrigir ${escapeHtml(item.hour_slot)} de ${escapeHtml(String(item.full_name).replace(/'/g, ''))} de ${item.produced_quantity} para ' + this.produced_quantity.value + ' peça(s)?' + (this.produced_quantity.value === '0' ? ' (0 = excluir o lançamento)' : ''))"><input type="hidden" name="back_employee" value="${escapeHtml(selectedEmployeeId || '')}" /><input type="number" name="produced_quantity" min="0" step="1" required value="${item.produced_quantity}" aria-label="Quantidade correta" /><button class="btn secondary" type="submit" title="Salvar correção">✔</button></form>` : '<span class="hint">só adm</span>'}</td></tr>`; }).join('') || (getZeroHours(productionDate, selectedEmployeeId || '').length ? '' : '<tr><td colspan="11">Nenhum lançamento por hora gravado para esse filtro.</td></tr>')}
        </tbody>
      </table>
    </section>

    <section class="panel section-gap">
      <div class="panel-header"><h3>Conferência e validação do dia</h3><span class="hint">Consolida os lançamentos horários no diário oficial.</span></div>
      <form class="inline-form" method="post" action="/productions/hourly/validate">
        <label>Data para validar<input type="date" name="production_date" value="${escapeHtml(productionDate)}" /></label>
        <button class="btn" type="submit">Validar dia</button>
      </form>
      ${isAdminRole(role) && summary.some(item => Number(item.validated_rows) > 0) ? `
      <details class="unvalidate-box">
        <summary>Estornar a validação de ${formatDatePtBr(productionDate)}</summary>
        <form class="inline-form" method="post" action="/productions/hourly/unvalidate" onsubmit="return confirm('Estornar a validação de ${formatDatePtBr(productionDate)}? Os lançamentos por hora voltam para pendente e saem do diário.')">
          <input type="hidden" name="production_date" value="${escapeHtml(productionDate)}" />
          <label>Motivo<input name="reason" required placeholder="Ex.: validação feita com lançamento errado" /></label>
          <button class="btn btn-danger-soft" type="submit">Estornar validação</button>
        </form>
        <p class="hint">Os lançamentos por hora do dia voltam para pendente e saem do lançamento diário. Peças lançadas pelo lançamento rápido não são afetadas. Depois de corrigir, valide o dia de novo.</p>
      </details>` : ''}
      <table>
        <thead><tr><th>Registro</th><th>Costureira</th><th>Horas lançadas</th><th>Qtd total</th><th>Min. total</th><th>% do dia</th><th>Pendentes</th><th>Validados</th></tr></thead>
        <tbody>
          ${summary.map(item => `<tr><td>${escapeHtml(item.registration_code)}</td><td>${escapeHtml(item.full_name)}</td><td>${item.launched_hours}</td><td>${item.total_quantity}</td><td>${fmtNum(round3(item.total_minutes || 0), 3)}</td><td>${fmtNum(Number(item.day_efficiency_percent || 0), 2)}%</td><td>${item.pending_rows}</td><td>${item.validated_rows}</td></tr>`).join('') || '<tr><td colspan="8">Nenhum lançamento por hora neste dia.</td></tr>'}
        </tbody>
      </table>
      <p class="hint">Após validar, os registros por hora são consolidados no lançamento diário oficial, preservando compatibilidade com resultado, prêmio e fechamento.</p>
    </section>

    <script>
      (() => {
        const form = document.querySelector('[data-hourly-launch]');
        if (!form) return;
        const employeeLabel = form.querySelector('[data-hourly-field="employee-label"]');
        const employeeId = form.querySelector('[data-hourly-field="employee-id"]');
        const hourField = form.querySelector('[data-hourly-field="hour"]');
        const op = form.querySelector('[data-hourly-field="op"]');
        const quantity = form.querySelector('[data-hourly-field="quantity"]');
        const normalizeHourField = () => {
          if (!hourField) return;
          const raw = String(hourField.value || '').trim();
          const compact = raw.replace(/\D/g, '');
          let normalized = '';
          if (/^\d{3,4}$/.test(compact)) {
            const hour = Number(compact.slice(0, compact.length - 2));
            if (Number.isInteger(hour) && hour >= 0 && hour <= 23) normalized = String(hour).padStart(2, '0') + ':00';
          } else {
            const match = raw.match(/^(\d{1,2})(?::(\d{1,2}))?$/);
            if (match) {
              const hour = Number(match[1]);
              if (Number.isInteger(hour) && hour >= 0 && hour <= 23) normalized = String(hour).padStart(2, '0') + ':00';
            }
          }
          if (normalized) hourField.value = normalized;
        };
        const normalizeOpField = () => {
          if (!op) return;
          const raw = String(op.value || '').trim().toUpperCase();
          if (/^\d{7}$/.test(raw)) op.value = raw + '-001';
        };
        const employeeOptions = ${JSON.stringify(employeeSuggestions)};
        const syncEmployeeSelection = () => {
          const typed = String(employeeLabel?.value || '').trim().toLowerCase();
          const match = employeeOptions.find(item => item.label.toLowerCase() === typed);
          employeeId.value = match ? match.id : '';
        };
        const applyLocalHourSlot = () => {
          if (!hourField) return;
          const now = new Date();
          const localHour = String(now.getHours()).padStart(2, '0') + ':00';
          hourField.value = localHour;
        };
        if (employeeLabel) {
          employeeLabel.addEventListener('input', syncEmployeeSelection);
          employeeLabel.addEventListener('change', syncEmployeeSelection);
          employeeLabel.addEventListener('blur', syncEmployeeSelection);
        }
        if (hourField) {
          if (!hourField.value) applyLocalHourSlot();
          hourField.addEventListener('blur', normalizeHourField);
          hourField.addEventListener('change', normalizeHourField);
        }
        if (op) {
          op.addEventListener('blur', normalizeOpField);
          op.addEventListener('change', normalizeOpField);
          const goQuantity = () => { normalizeOpField(); if (quantity) { quantity.focus(); quantity.select(); } };
          op.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); goQuantity(); } });
          op.addEventListener('scan', goQuantity);
        }
        syncEmployeeSelection();
        const firstTarget = employeeLabel && !employeeLabel.value ? employeeLabel : op || quantity || employeeLabel;
        if (firstTarget) firstTarget.focus();
        if (op && op.value) op.select();
      })();
    </script>
  `;

  return pageLayout({ title: 'Lançamento por hora', content, error, notice, role });
}

function renderProductionForm(values = {}, error = '', notice = '', role = getRequestRole() || 'adm') {
  const employees = db.prepare('SELECT id, registration_code, full_name, start_date, termination_date FROM employees ORDER BY full_name').all();
  const allOps = getOpList({});
  const blockedCellOps = allOps.filter(op => op.status_color === 'rosa');
  const ops = allOps.filter(op => op.status_color !== 'rosa');
  const recent = db.prepare(`
    SELECT p.production_date, p.produced_quantity, p.normal_minutes, p.extra_minutes, p.produced_minutes, o.op_number, e.registration_code, e.full_name
    FROM op_daily_productions p
    JOIN ops o ON o.id = p.op_id
    JOIN employees e ON e.id = p.employee_id
    ORDER BY p.created_at DESC
    LIMIT 20
  `).all();

  // Padrão: lançamento rápido (OP bipada/digitada). Lista completa só com ?mode=lista.
  const mode = values.mode === 'lista' || values.mode === 'default' ? 'default' : 'quick';
  const keepEmployee = values.keep_employee === '1';
  const selectedEmployeeId = String(values.employee_id || '');
  const selectedDate = values.production_date || today();
  const quickPreview = getOpQuickPreview(values.op_number || '');
  const selectedLaunchMinutes = values.used_minutes_f21 || (quickPreview ? quickPreview.minutes_f21.toFixed(3) : '');

  const quickContent = `
    <section class="panel quick-launch-panel">
      <div class="quick-launch-header">
        <div>
          <h3>Lançamento rápido</h3>
          <p>Bipe a etiqueta (leitor ou câmera) ou digite a OP. Enter avança para a quantidade.</p>
        </div>
        <a class="btn secondary" href="/productions/new?mode=lista">Modo lista</a>
      </div>
      <form class="form-grid quick-launch-form" method="post" action="/productions" data-quick-launch>
        <input type="hidden" name="mode" value="quick" />
        <label>Colaborador
          <select name="employee_id" required data-quick-field="employee">
            <option value="">Selecione</option>
            ${employees.map(emp => `<option value="${emp.id}" ${selectedEmployeeId === String(emp.id) ? 'selected' : ''}>${escapeHtml(emp.registration_code)} - ${escapeHtml(emp.full_name)}${emp.start_date || emp.termination_date ? ` (${emp.start_date || 'sem início'} até ${emp.termination_date || 'atual'})` : ''}</option>`).join('')}
          </select>
        </label>
        <label>Data
          <input type="date" name="production_date" value="${escapeHtml(selectedDate)}" ${launchDateAttrs(role)} data-quick-field="date" />
          ${launchDateHint(role)}
        </label>
        <label class="quick-checkbox">
          <span>Manter colaborador</span>
          <input type="checkbox" name="keep_employee" value="1" ${keepEmployee ? 'checked' : ''} />
        </label>
        <label>OP (bipar ou digitar)
          <span class="scan-input"><input name="op_number" required autocomplete="off" placeholder="Bipe a etiqueta ou digite a OP" value="${escapeHtml(values.op_number || '')}" data-quick-field="op" data-scan-input /><button class="btn secondary scan-btn" type="button" data-scan-camera title="Ler com a câmera">📷</button></span>
        </label>
        <label>Minutos F21 do lançamento
          <input type="number" min="0.001" step="0.001" name="used_minutes_f21" value="${escapeHtml(selectedLaunchMinutes)}" data-quick-field="minutes" />
        </label>
        <label>Quantidade produzida
          <input type="number" inputmode="numeric" min="1" name="produced_quantity" required value="${escapeHtml(values.produced_quantity || '')}" data-quick-field="quantity" />
        </label>
        <div class="full">${renderPrizeFlagField(values)}</div>
        <div class="full actions">
          <button class="btn" type="submit">Salvar e seguir</button>
          <a class="btn secondary" href="/ops">Consultar OPs</a>
        </div>
      </form>
      ${renderPrizeFlagScript({ formSelector: '[data-quick-launch]', employeeFieldSelector: '[name=employee_id]', dateFieldSelector: '[name=production_date]' })}
      <div class="quick-launch-tip">Leitor USB: bipe a etiqueta no campo OP e o cursor vai direto para a quantidade. No celular, use 📷. Enter na quantidade salva.</div>
      ${renderScannerScript()}
      ${quickPreview ? `
        <div class="quick-op-preview ${quickPreview.is_in_cell ? 'is-blocked' : (quickPreview.remaining_quantity <= 0 ? 'is-finished' : '')}">
          <strong>${escapeHtml(quickPreview.op_number)} · ${escapeHtml(quickPreview.product_name)}</strong>
          <span>Saldo atual: ${quickPreview.remaining_quantity} peça(s) · Produzido: ${quickPreview.produced_quantity}/${quickPreview.total_pieces}</span>
          <span>Min. base lançamento: ${fmtNum(quickPreview.effective_launch_minutes, 3)} · Normal/pç: ${fmtNum(quickPreview.launch_normal_minutes_per_piece, 3)} · Extra/pç: ${fmtNum(quickPreview.extra_minutes_per_piece, 3)} · Total/pç: ${fmtNum(quickPreview.total_launch_minutes_per_piece, 3)} · Status: ${escapeHtml(quickPreview.status_color)}</span>
          ${quickPreview.extra_reason ? `<span>Tempo extra ativo: ${quickPreview.extra_reason}</span>` : ''}
          ${quickPreview.is_in_cell ? `<span><strong>Bloqueada para lançamento normal.</strong> Está na célula ${escapeHtml(quickPreview.active_cell_name || '-')} e precisa de retorno antes.</span>` : ''}
        </div>
      ` : values.op_number ? '<div class="quick-op-preview is-missing"><strong>OP não encontrada.</strong><span>Confira o número digitado antes de salvar.</span></div>' : ''}
    </section>
    <section class="panel">
      <h3>Últimos lançamentos</h3>
      <table>
        <thead><tr><th>Data</th><th>OP</th><th>Colaborador</th><th>Qtd</th><th>Normal</th><th>Extra</th><th>Total</th></tr></thead>
        <tbody>
          ${recent.map(item => `<tr><td>${escapeHtml(nowPt(item.production_date))}</td><td>${escapeHtml(item.op_number)}</td><td>${escapeHtml(item.registration_code)} - ${escapeHtml(item.full_name)}</td><td>${item.produced_quantity}</td><td>${fmtNum(round3(item.normal_minutes || 0), 3)}</td><td>${fmtNum(round3(item.extra_minutes || 0), 3)}</td><td>${fmtNum(round3(item.produced_minutes), 3)}</td></tr>`).join('') || '<tr><td colspan="7">Nenhum lançamento ainda.</td></tr>'}
        </tbody>
      </table>
    </section>
    <script>
      (() => {
        const form = document.querySelector('[data-quick-launch]');
        if (!form) return;
        const employee = form.querySelector('[data-quick-field="employee"]');
        const date = form.querySelector('[data-quick-field="date"]');
        const op = form.querySelector('[data-quick-field="op"]');
        const minutes = form.querySelector('[data-quick-field="minutes"]');
        const quantity = form.querySelector('[data-quick-field="quantity"]');
        const firstTarget = employee && !employee.value ? employee : op || minutes || quantity || employee || date;
        if (firstTarget) firstTarget.focus();
        if (op && op.value) op.select();
        const loadPreview = async () => {
          const opNumber = (op.value || '').trim();
          if (!opNumber || !minutes) return;
          try {
            const response = await fetch('/api/op-preview?op_number=' + encodeURIComponent(opNumber), { headers: { Accept: 'application/json' } });
            if (!response.ok) return;
            const data = await response.json();
            if (data && data.found && typeof data.effective_launch_minutes === 'number') {
              minutes.value = Number(data.effective_launch_minutes).toFixed(3);
            }
          } catch (_error) {}
        };
        if (op) {
          op.addEventListener('blur', loadPreview);
          op.addEventListener('change', loadPreview);
        }
        const ordered = [employee, date, op, minutes, quantity].filter(Boolean);
        ordered.forEach((field, index) => {
          field.addEventListener('keydown', event => {
            if (event.key !== 'Enter') return;
            if (field === quantity) return;
            event.preventDefault();
            if (field === op) { loadPreview(); if (quantity) { quantity.focus(); quantity.select(); } return; }
            const next = ordered[index + 1];
            if (next) next.focus();
          });
        });
        if (op) op.addEventListener('scan', () => { loadPreview(); if (quantity) { quantity.focus(); quantity.select(); } });
      })();
    </script>
  `;

  const defaultContent = `
    <section class="panel quick-launch-switch">
      <div>
        <h3>Precisa lançar mais rápido?</h3>
        <p>Use o modo sequencial para digitar OP manualmente e seguir um lançamento por vez.</p>
      </div>
      <a class="btn" href="/productions/new">Abrir lançamento rápido</a>
    </section>
    <form class="panel form-grid" method="post" action="/productions" data-full-launch>
      <input type="hidden" name="mode" value="default" />
      <label>Colaborador
        <select name="employee_id" required>
          <option value="">Selecione</option>
          ${employees.map(emp => `<option value="${emp.id}" ${String(values.employee_id || '') === String(emp.id) ? 'selected' : ''}>${escapeHtml(emp.registration_code)} - ${escapeHtml(emp.full_name)}${emp.start_date || emp.termination_date ? ` (${emp.start_date || 'sem início'} até ${emp.termination_date || 'atual'})` : ''}</option>`).join('')}
        </select>
      </label>
      <label>OP
        <select name="op_id" required>
          <option value="">Selecione</option>
          ${ops.map(op => `<option value="${op.id}" ${String(values.op_id || '') === String(op.id) ? 'selected' : ''}>${escapeHtml(op.op_number)} - ${escapeHtml(op.product_name)} (${op.remaining_quantity} saldo)</option>`).join('')}
        </select>
      </label>
      <label>Minutos F21 do lançamento<input type="number" min="0.001" step="0.001" name="used_minutes_f21" value="${escapeHtml(values.used_minutes_f21 || '')}" /></label>
      <label>Quantidade produzida<input type="number" inputmode="numeric" min="1" name="produced_quantity" required value="${escapeHtml(values.produced_quantity || '')}" /></label>
      <label>Data<input type="date" name="production_date" value="${escapeHtml(selectedDate)}" ${launchDateAttrs(role)} />${launchDateHint(role)}</label>
      <div class="full">${renderPrizeFlagField(values)}</div>
      <div class="full actions"><button class="btn" type="submit">Salvar lançamento</button><a class="btn secondary" href="/ops">Consultar OPs</a></div>
      <p class="hint full">${blockedCellOps.length ? `${blockedCellOps.length} OP(s) em célula foram retiradas da lista normal até o retorno. <a href="/ops?status=rosa">Ver OPs em célula</a>.` : 'Nenhuma OP bloqueada por célula no momento.'}</p>
    </form>
    ${renderPrizeFlagScript({ formSelector: '[data-full-launch]', employeeFieldSelector: '[name=employee_id]', dateFieldSelector: '[name=production_date]' })}

    <section class="panel">
      <h3>Últimos lançamentos</h3>
      <table>
        <thead><tr><th>Data</th><th>OP</th><th>Colaborador</th><th>Qtd</th><th>Normal</th><th>Extra</th><th>Total</th></tr></thead>
        <tbody>
          ${recent.map(item => `<tr><td>${escapeHtml(nowPt(item.production_date))}</td><td>${escapeHtml(item.op_number)}</td><td>${escapeHtml(item.registration_code)} - ${escapeHtml(item.full_name)}</td><td>${item.produced_quantity}</td><td>${fmtNum(round3(item.normal_minutes || 0), 3)}</td><td>${fmtNum(round3(item.extra_minutes || 0), 3)}</td><td>${fmtNum(round3(item.produced_minutes), 3)}</td></tr>`).join('') || '<tr><td colspan="7">Nenhum lançamento ainda.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;

  const content = `
    <section class="page-header"><div><h2>Lançamento diário</h2><p>Cálculo automático separado em minutos normais, minutos extras e total do lançamento. F21/F22 seguem preservados.</p></div></section>
    ${mode === 'quick' ? quickContent : defaultContent}
  `;

  return pageLayout({ title: 'Novo lançamento', content, error, notice, role });
}

function renderOpListPage(query = {}, role = 'adm') {
  const availableBrands = getBrandList().map(item => item.name);
  const availableCollections = getCollectionList().map(item => item.name);
  const filters = {
    q: query.q || '',
    status: query.status || '',
    opType: query.op_type || '',
    brand: query.brand || '',
    collectionName: query.collection_name || '',
    billingStatus: query.billing_status || '',
    deadline: query.deadline || '',
    sort: query.sort || ''
  };
  const rows = getOpList(filters);
  const deadlineCounts = db.prepare(`
    SELECT
      SUM(CASE WHEN delivery_date IS NOT NULL AND delivery_date <> '' AND delivery_date < ? THEN 1 ELSE 0 END) AS late,
      SUM(CASE WHEN delivery_date BETWEEN ? AND ? THEN 1 ELSE 0 END) AS soon
    FROM ops
    WHERE is_reversed = 0 AND shipped_at IS NULL AND status_color <> 'vermelho' AND COALESCE(lifecycle_type, 'normal') = 'normal'
  `).get(today(), today(), addDaysIso(today(), 3));
  const content = `
    <section class="page-header">
      <div><h2>Consulta de OPs</h2><p>Busca com status, saldo e acesso ao histórico detalhado.</p></div>
      <a class="btn" href="/ops/new">Nova OP</a>
    </section>
    ${Number(deadlineCounts.late || 0) || Number(deadlineCounts.soon || 0) ? `<div class="deadline-alerts">
      ${Number(deadlineCounts.late || 0) ? `<a class="delivery-tag late" href="/ops?deadline=atrasadas">${deadlineCounts.late} OP(s) atrasada(s)</a>` : ''}
      ${Number(deadlineCounts.soon || 0) ? `<a class="delivery-tag soon" href="/ops?deadline=vencem3">${deadlineCounts.soon} vencem em até 3 dias</a>` : ''}
    </div>` : ''}
    <form class="panel inline-form" method="get" action="/ops">
      <label>Buscar<input name="q" value="${escapeHtml(filters.q)}" placeholder="OP, código de barras, produto ou marca" /></label>
      <label>Status
        <select name="status">
          <option value="">Todos</option>
          <option value="verde" ${filters.status === 'verde' ? 'selected' : ''}>Verde</option>
          <option value="amarelo" ${filters.status === 'amarelo' ? 'selected' : ''}>Amarelo</option>
          <option value="azul" ${filters.status === 'azul' ? 'selected' : ''}>Azul</option>
          <option value="rosa" ${filters.status === 'rosa' ? 'selected' : ''}>Rosa / em célula</option>
          <option value="vermelho" ${filters.status === 'vermelho' ? 'selected' : ''}>Vermelho</option>
        </select>
      </label>
      <label>Tipo
        <select name="op_type">
          <option value="">Todos</option>
          <option value="producao" ${filters.opType === 'producao' ? 'selected' : ''}>Produção</option>
          <option value="mostruario" ${filters.opType === 'mostruario' ? 'selected' : ''}>Mostruário</option>
        </select>
      </label>
      <label>Marca
        <select name="brand">
          <option value="">Todas</option>
          ${availableBrands.map(item => `<option value="${escapeHtml(item)}" ${filters.brand === item ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}
        </select>
      </label>
      <label>Coleção
        <select name="collection_name">
          <option value="">Todas</option>
          ${availableCollections.map(item => `<option value="${escapeHtml(item)}" ${filters.collectionName === item ? 'selected' : ''}>${escapeHtml(item)}</option>`).join('')}
        </select>
      </label>
      <label>Prazo de entrega
        <select name="deadline">
          <option value="">Todos</option>
          <option value="atrasadas" ${filters.deadline === 'atrasadas' ? 'selected' : ''}>Atrasadas</option>
          <option value="vencem3" ${filters.deadline === 'vencem3' ? 'selected' : ''}>Vencem em até 3 dias</option>
          <option value="sem_data" ${filters.deadline === 'sem_data' ? 'selected' : ''}>Sem data</option>
        </select>
      </label>
      <label ${isLancadorRole(role) ? 'hidden' : ''}>Cobrança
        <select name="billing_status">
          <option value="">Todas</option>
          <option value="billed" ${filters.billingStatus === 'billed' ? 'selected' : ''}>Cobradas</option>
          <option value="not_billed" ${filters.billingStatus === 'not_billed' ? 'selected' : ''}>Não cobradas</option>
          <option value="returned" ${filters.billingStatus === 'returned' ? 'selected' : ''}>Devolvidas</option>
        </select>
      </label>
      <button class="btn" type="submit">Filtrar</button>
      <a class="btn secondary" href="/labels/entry?${new URLSearchParams({ q: filters.q, status: filters.status, op_type: filters.opType, brand: filters.brand, collection_name: filters.collectionName }).toString()}" target="_blank">Gerar etiquetas de entrada</a>
    </form>
    <section class="panel">
      <table>
        <thead><tr><th>OP</th><th>Produto</th><th>Tipo</th><th>Marca</th><th>Coleção</th><th>Total</th><th>Produzido</th><th>Saldo</th><th><a href="/ops?${new URLSearchParams({ ...query, sort: 'entrega' }).toString()}" title="Ordenar por data de entrega">Entrega ↑</a></th><th>Embarque</th><th>Status</th>${isLancadorRole(role) ? '' : '<th>Cobrança</th>'}<th>Ações</th></tr></thead>
        <tbody>
          ${rows.map(op => `<tr><td>${escapeHtml(op.op_number)}</td><td>${escapeHtml(op.product_name)}</td><td>${escapeHtml(op.op_type)}</td><td>${escapeHtml(op.brand || '-')}</td><td>${escapeHtml(op.collection_name || '-')}</td><td>${op.total_pieces}</td><td>${op.produced_quantity}</td><td>${op.remaining_quantity}</td><td>${deliveryBadge(op)}</td><td>${escapeHtml(nowPt(op.shipped_at))}</td><td>${statusBadge(op.status_color)} ${lifecycleBadge(op.lifecycle_type)}</td>${isLancadorRole(role) ? '' : `<td>${billingStatusLabel(op)}</td>`}<td><a href="/ops/${op.id}">Detalhar</a></td></tr>`).join('') || '<tr><td colspan="13">Nenhuma OP encontrada.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'OPs', content, notice: query.notice || '', role });
}

function renderOpDetailPage(id, query = {}, role = 'adm') {
  const detail = getOpDetail(Number(id));
  if (!detail) return pageLayout({ title: 'OP não encontrada', content: '<section class="panel"><p>OP não encontrada.</p></section>', error: 'Registro não localizado.', role });
  const { op, history, occurrences, problemHistory, shipmentHistory, extraTimes, billingHistory, cellTransfers, openCellTransfers, activeCellTransfer, cellBalance } = detail;
  const content = `
    <section class="page-header">
      <div>
        <h2>OP ${escapeHtml(op.op_number)}</h2>
        <p>${escapeHtml(op.product_name)} · ${escapeHtml(op.brand || 'Sem marca')} · ${escapeHtml(op.op_type)}</p>
      </div>
      <div class="header-actions">
        ${statusBadge(op.status_color)}
        ${lifecycleBadge(op.lifecycle_type)}
        <a class="btn secondary" href="/ops">Voltar à consulta</a>
      </div>
    </section>


    <div class="two-columns">
      <section class="panel">
        <h3>Dados da OP</h3>
        ${activeCellTransfer ? `<div class="alert cell-alert">OP com saldo em célula. Último envio pendente: <strong>${escapeHtml(activeCellTransfer.cell_name)}</strong> desde ${escapeHtml(nowPt(activeCellTransfer.sent_at))}.</div>` : ''}
        <dl class="details-grid">
          <dt>Barcode</dt><dd>${escapeHtml(op.barcode || '-')}</dd>
          <dt>Quantidade total</dt><dd>${op.total_pieces}</dd>
          <dt>Produzido acumulado</dt><dd>${op.produced_quantity}</dd>
          <dt>Peças com problema</dt><dd>${op.problem_quantity}</dd>
          <dt>Retornadas da célula</dt><dd>${op.returned_from_cells_quantity || 0}</dd>
          <dt>Aberto em célula</dt><dd>${op.open_in_cells_quantity || 0}</dd>
          <dt>Total considerado</dt><dd>${op.counted_quantity}</dd>
          <dt>Saldo</dt><dd>${op.remaining_quantity}</dd>
          <dt>Minutos F21</dt><dd>${fmtNum(Number(op.minutes_f21), 3)}</dd>
          <dt>Minutos F22</dt><dd>${fmtNum(Number(op.minutes_f22), 3)}</dd>
          <dt>F23</dt><dd>${escapeHtml(op.f23_mode)} ${op.minutes_f23 != null ? `(${fmtNum(Number(op.minutes_f23), 3)} min)` : ''}</dd>
          <dt>Coleção</dt><dd>${escapeHtml(op.collection_name || '-')}</dd>
          <dt>Piloto</dt><dd>${escapeHtml(op.pilot_mode || '-')}</dd>
          <dt>Aparelho</dt><dd>${escapeHtml(op.appliance || '-')}</dd>
          <dt>Data de entrada</dt><dd>${escapeHtml(nowPt(op.entry_date))}</dd>
          <dt>Data de entrega</dt><dd>${deliveryBadge(op)}${canAccessCadastros(role) ? `<form class="inline-form delivery-form" method="post" action="/ops/${op.id}/delivery-date"><input type="date" name="delivery_date" value="${escapeHtml(op.delivery_date || '')}" /><button class="btn secondary" type="submit">Salvar</button></form>` : ''}</dd>
          <dt>Data de saída</dt><dd>${escapeHtml(nowPt(op.shipped_at))}</dd>
          ${isLancadorRole(role) ? '' : `<dt>Cobrança</dt><dd>${billingStatusText(op)}</dd>
          <dt>Obs. cobrança</dt><dd>${escapeHtml(op.billing_notes || '-')}</dd>`}
          <dt>Fluxo da OP</dt><dd>${lifecycleFlowLabel(op.lifecycle_type)}</dd>
          ${isReturnedWithoutProductionLifecycle(op.lifecycle_type) ? `<dt>Motivo da devolução</dt><dd>${escapeHtml(op.return_reason || '-')}</dd><dt>Devolvida em</dt><dd>${escapeHtml(nowPt(op.returned_without_production_at))}</dd>` : ''}
          <dt>Origem</dt><dd>${escapeHtml(getSourceLabel(op.notes))}</dd>
          <dt>Minutos normais produzidos</dt><dd>${fmtNum(Number(op.produced_normal_minutes || 0), 2)}</dd>
          <dt>Minutos extras produzidos</dt><dd>${fmtNum(Number(op.produced_extra_minutes || 0), 2)}</dd>
          <dt>Total minutos produzidos</dt><dd>${fmtNum(Number(op.produced_minutes || 0), 2)}</dd>
          <dt>Min. embarque costura</dt><dd>${fmtNum(Number(op.sewing_minutes || 0), 2)}</dd>
          <dt>Min. embarque pós-costura</dt><dd>${fmtNum(Number(op.post_sewing_minutes || 0), 2)}</dd>
          <dt>Observações</dt><dd>${escapeHtml(op.notes || '-')}</dd>
        </dl>
      </section>

      <section class="panel">
        <h3>Costura em célula</h3>
        <div class="mini-stats" style="margin-bottom:12px; display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr)); gap:8px;">
          <div class="card"><span>Enviado</span><strong>${cellBalance.total_sent}</strong></div>
          <div class="card"><span>Retornado</span><strong>${cellBalance.total_returned}</strong></div>
          <div class="card"><span>Aberto</span><strong>${cellBalance.total_open}</strong></div>
          <div class="card"><span>Saldo livre</span><strong>${Math.max(Number(op.remaining_quantity || 0) - Number(cellBalance.total_open || 0), 0)}</strong></div>
        </div>
        ${userCanManageCells(role) ? `
          <form method="post" action="/ops/${op.id}/cell/send" class="stack-form">
            <label>Célula
              <select name="cell_id" required>
                <option value="">Selecione</option>
                ${getCellList().map(cell => `<option value="${cell.id}">${escapeHtml(cell.name)}</option>`).join('')}
              </select>
            </label>
            <label>Quantidade para enviar<input type="number" inputmode="numeric" name="quantity_sent" min="1" max="${Math.max(Number(op.remaining_quantity || 0) - Number(cellBalance.total_open || 0), 0)}" value="${Math.max(Math.min(Math.max(Number(op.remaining_quantity || 0) - Number(cellBalance.total_open || 0), 0), 1), 0)}" required /></label>
            <label>Data de envio<input type="date" name="sent_at" value="${escapeHtml(today())}" required /></label>
            <label class="full">Observações do envio<textarea name="sent_notes" rows="3" placeholder="Opcional"></textarea></label>
            <button class="btn" type="submit">Enviar quantidade para célula</button>
          </form>
          ${openCellTransfers.length ? `<div class="panel" style="margin-top:12px;"><h4 style="margin-top:0;">Pendências abertas por célula</h4>${openCellTransfers.map(item => `<form method="post" action="/ops/${op.id}/cell/return" class="stack-form" style="margin-bottom:12px; padding-bottom:12px; border-bottom:1px solid rgba(148,163,184,.2);"><input type="hidden" name="transfer_id" value="${item.id}" /><div><strong>${escapeHtml(item.cell_name)}</strong> · envio em ${escapeHtml(nowPt(item.sent_at))} · aberto ${getOpenQuantityFromCellTransfer(item)} peça(s)</div><label>Quantidade retornada<input type="number" name="quantity_returned" min="1" max="${getOpenQuantityFromCellTransfer(item)}" value="${getOpenQuantityFromCellTransfer(item)}" required /></label><label>Data do retorno<input type="date" name="returned_at" value="${escapeHtml(today())}" required /></label><label class="full">Observações do retorno<textarea name="return_notes" rows="2" placeholder="Opcional"></textarea></label><button class="btn secondary" type="submit">Registrar retorno desta célula</button></form>`).join('')}</div>` : '<p class="hint">Nenhum envio pendente em célula no momento.</p>'}
        ` : '<p class="hint">Somente Administrador e Operacional podem registrar envio/retorno de célula.</p>'}
        <div class="filters"></div>
        <table>
          <thead><tr><th>Célula</th><th>Envio</th><th>Retorno final</th><th>Recebeu</th><th>Devolveu</th><th>Aberto</th><th>Status</th><th>Obs.</th></tr></thead>
          <tbody>
            ${cellTransfers.map(item => `<tr><td>${escapeHtml(item.cell_name)}</td><td>${escapeHtml(nowPt(item.sent_at))}</td><td>${escapeHtml(nowPt(item.returned_at))}</td><td>${Number(item.quantity_sent || 0)}</td><td>${Number(item.quantity_returned || 0)}</td><td>${getOpenQuantityFromCellTransfer(item)}</td><td>${getOpenQuantityFromCellTransfer(item) > 0 ? '<span class="badge rosa">pendente em célula</span>' : '<span class="badge azul">retorno concluído</span>'}</td><td>${escapeHtml([item.sent_notes, item.return_notes].filter(Boolean).join(' | ') || '-')}</td></tr>`).join('') || '<tr><td colspan="8">Nenhum envio para célula registrado.</td></tr>'}
          </tbody>
        </table>
      </section>

      <section class="panel">
        <h3>Ocorrências</h3>
        <form method="post" action="/ops/${op.id}/occurrences" class="stack-form">
          <label>Nova ocorrência<textarea name="description" rows="4" placeholder="Descreva a pendência ou parada da OP"></textarea></label>
          <button class="btn" type="submit">Registrar ocorrência</button>
        </form>
        <div class="occurrence-list">
          ${occurrences.map(oc => `
            <article class="occurrence ${oc.is_concluded ? 'done' : 'open'}">
              <strong>${oc.is_concluded ? 'Concluída' : 'Aberta'}</strong>
              <p>${escapeHtml(oc.description)}</p>
              <small>Abertura: ${escapeHtml(nowPt(oc.opened_at))}</small>
              ${oc.is_concluded ? `<small>Fechamento: ${escapeHtml(nowPt(oc.concluded_at))}</small><p><strong>Justificativa:</strong> ${escapeHtml(oc.conclusion_reason || '-')}</p>` : `
                <form method="post" action="/ops/${op.id}/occurrences/${oc.id}/conclude" class="stack-form compact">
                  <label>Justificativa de conclusão<input name="conclusion_reason" /></label>
                  <button class="btn secondary" type="submit">Concluir ocorrência</button>
                </form>`}
            </article>
          `).join('') || '<p class="hint">Nenhuma ocorrência registrada.</p>'}
        </div>
      </section>
    </div>

    <section class="panel">
      <h3>Histórico de embarque</h3>
      <table>
        <thead><tr><th>Embarque</th><th>Data</th><th>Costura</th><th>Pós-costura</th><th>Total</th></tr></thead>
        <tbody>
          ${shipmentHistory.map(item => `<tr><td><a href="/shipments/${item.shipment_id}">${escapeHtml(item.shipment_number)}</a></td><td>${escapeHtml(nowPt(item.shipment_date))}</td><td>${fmtNum(Number(item.sewing_minutes || 0), 2)}</td><td>${fmtNum(Number(item.post_sewing_minutes || 0), 2)}</td><td>${fmtNum(Number(item.total_minutes || 0), 2)}</td></tr>`).join('') || '<tr><td colspan="5">Nenhum embarque registrado para esta OP.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel" ${isLancadorRole(role) ? 'hidden' : ''}>
      <h3>Histórico de cobrança</h3>
      <table>
        <thead><tr><th>Data</th><th>Observação</th><th>Registrado por</th><th>Lote</th></tr></thead>
        <tbody>
          ${billingHistory.map(item => `<tr><td>${escapeHtml(nowPt(item.billed_at))}</td><td>${escapeHtml(item.notes || '-')}</td><td>${escapeHtml(item.billed_by_name || '-')}</td><td>${escapeHtml(item.batch_reference || '-')}</td></tr>`).join('') || '<tr><td colspan="4">Nenhuma cobrança registrada para esta OP.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h3>Tempo extra da OP</h3>
      <table>
        <thead><tr><th>Início</th><th>Extra/pç</th><th>Motivo</th><th>Descrição</th><th>Status</th><th>Obs.</th></tr></thead>
        <tbody>
          ${extraTimes.map(item => `<tr><td>${escapeHtml(nowPt(item.effective_date))}</td><td>${fmtNum(Number(item.extra_minutes_per_piece || 0), 3)}</td><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.description || '-')}</td><td>${item.is_active ? 'Ativo' : 'Inativo'}</td><td>${escapeHtml(item.notes || '-')}</td></tr>`).join('') || '<tr><td colspan="6">Nenhum tempo extra cadastrado para esta OP.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h3>Histórico de produção</h3>
      <table>
        <thead><tr><th>Data</th><th>Registro</th><th>Colaborador</th><th>Quantidade</th><th>F21 usado</th><th>Normal</th><th>Extra</th><th>Total</th></tr></thead>
        <tbody>
          ${history.map(item => `<tr><td>${escapeHtml(nowPt(item.production_date))}</td><td>${escapeHtml(item.registration_code)}</td><td>${escapeHtml(item.full_name)}</td><td>${item.produced_quantity}</td><td>${fmtNum(Number(item.used_minutes_f21), 3)}</td><td>${fmtNum(Number(item.normal_minutes || 0), 3)}</td><td>${fmtNum(Number(item.extra_minutes || 0), 3)}</td><td>${fmtNum(Number(item.produced_minutes), 3)}</td></tr>`).join('') || '<tr><td colspan="8">Nenhum lançamento para esta OP.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h3>Peças com problema</h3>
      <form method="post" action="/ops/${op.id}/problem-items" class="stack-form">
        <label>Data<input type="date" name="problem_date" value="${escapeHtml(today())}" required /></label>
        <label>Quantidade<input type="number" min="1" step="1" name="quantity" required /></label>
        <label>Motivo<input name="reason" required placeholder="Ex.: painel, segunda qualidade, estampa errada" /></label>
        <label class="full">Observação<textarea name="notes" rows="3" placeholder="Detalhes opcionais do problema"></textarea></label>
        <button class="btn" type="submit">Registrar peça com problema</button>
      </form>
      ${op.remaining_quantity > 0 ? `
      <form method="post" action="/ops/${op.id}/return-without-sewing" class="stack-form compact" onsubmit="return confirm('Confirmar devolução sem costura do saldo restante desta OP?');">
        <label>Data<input type="date" name="problem_date" value="${escapeHtml(today())}" required /></label>
        <label>Saldo restante<input value="${op.remaining_quantity}" disabled /></label>
        <label>Gera cobrança?
          <select name="billing_decision" required>
            <option value="">Selecione</option>
            <option value="bill">Sim, terá cobrança</option>
            <option value="return">Não, deixar como devolvida</option>
          </select>
        </label>
        <label class="full">Motivo obrigatório<textarea name="reason" rows="2" required placeholder="Ex.: faltou painel frente"></textarea></label>
        <label class="full">Observação<textarea name="notes" rows="2" placeholder="Detalhes adicionais da devolução sem costura"></textarea></label>
        <button class="btn secondary" type="submit">Devolver saldo sem costurar</button>
      </form>` : ''}
      <div class="filters"></div>
      <table>
        <thead><tr><th>Data</th><th>Qtd</th><th>Motivo</th><th>Observação</th><th>Registrado em</th></tr></thead>
        <tbody>
          ${problemHistory.map(item => `<tr><td>${escapeHtml(nowPt(item.problem_date))}</td><td>${item.quantity}</td><td>${escapeHtml(item.reason)}</td><td>${escapeHtml(item.notes || '-')}</td><td>${escapeHtml(nowPt(item.created_at))}</td></tr>`).join('') || '<tr><td colspan="5">Nenhuma peça com problema registrada para esta OP.</td></tr>'}
        </tbody>
      </table>
      <p class="hint">Essas peças entram no saldo da OP, ajudam a concluir a quantidade total e não geram minutos de costura.</p>
    </section>
  `;
  return pageLayout({ title: `OP ${op.op_number}`, content, notice: query.notice || '', error: query.error || '', role });
}

function renderShipmentCreatePage(values = {}, error = '', notice = '', role = 'adm') {
  const filters = {
    q: values.q || '',
    op_number: values.op_number || '',
    entry_date: values.entry_date || ''
  };
  const shipmentDate = values.shipment_date || today();
  const selectedIds = normalizeIds(values.op_ids);
  const rows = getEligibleShipmentOps({ q: filters.q, opNumber: filters.op_number, entryDate: filters.entry_date });
  const previewRows = selectedIds.length ? getShipmentCreatePreview(selectedIds).rows : [];
  const previewTotals = summarizeShipmentTotals(previewRows);

  const content = `
    <section class="page-header">
      <div>
        <h2>Gerar embarque</h2>
        <p>Somente OPs azuis (finalizadas) e ainda não embarcadas podem entrar no embarque.</p>
      </div>
      <a class="btn secondary" href="/shipments">Ver embarques gerados</a>
    </section>

    <form class="panel inline-form" method="get" action="/shipments/new">
      <label>Busca geral<input name="q" value="${escapeHtml(filters.q)}" placeholder="Número da OP, produto, marca ou código de barras" /></label>
      <label>Número da OP<input name="op_number" value="${escapeHtml(filters.op_number)}" placeholder="Ex.: OP-1024" /></label>
      <label>Data de entrada<input type="date" name="entry_date" value="${escapeHtml(filters.entry_date)}" /></label>
      <button class="btn" type="submit">Filtrar</button>
      <a class="btn secondary" href="/shipments/new">Limpar</a>
    </form>

    <form class="panel stack-form" method="post" action="/shipments">
      <input type="hidden" name="q" value="${escapeHtml(filters.q)}" />
      <input type="hidden" name="op_number" value="${escapeHtml(filters.op_number)}" />
      <input type="hidden" name="entry_date" value="${escapeHtml(filters.entry_date)}" />
      <div class="inline-form">
        <label>Data do embarque<input type="date" name="shipment_date" value="${escapeHtml(shipmentDate)}" /></label>
        <label>Observações<input name="notes" value="${escapeHtml(values.notes || '')}" placeholder="Opcional" /></label>
      </div>
      <table>
        <thead><tr><th>Sel.</th><th>OP</th><th>Produto</th><th>Tipo</th><th>Status</th><th>Entrada</th><th>Qtd</th><th>Costura (F21+F22)</th><th>Pós-costura (F23)</th><th>Total</th></tr></thead>
        <tbody>
          ${rows.map(op => `<tr>
            <td><input type="checkbox" name="op_ids" value="${op.id}" ${selectedIds.includes(op.id) ? 'checked' : ''} /></td>
            <td>${escapeHtml(op.op_number)}</td>
            <td>${escapeHtml(op.product_name)}</td>
            <td>${escapeHtml(op.op_type)}</td>
            <td>${statusBadge(op.status_color)}</td>
            <td>${escapeHtml(nowPt(op.entry_date))}</td>
            <td>${op.total_pieces}</td>
            <td>${fmtNum(Number(op.sewing_minutes), 2)}</td>
            <td>${fmtNum(Number(op.post_sewing_minutes), 2)}</td>
            <td>${fmtNum(Number(op.total_shipment_minutes), 2)}</td>
          </tr>`).join('') || '<tr><td colspan="10">Nenhuma OP apta encontrada.</td></tr>'}
        </tbody>
      </table>
      <div class="shipment-summary-grid">
        <article class="mini-card"><span>OPs selecionadas</span><strong>${previewTotals.opCount}</strong></article>
        <article class="mini-card"><span>Produção</span><strong>${fmtNum(previewTotals.productionMinutes, 2)}</strong></article>
        <article class="mini-card"><span>Mostruário</span><strong>${fmtNum(previewTotals.sampleMinutes, 2)}</strong></article>
        <article class="mini-card"><span>Costura</span><strong>${fmtNum(previewTotals.sewingMinutes, 2)}</strong></article>
        <article class="mini-card"><span>Pós-costura</span><strong>${fmtNum(previewTotals.postSewingMinutes, 2)}</strong></article>
        <article class="mini-card"><span>Total</span><strong>${fmtNum(previewTotals.totalMinutes, 2)}</strong></article>
      </div>
      <div class="actions"><button class="btn" type="submit">Gerar embarque</button><button class="btn secondary" type="submit" formaction="/labels/shipment" formmethod="get" formtarget="_blank">Visualizar etiquetas de embarque</button></div>
    </form>
  `;
  return pageLayout({ title: 'Novo embarque', content, error, notice, role });
}

function renderShipmentListPage(query = {}, role = 'adm') {
  const filters = {
    start_date: query.start_date || '',
    end_date: query.end_date || '',
    q: query.q || ''
  };
  const { rows, totals } = getShipmentList(filters);
  const content = `
    <section class="page-header">
      <div><h2>Consulta de embarques</h2><p>Filtro básico por data e totalizadores consolidados do período.</p></div>
      <a class="btn" href="/shipments/new">Novo embarque</a>
    </section>
    <form class="panel inline-form" method="get" action="/shipments">
      <label>De<input type="date" name="start_date" value="${escapeHtml(filters.start_date)}" /></label>
      <label>Até<input type="date" name="end_date" value="${escapeHtml(filters.end_date)}" /></label>
      <label>Buscar<input name="q" value="${escapeHtml(filters.q)}" placeholder="Número do embarque ou OP" /></label>
      <button class="btn" type="submit">Filtrar</button>
    </form>

    <div class="shipment-summary-grid section-gap">
      <article class="mini-card"><span>Embarques</span><strong>${totals.shipments}</strong></article>
      <article class="mini-card"><span>OPs</span><strong>${totals.ops}</strong></article>
      <article class="mini-card"><span>Produção</span><strong>${fmtNum(totals.productionMinutes, 2)}</strong></article>
      <article class="mini-card"><span>Mostruário</span><strong>${fmtNum(totals.sampleMinutes, 2)}</strong></article>
      <article class="mini-card"><span>Costura</span><strong>${fmtNum(totals.sewingMinutes, 2)}</strong></article>
      <article class="mini-card"><span>Pós-costura</span><strong>${fmtNum(totals.postSewingMinutes, 2)}</strong></article>
      <article class="mini-card"><span>Total</span><strong>${fmtNum(totals.totalMinutes, 2)}</strong></article>
    </div>

    <section class="panel">
      <table>
        <thead><tr><th>Embarque</th><th>Data</th><th>OPs</th><th>Produção</th><th>Mostruário</th><th>Costura</th><th>Pós-costura</th><th>Total</th><th></th></tr></thead>
        <tbody>
          ${rows.map(row => `<tr><td>${escapeHtml(row.shipment_number)}</td><td>${escapeHtml(nowPt(row.shipment_date))}</td><td>${row.total_ops}</td><td>${fmtNum(Number(row.production_minutes || 0), 2)}</td><td>${fmtNum(Number(row.sample_minutes || 0), 2)}</td><td>${fmtNum(Number(row.sewing_minutes || 0), 2)}</td><td>${fmtNum(Number(row.post_sewing_minutes || 0), 2)}</td><td>${fmtNum(Number(row.total_minutes || 0), 2)}</td><td><a href="/shipments/${row.id}">Detalhar</a></td></tr>`).join('') || '<tr><td colspan="9">Nenhum embarque encontrado.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'Embarques', content, notice: query.notice || '', role });
}

function renderShipmentDetailPage(id, query = {}, role = 'adm') {
  const detail = getShipmentDetail(Number(id));
  if (!detail) {
    return pageLayout({ title: 'Embarque não encontrado', content: '<section class="panel"><p>Embarque não encontrado.</p></section>', error: 'Registro não localizado.', role });
  }
  const { shipment, items } = detail;
  const content = `
    <section class="page-header">
      <div>
        <h2>Embarque ${escapeHtml(shipment.shipment_number)}</h2>
        <p>Data ${escapeHtml(nowPt(shipment.shipment_date))} · ${shipment.total_ops} OP(s)</p>
      </div>
      <div class="header-actions">
        <a class="btn secondary" href="/shipments">Voltar à consulta</a>
        <a class="btn secondary" href="/shipments/${shipment.id}/labels" target="_blank">Etiquetas do embarque</a>
      </div>
    </section>

    <div class="shipment-summary-grid section-gap">
      <article class="mini-card"><span>Produção</span><strong>${fmtNum(Number(shipment.production_minutes || 0), 2)}</strong></article>
      <article class="mini-card"><span>Mostruário</span><strong>${fmtNum(Number(shipment.sample_minutes || 0), 2)}</strong></article>
      <article class="mini-card"><span>Costura</span><strong>${fmtNum(Number(shipment.sewing_minutes || 0), 2)}</strong></article>
      <article class="mini-card"><span>Pós-costura</span><strong>${fmtNum(Number(shipment.post_sewing_minutes || 0), 2)}</strong></article>
      <article class="mini-card"><span>Total</span><strong>${fmtNum(Number(shipment.total_minutes || 0), 2)}</strong></article>
    </div>

    <section class="panel">
      <h3>Itens do embarque</h3>
      <table>
        <thead><tr><th>OP</th><th>Produto</th><th>Marca</th><th>Tipo</th><th>Qtd</th><th>Costura</th><th>Pós-costura</th><th>Total</th><th>Saída</th></tr></thead>
        <tbody>
          ${items.map(item => {
            const noIndustrialization = isReturnedWithoutProductionLifecycle(item.lifecycle_type);
            return `<tr><td><a href="/ops/${item.op_id}">${escapeHtml(item.op_number)}</a>${noIndustrialization ? '<br /><span class="hint">Baixada sem industrialização</span>' : ''}</td><td>${escapeHtml(item.product_name || '-')}</td><td>${escapeHtml(item.brand || '-')}</td><td>${escapeHtml(item.op_type)}</td><td>${item.total_pieces}</td><td>${noIndustrialization ? '-' : fmtNum(Number(item.sewing_minutes || 0), 2)}</td><td>${noIndustrialization ? '-' : fmtNum(Number(item.post_sewing_minutes || 0), 2)}</td><td>${noIndustrialization ? '-' : fmtNum(Number(item.total_minutes || 0), 2)}</td><td>${escapeHtml(item.shipped_at || shipment.shipment_date)}</td></tr>`;
          }).join('') || '<tr><td colspan="9">Nenhum item encontrado.</td></tr>'}
        </tbody>
      </table>
      <p class="hint">Observações: ${escapeHtml(shipment.notes || '-')}</p>
    </section>
  `;
  return pageLayout({ title: `Embarques ${shipment.shipment_number}`, content, notice: query.notice || '', role });
}


function getEstornoSearchData(filters = {}) {
  const recordType = filters.record_type || 'op';
  const q = String(filters.q || '').trim();
  if (!q) return { recordType, rows: [] };

  if (recordType === 'production') {
    const rows = db.prepare(`
      SELECT
        p.id,
        p.production_date,
        p.produced_quantity,
        p.normal_minutes,
        p.extra_minutes,
        p.produced_minutes,
        p.used_minutes_f21,
        p.is_reversed,
        p.reversed_at,
        o.id AS op_id,
        o.op_number,
        o.product_name,
        e.id AS employee_id,
        e.registration_code,
        e.full_name
      FROM op_daily_productions p
      JOIN ops o ON o.id = p.op_id
      JOIN employees e ON e.id = p.employee_id
      WHERE o.is_reversed = 0
        AND (
          o.op_number LIKE ? OR
          e.full_name LIKE ? OR
          e.registration_code LIKE ? OR
          p.production_date LIKE ?
        )
      ORDER BY p.production_date DESC, p.created_at DESC
      LIMIT 30
    `).all(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
    return { recordType, rows };
  }

  if (recordType === 'shipment') {
    const rows = db.prepare(`
      SELECT
        s.id,
        s.shipment_number,
        s.shipment_date,
        s.total_ops,
        s.total_minutes,
        s.notes,
        s.is_reversed,
        s.reversed_at,
        GROUP_CONCAT(si.op_number, ', ') AS op_numbers
      FROM shipments s
      LEFT JOIN shipment_items si ON si.shipment_id = s.id
      WHERE s.shipment_number LIKE ?
         OR EXISTS (SELECT 1 FROM shipment_items x WHERE x.shipment_id = s.id AND x.op_number LIKE ?)
      GROUP BY s.id
      ORDER BY s.shipment_date DESC, s.created_at DESC
      LIMIT 30
    `).all(`%${q}%`, `%${q}%`);
    return { recordType, rows };
  }

  const rows = db.prepare(`
    SELECT
      o.id,
      o.op_number,
      o.product_name,
      o.brand,
      o.op_type,
      o.total_pieces,
      o.minutes_f21,
      o.minutes_f22,
      o.f23_mode,
      o.minutes_f23,
      o.entry_date,
      o.notes,
      o.status_color,
      o.is_reversed,
      o.reversed_at,
      COALESCE(SUM(p.produced_quantity), 0) AS produced_quantity
    FROM ops o
    LEFT JOIN op_daily_productions p ON p.op_id = o.id AND p.is_reversed = 0
    WHERE o.op_number LIKE ?
       OR COALESCE(o.barcode, '') LIKE ?
       OR o.product_name LIKE ?
       OR COALESCE(o.brand, '') LIKE ?
    GROUP BY o.id
    ORDER BY o.created_at DESC
    LIMIT 30
  `).all(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
  return { recordType, rows };
}


function getLabelRows(filters = {}) {
  return getOpList({
    q: filters.q || '',
    status: filters.status || '',
    opType: filters.op_type || '',
    brand: filters.brand || '',
    collectionName: filters.collection_name || '',
    opNumber: filters.op_number || '',
    entryDate: filters.entry_date || ''
  });
}

function getSelectedShipmentLabelRows(query = {}) {
  const selectedIds = normalizeIds(query.op_ids || []);
  if (selectedIds.length) {
    return getShipmentCreatePreview(selectedIds).rows;
  }
  return getEligibleShipmentOps({ q: query.q || '', opNumber: query.op_number || '', entryDate: query.entry_date || '' });
}

function buildLabelQuery(params = {}) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (Array.isArray(value)) {
      value.filter(Boolean).forEach(item => search.append(key, String(item)));
      continue;
    }
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  }
  return search.toString();
}

function formatLabelTime(unitMinutes, totalPieces, enabled = true) {
  if (!enabled) return 'Externo';
  const unit = Number(unitMinutes || 0);
  const total = round2(unit * Number(totalPieces || 0));
  return `${fmtNum(unit, 3)} · Total ${fmtNum(total, 2)}`;
}

function formatPilotLabel(mode) {
  const normalized = String(mode || '').trim().toLowerCase();
  if (normalized === 'com piloto') return 'Sim';
  if (normalized === 'sem piloto') return 'Não';
  return mode || '-';
}

// ===================== CÓDIGO DE BARRAS (T1.2) =====================
// Code 128 (conjunto B) gerado no servidor como SVG — sem dependências externas.
const CODE128_PATTERNS = '212222 222122 222221 121223 121322 131222 122213 122312 132212 221213 221312 231212 112232 122132 122231 113222 123122 123221 223211 221132 221231 213212 223112 312131 311222 321122 321221 312212 322112 322211 212123 212321 232121 111323 131123 131321 112313 132113 132311 211313 231113 231311 112133 112331 132131 113123 113321 133121 313121 211331 231131 213113 213311 213131 311123 311321 331121 312113 312311 332111 314111 221411 431111 111224 111422 121124 121421 141122 141221 112214 112412 122114 122411 142112 142211 241211 221114 413111 241112 134111 111242 121142 121241 114212 124112 124211 411212 421112 421211 212141 214121 412121 111143 111341 131141 114113 114311 411113 411311 113141 114131 311141 411131 211412 211214 211232'.split(' ');
const CODE128_STOP = '2331112';

function renderCode128Svg(text, { height = 46, className = 'barcode-svg' } = {}) {
  const value = String(text || '').trim();
  if (!value || /[^\x20-\x7e]/.test(value)) return '';
  const codes = [104];
  for (const ch of value) codes.push(ch.charCodeAt(0) - 32);
  const checksum = codes.reduce((sum, code, index) => sum + code * (index || 1), 0) % 103;
  codes.push(checksum);
  const widths = codes.map(code => CODE128_PATTERNS[code]).join('') + CODE128_STOP;
  const quiet = 10;
  let x = quiet;
  let bars = '';
  let isBar = true;
  for (const w of widths) {
    const width = Number(w);
    if (isBar) bars += `<rect x="${x}" y="0" width="${width}" height="${height}"/>`;
    x += width;
    isBar = !isBar;
  }
  const total = x + quiet;
  return `<svg class="${className}" viewBox="0 0 ${total} ${height}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Código de barras ${escapeHtml(value)}" shape-rendering="crispEdges"><rect width="${total}" height="${height}" fill="#fff"/><g fill="#000">${bars}</g></svg>`;
}

// Leitura pela câmera (celular/tablet). Usa o leitor nativo do navegador (Android/Chrome)
// e, se não existir (iPhone), carrega o ZXing. Ao ler, preenche o campo e dispara o evento "scan".
function renderScannerScript() {
  return `<script>
  (() => {
    if (window.__agilfacScanner) return;
    window.__agilfacScanner = true;
    let overlay, video, statusEl, stream, rafId, zxingReader, done;
    const stop = () => {
      done = true;
      if (rafId) cancelAnimationFrame(rafId);
      if (zxingReader) { try { zxingReader.reset(); } catch (_) {} zxingReader = null; }
      if (stream) { stream.getTracks().forEach(t => t.stop()); stream = null; }
      if (overlay) overlay.hidden = true;
    };
    const ensureOverlay = () => {
      if (overlay) return;
      overlay = document.createElement('div');
      overlay.className = 'scan-overlay';
      overlay.innerHTML = '<div class="scan-box"><video playsinline muted></video><div class="scan-aim"></div><p class="scan-status">Aponte a câmera para o código de barras da etiqueta</p><button type="button" class="btn secondary">Cancelar</button></div>';
      document.body.appendChild(overlay);
      video = overlay.querySelector('video');
      statusEl = overlay.querySelector('.scan-status');
      overlay.querySelector('button').addEventListener('click', stop);
    };
    const deliver = (input, text) => {
      if (done) return;
      stop();
      input.value = String(text || '').trim();
      try { navigator.vibrate && navigator.vibrate(80); } catch (_) {}
      input.dispatchEvent(new Event('change', { bubbles: true }));
      input.dispatchEvent(new CustomEvent('scan', { bubbles: true }));
    };
    const loadZxing = () => new Promise((resolve, reject) => {
      if (window.ZXing) return resolve(window.ZXing);
      const sc = document.createElement('script');
      sc.src = 'https://unpkg.com/@zxing/library@0.21.3/umd/index.min.js';
      sc.onload = () => resolve(window.ZXing);
      sc.onerror = reject;
      document.head.appendChild(sc);
    });
    const open = async input => {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { alert('Este navegador não permite usar a câmera. Digite a OP.'); return; }
      ensureOverlay();
      done = false;
      overlay.hidden = false;
      statusEl.textContent = 'Abrindo a câmera...';
      const constraints = { video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 } } };
      try {
        if ('BarcodeDetector' in window) {
          const detector = new BarcodeDetector({ formats: ['code_128', 'ean_13', 'code_39', 'qr_code'] });
          stream = await navigator.mediaDevices.getUserMedia(constraints);
          video.srcObject = stream;
          await video.play();
          statusEl.textContent = 'Aponte para o código de barras';
          const tick = async () => {
            if (done) return;
            try {
              const codes = await detector.detect(video);
              if (codes && codes.length) return deliver(input, codes[0].rawValue);
            } catch (_) {}
            rafId = requestAnimationFrame(tick);
          };
          tick();
        } else {
          const ZX = await loadZxing();
          zxingReader = new ZX.BrowserMultiFormatReader();
          statusEl.textContent = 'Aponte para o código de barras';
          zxingReader.decodeFromConstraints(constraints, video, result => { if (result) deliver(input, result.getText()); });
        }
      } catch (error) {
        stop();
        alert('Não foi possível usar a câmera (' + (error && error.name ? error.name : 'erro') + '). Verifique a permissão do navegador.');
      }
    };
    document.addEventListener('click', event => {
      const btn = event.target.closest('[data-scan-camera]');
      if (!btn) return;
      event.preventDefault();
      const input = btn.parentElement.querySelector('[data-scan-input]');
      if (input) open(input);
    });
  })();
  </script>`;
}

function renderLabelBarcode(opNumber) {
  const svg = renderCode128Svg(opNumber);
  return svg ? `<div class="label-barcode">${svg}<span>${escapeHtml(opNumber)}</span></div>` : '';
}

function renderLabelsShell({ title, subtitle, labels, role = 'adm', emptyMessage = 'Nenhuma etiqueta encontrada.', filtersHtml = '', batchActionsHtml = '' }) {
  const companyName = getCompanyName();
  const renderedLabels = labels.map(item => {
    const isEntryLabel = item.labelType === 'Etiqueta de entrada';
    if (isEntryLabel) {
      return `
        <article class="label-card label-card-entry label-card-entry-layout-v3">
          <div class="entry-label-header entry-label-header-compact">
            <strong>${escapeHtml(companyName)}</strong>
            <span>${escapeHtml(item.labelType)}</span>
          </div>

          <div class="entry-label-grid-row entry-label-grid-line-1">
            <div class="entry-cell entry-cell-brand"><span>Marca</span><strong>${escapeHtml(item.brand || '-')}</strong></div>
            <div class="entry-cell entry-cell-op"><span>OP</span><strong>${escapeHtml(item.op_number)}</strong></div>
          </div>

          <div class="entry-label-grid-row entry-label-grid-line-2">
            <div class="entry-cell entry-cell-model"><span>Modelo</span><strong>${escapeHtml(item.product_name || '-')}</strong></div>
            <div class="entry-cell"><span>Piloto</span><strong>${escapeHtml(formatPilotLabel(item.pilot_mode))}</strong></div>
            <div class="entry-cell"><span>Chegada</span><strong>${escapeHtml(nowPt(item.entry_date))}</strong></div>
          </div>

          <div class="entry-label-grid-row entry-label-grid-line-3">
            <div class="entry-cell entry-cell-qty"><span>Quantidade</span><strong>${escapeHtml(String(item.total_pieces || 0))}</strong></div>
            <div class="entry-cell entry-cell-time"><span>T. costura</span><strong>${formatLabelTime(Math.max(Number(item.minutes_f21 || 0) - Number(item.minutes_f22 || 0), 0), item.total_pieces, true)}</strong></div>
            <div class="entry-cell entry-cell-time"><span>T. Pós costura</span><strong>${formatLabelTime(item.minutes_f23, item.total_pieces, item.f23_mode === 'interno')}</strong></div>
          </div>

          <div class="entry-label-grid-row entry-label-grid-line-4 ${item.delivery_date ? 'has-delivery' : ''}">
            <div class="entry-cell entry-cell-appliance"><span>Aparelho</span><strong>${escapeHtml(item.appliance || '-')}</strong></div>
            ${item.delivery_date ? `<div class="entry-cell entry-cell-delivery"><span>Entrega</span><strong>${escapeHtml(formatDatePtBr(item.delivery_date))}</strong></div>` : ''}
          </div>
          ${renderLabelBarcode(item.op_number)}
          ${item.singleLabelHref ? `<div class="label-card-actions no-print"><a class="btn secondary" href="${item.singleLabelHref}" target="_blank">Gerar individual</a></div>` : ''}
        </article>
      `;
    }
    return `
      <article class="label-card">
        <div class="label-card-head">
          <div class="label-card-title-block">
            <span>${escapeHtml(item.labelType)}</span>
            <strong>${escapeHtml(companyName)}</strong>
          </div>
          <div class="label-card-op-block">
            <span>OP</span>
            <b>${escapeHtml(item.op_number)}</b>
          </div>
        </div>

        <div class="label-product-block">
          <span>MOD</span>
          <strong>${escapeHtml(item.product_name || '-')}</strong>
        </div>

        <section class="label-highlights">
          <article class="label-highlight qty">
            <span>Quant.</span>
            <strong>${escapeHtml(String(item.total_pieces || 0))}</strong>
          </article>
          <article class="label-highlight time">
            <span>T. costura</span>
            <strong>${formatLabelTime(item.minutes_f21, item.total_pieces, true)}</strong>
          </article>
          <article class="label-highlight time">
            <span>T. Pós</span>
            <strong>${formatLabelTime(item.minutes_f23, item.total_pieces, item.f23_mode === 'interno')}</strong>
          </article>
        </section>

        <dl class="label-fields label-fields-secondary">
          <div class="label-field-emphasis"><dt>Marca</dt><dd>${escapeHtml(item.brand || '-')}</dd></div>
          <div class="label-field-emphasis"><dt>Aparelho</dt><dd>${escapeHtml(item.appliance || '-')}</dd></div>
          <div><dt>Piloto</dt><dd>${escapeHtml(formatPilotLabel(item.pilot_mode))}</dd></div>
          <div><dt>Chegada</dt><dd>${escapeHtml(nowPt(item.entry_date))}</dd></div>
          <div><dt>Coleção</dt><dd>${escapeHtml(item.collection_name || '-')}</dd></div>
          ${item.shipment_date ? `<div><dt>Embarque</dt><dd>${escapeHtml(nowPt(item.shipment_date))}</dd></div>` : ''}
        </dl>
        ${renderLabelBarcode(item.op_number)}
        ${item.singleLabelHref ? `<div class="label-card-actions no-print"><a class="btn secondary" href="${item.singleLabelHref}" target="_blank">Gerar individual</a></div>` : ''}
      </article>
    `;
  }).join('');
  const content = `
    <section class="page-header print-header no-print">
      <div>
        <h2>${escapeHtml(title)}</h2>
        <p>${escapeHtml(subtitle)}</p>
      </div>
      <div class="header-actions">
        <button class="btn" type="button" onclick="window.print()">Imprimir / salvar PDF</button>
      </div>
    </section>

    <div class="no-print">${filtersHtml}</div>
    <div class="no-print">${batchActionsHtml}</div>

    <section class="label-grid">
      ${renderedLabels || `<section class="panel"><p>${escapeHtml(emptyMessage)}</p></section>`}
    </section>
  `;
  return pageLayout({ title, content, role });
}

function renderEntryLabelsPage(query = {}, role = 'adm') {
  const filters = {
    q: query.q || '',
    status: query.status || '',
    op_type: query.op_type || '',
    brand: query.brand || '',
    collection_name: query.collection_name || '',
    op_number: query.op_number || '',
    entry_date: query.entry_date || ''
  };
  const rows = getLabelRows(filters).map(row => ({
    ...row,
    labelType: 'Etiqueta de entrada',
    singleLabelHref: `/labels/entry?${buildLabelQuery({ ...filters, op_number: row.op_number })}`
  }));
  const filtersHtml = `
    <form class="panel inline-form no-print" method="get" action="/labels/entry">
      <label>Busca geral<input name="q" value="${escapeHtml(filters.q)}" placeholder="OP, produto, marca ou código de barras" /></label>
      <label>Número da OP<input name="op_number" value="${escapeHtml(filters.op_number)}" placeholder="Ex.: OP-1024" /></label>
      <label>Data de entrada<input type="date" name="entry_date" value="${escapeHtml(filters.entry_date)}" /></label>
      <label>Status
        <select name="status">
          <option value="">Todos</option>
          <option value="verde" ${filters.status === 'verde' ? 'selected' : ''}>Verde</option>
          <option value="amarelo" ${filters.status === 'amarelo' ? 'selected' : ''}>Amarelo</option>
          <option value="azul" ${filters.status === 'azul' ? 'selected' : ''}>Azul</option>
          <option value="rosa" ${filters.status === 'rosa' ? 'selected' : ''}>Rosa / em célula</option>
          <option value="vermelho" ${filters.status === 'vermelho' ? 'selected' : ''}>Vermelho</option>
        </select>
      </label>
      <button class="btn" type="submit">Filtrar</button>
      <a class="btn secondary" href="/labels/entry">Ver todas</a>
    </form>
  `;
  const batchActionsHtml = `
    <section class="panel label-toolbar no-print">
      <div>
        <strong>${rows.length} etiqueta(s)</strong>
        <p>Resultado atual pronto para impressão em lote ou geração individual.</p>
      </div>
      <div class="actions">
        <button class="btn" type="button" onclick="window.print()">Gerar lote filtrado</button>
        <a class="btn secondary" href="/ops?${buildLabelQuery(filters)}">Voltar para consulta de OPs</a>
      </div>
    </section>
  `;
  return renderLabelsShell({
    title: 'Etiquetas de entrada',
    subtitle: `Visualização completa das etiquetas de entrada. ${rows.length} etiqueta(s) no filtro atual.`,
    labels: rows,
    role,
    filtersHtml,
    batchActionsHtml,
    emptyMessage: 'Nenhuma OP encontrada para gerar etiquetas de entrada com os filtros informados.'
  });
}

function renderShipmentLabelsPage(query = {}, role = 'adm') {
  const filters = {
    q: query.q || '',
    op_number: query.op_number || '',
    entry_date: query.entry_date || '',
    shipment_date: query.shipment_date || today(),
    op_ids: normalizeIds(query.op_ids || [])
  };
  const rows = getSelectedShipmentLabelRows(filters).map(row => ({
    ...row,
    labelType: 'Etiqueta de embarque',
    shipment_date: filters.shipment_date,
    singleLabelHref: `/labels/shipment?${buildLabelQuery({ shipment_date: filters.shipment_date, op_number: row.op_number })}`
  }));
  const selectionHint = filters.op_ids.length ? 'Baseadas nas OPs selecionadas na tela de embarque.' : 'Se nada for selecionado, a tela lista todas as OPs aptas e permite filtrar.';
  const filtersHtml = `
    <form class="panel inline-form no-print" method="get" action="/labels/shipment">
      <label>Busca geral<input name="q" value="${escapeHtml(filters.q)}" placeholder="OP, produto, marca ou código de barras" /></label>
      <label>Número da OP<input name="op_number" value="${escapeHtml(filters.op_number)}" placeholder="Ex.: OP-1024" /></label>
      <label>Data de entrada<input type="date" name="entry_date" value="${escapeHtml(filters.entry_date)}" /></label>
      <label>Data do embarque<input type="date" name="shipment_date" value="${escapeHtml(filters.shipment_date)}" /></label>
      ${filters.op_ids.map(id => `<input type="hidden" name="op_ids" value="${id}" />`).join('')}
      <button class="btn" type="submit">Filtrar</button>
      <a class="btn secondary" href="/labels/shipment">Ver todas aptas</a>
    </form>
  `;
  const batchActionsHtml = `
    <section class="panel label-toolbar no-print">
      <div>
        <strong>${rows.length} etiqueta(s)</strong>
        <p>${escapeHtml(selectionHint)}</p>
      </div>
      <div class="actions">
        <button class="btn" type="button" onclick="window.print()">Gerar lote filtrado</button>
        <a class="btn secondary" href="/shipments/new?${buildLabelQuery({ q: filters.q, op_number: filters.op_number, entry_date: filters.entry_date, shipment_date: filters.shipment_date, op_ids: filters.op_ids })}">Voltar para embarque</a>
      </div>
    </section>
  `;
  return renderLabelsShell({
    title: 'Etiquetas de embarque',
    subtitle: `Visualização das etiquetas de embarque. ${rows.length} etiqueta(s) no filtro atual.`,
    labels: rows,
    role,
    filtersHtml,
    batchActionsHtml,
    emptyMessage: 'Nenhuma OP apta encontrada para gerar etiquetas de embarque.'
  });
}

function renderShipmentLabelsByShipmentPage(id, query = {}, role = 'adm') {
  const detail = getShipmentDetail(Number(id));
  if (!detail) {
    return pageLayout({ title: 'Etiquetas de embarque', content: '<section class="panel"><p>Embarque não encontrado.</p></section>', error: 'Registro não localizado.', role });
  }
  const rows = detail.items.map(item => ({
    ...item,
    minutes_f21: item.minutes_f21,
    minutes_f23: item.minutes_f23,
    f23_mode: item.f23_mode,
    entry_date: item.entry_date,
    pilot_mode: item.pilot_mode,
    collection_name: item.collection_name,
    appliance: item.appliance,
    brand: item.brand,
    labelType: `Etiqueta de embarque ${detail.shipment.shipment_number}`,
    shipment_date: detail.shipment.shipment_date
  }));
  return renderLabelsShell({
    title: 'Etiquetas de embarque',
    subtitle: `Embarque ${detail.shipment.shipment_number} com ${rows.length} etiqueta(s).`,
    labels: rows,
    role,
    emptyMessage: 'Esse embarque não possui itens para etiqueta.'
  });
}

function renderEstornosPage(query = {}, role = 'adm') {
  const filters = { record_type: query.record_type || 'op', q: query.q || '' };
  const search = getEstornoSearchData(filters);
  const brands = getBrandList({ onlyActive: true });
  const employees = db.prepare('SELECT id, registration_code, full_name FROM employees ORDER BY full_name').all();
  const audits = getRecentAuditEntries(25);

  const rowsHtml = search.recordType === 'production'
    ? search.rows.map(row => `
      <article class="audit-record ${row.is_reversed ? 'is-reversed' : ''}">
        <div class="audit-record-head"><div><strong>Lançamento #${row.id}</strong><span>${escapeHtml(row.op_number)} · ${escapeHtml(row.registration_code)} - ${escapeHtml(row.full_name)} · ${formatDatePtBr(row.production_date)}</span></div><span class="status-pill ${row.is_reversed ? 'pending' : 'ok'}">${row.is_reversed ? 'Estornado' : 'Ativo'}</span></div>
        <p class="hint">Qtd ${row.produced_quantity} · Normal ${fmtNum(Number(row.normal_minutes || 0), 2)} · Extra ${fmtNum(Number(row.extra_minutes || 0), 2)} · Total ${fmtNum(Number(row.produced_minutes || 0), 2)}${row.reversed_at ? ` · estornado em ${escapeHtml(nowPt(row.reversed_at))}` : ''}</p>
        ${row.is_reversed ? '' : `
        <div class="closure-actions-grid audit-actions-grid">
          <form class="panel inset-panel stack-form compact" method="post" action="/estornos/production/correct">
            <input type="hidden" name="id" value="${row.id}" />
            <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
            <label>OP<input name="op_number" value="${escapeHtml(row.op_number)}" required /></label>
            <label>Colaborador
              <select name="employee_id" required>${employees.map(emp => `<option value="${emp.id}" ${emp.id === row.employee_id ? 'selected' : ''}>${escapeHtml(emp.registration_code)} - ${escapeHtml(emp.full_name)}</option>`).join('')}</select>
            </label>
            <label>Data<input type="date" name="production_date" value="${escapeHtml(row.production_date)}" required /></label>
            <label>Quantidade<input type="number" inputmode="numeric" min="1" name="produced_quantity" value="${row.produced_quantity}" required /></label>
            <label>Minutos F21 do lançamento<input type="number" min="0.001" step="0.001" name="used_minutes_f21" value="${Number(row.used_minutes_f21 || 0).toFixed(3)}" required /></label>
            <label class="full">Motivo da correção<textarea name="reason" rows="2" required placeholder="Obrigatório para auditoria."></textarea></label>
            <button class="btn" type="submit">Salvar correção</button>
          </form>
          <form class="panel inset-panel stack-form compact" method="post" action="/estornos/production/reverse">
            <input type="hidden" name="id" value="${row.id}" />
            <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
            <label>Motivo do estorno<textarea name="reason" rows="3" required placeholder="Obrigatório para estornar o lançamento."></textarea></label>
            <button class="btn secondary" type="submit">Estornar lançamento</button>
          </form>
        </div>`}
      </article>
    `).join('')
    : search.recordType === 'shipment'
      ? search.rows.map(row => `
        <article class="audit-record ${row.is_reversed ? 'is-reversed' : ''}">
          <div class="audit-record-head"><div><strong>${escapeHtml(row.shipment_number)}</strong><span>${formatDatePtBr(row.shipment_date)} · ${row.total_ops} OP(s)</span></div><span class="status-pill ${row.is_reversed ? 'pending' : 'ok'}">${row.is_reversed ? 'Estornado' : 'Ativo'}</span></div>
          <p class="hint">OPs: ${escapeHtml(row.op_numbers || '-')} · Total ${fmtNum(Number(row.total_minutes || 0), 2)} min${row.reversed_at ? ` · estornado em ${escapeHtml(nowPt(row.reversed_at))}` : ''}</p>
          ${row.is_reversed ? '' : `
          <div class="closure-actions-grid audit-actions-grid">
            <form class="panel inset-panel stack-form compact" method="post" action="/estornos/shipment/correct">
              <input type="hidden" name="id" value="${row.id}" />
              <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
              <label>Data do embarque<input type="date" name="shipment_date" value="${escapeHtml(row.shipment_date)}" required /></label>
              <label>Observações<input name="notes" value="${escapeHtml(row.notes || '')}" /></label>
              <label class="full">Motivo da correção<textarea name="reason" rows="2" required placeholder="Obrigatório para auditoria."></textarea></label>
              <button class="btn" type="submit">Salvar correção</button>
            </form>
            <form class="panel inset-panel stack-form compact" method="post" action="/estornos/shipment/reverse">
              <input type="hidden" name="id" value="${row.id}" />
              <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
              <label>Motivo do estorno<textarea name="reason" rows="3" required placeholder="Obrigatório para estornar o embarque."></textarea></label>
              <button class="btn secondary" type="submit">Estornar embarque</button>
            </form>
          </div>`}
        </article>
      `).join('')
      : search.rows.map(row => `
        <article class="audit-record ${row.is_reversed ? 'is-reversed' : ''}">
          <div class="audit-record-head"><div><strong>${escapeHtml(row.op_number)}</strong><span>${escapeHtml(row.product_name)} · ${escapeHtml(row.brand || 'Sem marca')} · ${escapeHtml(row.op_type)}</span></div><span class="status-pill ${row.is_reversed ? 'pending' : 'ok'}">${row.is_reversed ? 'Estornada' : 'Ativa'}</span></div>
          <p class="hint">Qtd ${row.total_pieces} · Produzido ${Number(row.produced_quantity || 0)} · Status ${escapeHtml(row.status_color)}${row.reversed_at ? ` · estornada em ${escapeHtml(nowPt(row.reversed_at))}` : ''}</p>
          ${row.is_reversed ? '' : `
          <div class="closure-actions-grid audit-actions-grid">
            <form class="panel inset-panel stack-form compact" method="post" action="/estornos/op/correct">
              <input type="hidden" name="id" value="${row.id}" />
              <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
              <label>Produto<input name="product_name" value="${escapeHtml(row.product_name)}" required /></label>
              <label>Marca
                <select name="brand" required>${brands.map(brand => `<option value="${escapeHtml(brand.name)}" ${brand.name === row.brand ? 'selected' : ''}>${escapeHtml(brand.name)}</option>`).join('')}</select>
              </label>
              <label>Coleção<input name="collection_name" list="collection-fix-suggestions-${row.id}" value="${escapeHtml(row.collection_name || '')}" /></label>
              <datalist id="collection-fix-suggestions-${row.id}">${getCollectionList().map(collection => `<option value="${escapeHtml(collection.name)}"></option>`).join('')}</datalist>
              <label>Piloto
                <select name="pilot_mode"><option value="" ${!row.pilot_mode ? 'selected' : ''}>Não informado</option><option value="com piloto" ${row.pilot_mode === 'com piloto' ? 'selected' : ''}>Com piloto</option><option value="sem piloto" ${row.pilot_mode === 'sem piloto' ? 'selected' : ''}>Sem piloto</option></select>
              </label>
              <label>Aparelho<input name="appliance" value="${escapeHtml(row.appliance || '')}" /></label>
              <label>Quantidade total<input type="number" min="1" name="total_pieces" value="${row.total_pieces}" required /></label>
              <label>F21<input type="number" min="0" step="0.001" name="minutes_f21" value="${escapeHtml(row.minutes_f21)}" required /></label>
              <label>F22<input type="number" min="0" step="0.001" name="minutes_f22" value="${escapeHtml(row.minutes_f22)}" /></label>
              <label>F23
                <select name="f23_mode"><option value="interno" ${row.f23_mode === 'interno' ? 'selected' : ''}>Interno</option><option value="externo" ${row.f23_mode === 'externo' ? 'selected' : ''}>Externo</option></select>
              </label>
              <label>Minutos F23<input type="number" min="0" step="0.001" name="minutes_f23" value="${escapeHtml(row.minutes_f23 || '')}" /></label>
              <label>Data de entrada<input type="date" name="entry_date" value="${escapeHtml(row.entry_date || '')}" /></label>
              <label class="full">Observações<textarea name="notes" rows="2">${escapeHtml(row.notes || '')}</textarea></label>
              <label class="full">Motivo da correção<textarea name="reason" rows="2" required placeholder="Obrigatório para auditoria."></textarea></label>
              <button class="btn" type="submit">Salvar correção</button>
            </form>
            <form class="panel inset-panel stack-form compact" method="post" action="/estornos/op/reverse">
              <input type="hidden" name="id" value="${row.id}" />
              <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
              <label>Motivo do estorno<textarea name="reason" rows="3" required placeholder="Obrigatório para estornar a OP."></textarea></label>
              <button class="btn secondary" type="submit">Estornar cadastro de OP</button>
              <p class="hint">Regra simples desta versão: só estorna OP sem lançamentos ativos e sem embarque ativo.</p>
            </form>
            <form class="panel inset-panel stack-form compact" method="post" action="/estornos/op/without-industrialization">
              <input type="hidden" name="id" value="${row.id}" />
              <input type="hidden" name="search_q" value="${escapeHtml(filters.q)}" />
              <label>Motivo da baixa sem industrialização<textarea name="reason" rows="3" required placeholder="Obrigatório para liberar a OP sem contar produção."></textarea></label>
              <button class="btn secondary" type="submit">Baixar sem industrialização</button>
              <p class="hint">Essa ação deixa a OP pronta para embarque, sem gerar minutos de produção e sem somar na meta.</p>
            </form>
          </div>`}
        </article>
      `).join('');

  const content = `
    <section class="page-header">
      <div><h2>Estornos / Correções</h2><p>Módulo enxuto exclusivo do ADM para localizar registros principais, corrigir dados e registrar estorno com motivo obrigatório.</p></div>
    </section>
    <section class="panel">
      <form class="inline-form" method="get" action="/estornos">
        <label>Tipo de registro
          <select name="record_type">
            <option value="op" ${filters.record_type === 'op' ? 'selected' : ''}>Cadastro de OP</option>
            <option value="production" ${filters.record_type === 'production' ? 'selected' : ''}>Lançamento diário</option>
            <option value="shipment" ${filters.record_type === 'shipment' ? 'selected' : ''}>Embarque</option>
          </select>
        </label>
        <label>Buscar<input name="q" value="${escapeHtml(filters.q)}" placeholder="Ex.: OP-1001, nome, registro ou EMB-202603" /></label>
        <button class="btn" type="submit">Localizar</button>
      </form>
      <p class="hint">Sem filtros avançados: informe o tipo e uma busca simples, abra o registro e aplique correção ou estorno.</p>
    </section>
    <section class="panel section-gap">
      <div class="panel-header"><h3>Resultados</h3><span class="hint">${filters.q ? `${search.rows.length} registro(s) encontrado(s)` : 'Digite algo para pesquisar.'}</span></div>
      <div class="audit-records">${rowsHtml || '<p class="hint">Nenhum registro encontrado para os critérios informados.</p>'}</div>
    </section>
    <section class="panel section-gap">
      <div class="panel-header"><h3>Histórico / auditoria básica</h3><span class="hint">Últimas 25 ações registradas.</span></div>
      <table>
        <thead><tr><th>Quando</th><th>Ação</th><th>Registro</th><th>Motivo</th></tr></thead>
        <tbody>
          ${audits.map(item => `<tr><td>${escapeHtml(nowPt(item.created_at))}</td><td>${escapeHtml(getAuditLabel(item))}</td><td>${escapeHtml(item.target_type)} #${item.target_id}</td><td>${escapeHtml(item.reason)}</td></tr>`).join('') || '<tr><td colspan="4">Nenhuma ação registrada ainda.</td></tr>'}
        </tbody>
      </table>
    </section>
  `;
  return pageLayout({ title: 'Estornos / Correções', content, notice: query.notice || '', error: query.error || '', role });
}

function redirectEstornos(res, recordType, q, message, isError = false) {
  const params = new URLSearchParams({ record_type: recordType || 'op' });
  if (q) params.set('q', q);
  params.set(isError ? 'error' : 'notice', message);
  redirect(res, `/estornos?${params.toString()}`);
}

function handleReverseOp(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  if (!id || !reason) return redirectEstornos(res, 'op', searchQ, 'Informe o motivo obrigatório do estorno.', true);
  const op = getOpDetail(id)?.op;
  if (!op || op.is_reversed) return redirectEstornos(res, 'op', searchQ, 'OP não encontrada para estorno.', true);
  const activeProductions = db.prepare('SELECT COUNT(*) AS count FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0').get(id).count;
  const activeShipment = db.prepare('SELECT COUNT(*) AS count FROM shipment_items si JOIN shipments s ON s.id = si.shipment_id WHERE si.op_id = ? AND s.is_reversed = 0').get(id).count;
  if (activeProductions || activeShipment) return redirectEstornos(res, 'op', searchQ, 'Esta versão só estorna OP sem lançamentos ativos e sem embarque ativo.', true);
  db.prepare('UPDATE ops SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(reason, id);
  logAuditEntry('op', id, 'estorno', reason, op, { id, is_reversed: 1 });
  redirectEstornos(res, 'op', searchQ, `OP ${op.op_number} estornada com sucesso.`);
}

function handleCorrectOp(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  const detail = getOpDetail(id);
  if (!detail || detail.op.is_reversed) return redirectEstornos(res, 'op', searchQ, 'OP não encontrada para correção.', true);
  if (!reason) return redirectEstornos(res, 'op', searchQ, 'Informe o motivo obrigatório da correção.', true);
  const brand = findBrandByName(form.brand);
  if (!brand) return redirectEstornos(res, 'op', searchQ, 'Marca inválida. Cadastre ou selecione uma marca existente.', true);
  const collection = String(form.collection_name || '').trim() ? findCollectionByName(form.collection_name) : null;
  if (String(form.collection_name || '').trim() && !collection) return redirectEstornos(res, 'op', searchQ, 'Coleção inválida. Cadastre ou selecione uma coleção existente.', true);
  const totalPieces = Number(form.total_pieces || 0);
  const produced = Number(detail.op.produced_quantity || 0);
  const f23Mode = form.f23_mode === 'externo' ? 'externo' : 'interno';
  const minutesF23 = f23Mode === 'interno' ? Number(form.minutes_f23 || 0) : null;
  if (!form.product_name || totalPieces <= 0 || totalPieces < produced || Number(form.minutes_f21) < 0 || Number(form.minutes_f22 || 0) < 0 || (f23Mode === 'interno' && String(form.minutes_f23 || '').trim() === '')) {
    return redirectEstornos(res, 'op', searchQ, 'Dados inválidos: confira produto, quantidade total e tempos F21/F22/F23.', true);
  }
  const before = detail.op;
  db.prepare(`
    UPDATE ops
    SET product_name = ?, brand = ?, collection_name = ?, pilot_mode = ?, appliance = ?, total_pieces = ?, minutes_f21 = ?, minutes_f22 = ?,
        f23_mode = ?, minutes_f23 = ?, entry_date = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(String(form.product_name).trim(), brand.name, collection?.name || null, String(form.pilot_mode || '').trim() || null, String(form.appliance || '').trim() || null, totalPieces, Number(form.minutes_f21 || 0), Number(form.minutes_f22 || 0), f23Mode, minutesF23, form.entry_date || today(), String(form.notes || '').trim() || null, id);
  recalculateOpStatus(id);
  logAuditEntry('op', id, 'correcao', reason, before, getOpDetail(id).op);
  redirectEstornos(res, 'op', searchQ, `OP ${before.op_number} corrigida com sucesso.`);
}

function handleMarkOpWithoutIndustrialization(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  const redirectTo = String(form.redirect_to || '').trim();
  const redirectBack = (message, isError = false) => {
    if (redirectTo) return redirect(res, buildRedirectWithFlash(redirectTo, message, isError));
    return redirectEstornos(res, 'op', searchQ, message, isError);
  };
  const detail = getOpDetail(id);
  if (!detail || detail.op.is_reversed) return redirectBack('OP não encontrada para baixa sem industrialização.', true);
  if (!reason) return redirectBack('Informe o motivo obrigatório da baixa sem industrialização.', true);
  const activeProductions = db.prepare('SELECT COUNT(*) AS count FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0').get(id).count;
  if (activeProductions) return redirectBack('Esta OP já possui lançamentos. A baixa sem industrialização só é permitida sem produção registrada.', true);
  if (detail.op.shipped_at) return redirectBack('A OP já foi embarcada.', true);
  if (isReturnedWithoutProductionLifecycle(detail.op.lifecycle_type)) return redirectBack('Esta OP já está baixada sem industrialização.', true);

  const before = detail.op;
  db.prepare(`
    UPDATE ops
    SET lifecycle_type = 'devolvida_sem_producao',
        returned_without_production_at = CURRENT_TIMESTAMP,
        return_reason = ?,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(reason, id);
  recalculateOpStatus(id);
  logAuditEntry('op', id, 'correcao', `Baixa sem industrialização: ${reason}`, before, getOpDetail(id).op);
  redirectBack(`OP ${before.op_number} baixada sem industrialização e liberada para embarque.`);
}

function handleReverseProduction(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  if (!id || !reason) return redirectEstornos(res, 'production', searchQ, 'Informe o motivo obrigatório do estorno.', true);
  const row = db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(id);
  if (!row || row.is_reversed) return redirectEstornos(res, 'production', searchQ, 'Lançamento não encontrado para estorno.', true);
  db.prepare('UPDATE op_daily_productions SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = ? WHERE id = ?').run(reason, id);
  recalculateOpStatus(row.op_id);
  logAuditEntry('production', id, 'estorno', reason, row, { id, is_reversed: 1 });
  redirectEstornos(res, 'production', searchQ, `Lançamento #${id} estornado com sucesso.`);
}

function handleCorrectProduction(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const employeeId = Number(form.employee_id || 0);
  const qty = Number(form.produced_quantity || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  const row = db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(id);
  if (!row || row.is_reversed) return redirectEstornos(res, 'production', searchQ, 'Lançamento não encontrado para correção.', true);
  if (!reason || !employeeId || qty <= 0) return redirectEstornos(res, 'production', searchQ, 'Preencha OP, colaborador, quantidade e motivo da correção.', true);
  const targetOp = getOpByNumber(form.op_number);
  if (!targetOp) return redirectEstornos(res, 'production', searchQ, 'OP informada não encontrada.', true);
  const employee = db.prepare('SELECT * FROM employees WHERE id = ?').get(employeeId);
  if (!employee) return redirectEstornos(res, 'production', searchQ, 'Colaborador não encontrado.', true);
  const targetTotals = db.prepare(`
    SELECT
      COALESCE((SELECT SUM(produced_quantity) FROM op_daily_productions WHERE op_id = ? AND is_reversed = 0 AND id != ?), 0) AS produced_total,
      COALESCE((SELECT SUM(quantity) FROM op_problem_items WHERE op_id = ?), 0) AS problem_total
  `).get(targetOp.id, id, targetOp.id);
  if (Number(targetTotals.produced_total || 0) + Number(targetTotals.problem_total || 0) + qty > targetOp.total_pieces) return redirectEstornos(res, 'production', searchQ, 'Correção bloqueada: a quantidade ultrapassa o limite total da OP destino.', true);
  const before = row;
  const productionDate = form.production_date || today();
  const launchF21 = Number(form.used_minutes_f21 || row.used_minutes_f21 || targetOp.minutes_f21 || 0);
  const metrics = calculateProductionLaunchMetrics(targetOp, qty, launchF21, productionDate);
  db.prepare(`
    UPDATE op_daily_productions
    SET op_id = ?, employee_id = ?, production_date = ?, produced_quantity = ?,
        used_minutes_f21 = ?, normal_minutes = ?, extra_minutes = ?, produced_minutes = ?,
        extra_time_id = ?, extra_reason_snapshot = ?, extra_description_snapshot = ?, extra_effective_date_snapshot = ?, extra_minutes_per_piece_snapshot = ?
    WHERE id = ?
  `).run(
    targetOp.id,
    employeeId,
    productionDate,
    qty,
    metrics.launchF21,
    metrics.normalMinutes,
    metrics.extraMinutes,
    metrics.totalMinutes,
    metrics.extraSnapshot.extra_time_id,
    metrics.extraSnapshot.extra_reason_snapshot,
    metrics.extraSnapshot.extra_description_snapshot,
    metrics.extraSnapshot.extra_effective_date_snapshot,
    metrics.extraSnapshot.extra_minutes_per_piece_snapshot,
    id
  );
  recalculateOpStatus(before.op_id);
  if (before.op_id !== targetOp.id) recalculateOpStatus(targetOp.id);
  logAuditEntry('production', id, 'correcao', reason, before, db.prepare('SELECT * FROM op_daily_productions WHERE id = ?').get(id));
  redirectEstornos(res, 'production', searchQ, `Lançamento #${id} corrigido com sucesso.`);
}

function handleReverseShipment(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  if (!id || !reason) return redirectEstornos(res, 'shipment', searchQ, 'Informe o motivo obrigatório do estorno.', true);
  const shipment = db.prepare('SELECT * FROM shipments WHERE id = ?').get(id);
  if (!shipment || shipment.is_reversed) return redirectEstornos(res, 'shipment', searchQ, 'Embarque não encontrado para estorno.', true);
  const items = db.prepare('SELECT * FROM shipment_items WHERE shipment_id = ?').all(id);
  try {
    db.exec('BEGIN');
    db.prepare('UPDATE shipments SET is_reversed = 1, reversed_at = CURRENT_TIMESTAMP, reversed_reason = ? WHERE id = ?').run(reason, id);
    for (const item of items) {
      db.prepare('UPDATE ops SET shipped_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(item.op_id);
      recalculateOpStatus(item.op_id);
    }
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    return redirectEstornos(res, 'shipment', searchQ, `Erro ao estornar embarque: ${error.message}`, true);
  }
  logAuditEntry('shipment', id, 'estorno', reason, { shipment, items }, { id, is_reversed: 1 });
  redirectEstornos(res, 'shipment', searchQ, `Embarque ${shipment.shipment_number} estornado com sucesso.`);
}

function handleCorrectShipment(form, res, role) {
  if (!isAdminRole(role)) return requireAdmin(null, res, role);
  const id = Number(form.id || 0);
  const reason = normalizeReason(form.reason);
  const searchQ = String(form.search_q || '');
  const shipment = db.prepare('SELECT * FROM shipments WHERE id = ?').get(id);
  if (!shipment || shipment.is_reversed) return redirectEstornos(res, 'shipment', searchQ, 'Embarque não encontrado para correção.', true);
  if (!reason) return redirectEstornos(res, 'shipment', searchQ, 'Informe o motivo obrigatório da correção.', true);
  const before = shipment;
  const shipmentDate = form.shipment_date || shipment.shipment_date;
  try {
    db.exec('BEGIN');
    db.prepare('UPDATE shipments SET shipment_date = ?, notes = ? WHERE id = ?').run(shipmentDate, String(form.notes || '').trim() || null, id);
    const items = db.prepare('SELECT op_id FROM shipment_items WHERE shipment_id = ?').all(id);
    for (const item of items) {
      db.prepare('UPDATE ops SET shipped_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(shipmentDate, item.op_id);
      recalculateOpStatus(item.op_id);
    }
    db.exec('COMMIT');
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    return redirectEstornos(res, 'shipment', searchQ, `Erro ao corrigir embarque: ${error.message}`, true);
  }
  logAuditEntry('shipment', id, 'correcao', reason, before, db.prepare('SELECT * FROM shipments WHERE id = ?').get(id));
  redirectEstornos(res, 'shipment', searchQ, `Embarque ${shipment.shipment_number} corrigido com sucesso.`);
}

const server = http.createServer(async (req, res) => {
  try {
    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = parsedUrl.pathname;
    const query = {};
    for (const key of new Set(Array.from(parsedUrl.searchParams.keys()))) {
      const all = parsedUrl.searchParams.getAll(key);
      query[key] = all.length > 1 ? all : (all[0] || '');
    }

    if (pathname.startsWith('/public/')) return serveStatic(pathname, res);
    if (pathname === '/api/v1' || pathname.startsWith('/api/v1/')) return handleReadApi(req, res, pathname, query);
    // T1.6 — app instalável (PWA): manifest e service worker na raiz para valer em todo o site
    if (req.method === 'GET' && pathname === '/manifest.webmanifest') return serveStatic('/public/manifest.webmanifest', res);
    if (req.method === 'GET' && pathname === '/sw.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/' });
      return res.end(fs.readFileSync(path.join(PUBLIC_DIR, 'sw.js')));
    }

    if (req.method === 'GET' && pathname === '/superadmin/login') {
      const session = getSuperAdminSession(req);
      if (session) return redirect(res, '/superadmin');
      return sendHtml(res, renderSuperAdminLoginPage({ username: query.username || '' }, query.error || '', query.notice || ''));
    }
    if (req.method === 'POST' && pathname === '/superadmin/login') return handleSuperAdminLogin(await parseBody(req), res, req);
    if (req.method === 'POST' && pathname === '/superadmin/logout') return handleSuperAdminLogout(req, res);
    if (pathname === '/superadmin' || pathname === '/superadmin/') {
      const session = getSuperAdminSession(req);
      if (!session) return redirect(res, '/superadmin/login');
      if (req.method === 'GET') return sendHtml(res, renderSuperAdminPanel(query, {}, query.error || '', query.notice || ''));
    }
    if (req.method === 'GET' && pathname === '/superadmin/backups/download') {
      const session = getSuperAdminSession(req);
      if (!session) return redirect(res, '/superadmin/login');
      return handleSuperAdminBackupDownload(query, res);
    }
    if (req.method === 'POST' && pathname === '/superadmin/companies') {
      const session = getSuperAdminSession(req);
      if (!session) return redirect(res, '/superadmin/login');
      return handleSuperAdminCreateCompany(await parseBody(req), res);
    }

    if (req.method === 'GET' && pathname === '/login') {
      const auth = getSessionContext(req);
      if (auth) return redirect(res, '/');
      return sendHtml(res, renderLoginPage({ returnTo: query.returnTo || '', company: query.company || '', username: query.username || '' }, query.error || '', query.notice || ''));
    }
    if (req.method === 'POST' && pathname === '/login') return handleLogin(await parseBody(req), res, req);
    if (req.method === 'POST' && pathname === '/logout') return handleLogout(req, res);

    const auth = getSessionContext(req);
    if (!auth) return requireAuthentication(req, res);

    return requestContext.run({ auth, tenantDb: auth.tenantDb }, async () => {
      const role = getRequestRole();

      if (req.method === 'GET' && pathname === '/conta/senha') return sendHtml(res, renderChangePasswordPage(auth, query.error || '', query.notice || ''));
      if (req.method === 'POST' && pathname === '/conta/senha') return handleChangePassword(await parseBody(req), res, auth);
      if (auth.user.must_change_password) return redirect(res, '/conta/senha');

      if (req.method === 'GET' && pathname === '/api/op-preview') {
        const preview = getOpQuickPreview(query.op_number || '');
        return sendJson(res, preview ? { found: true, ...preview } : { found: false }, preview ? 200 : 404);
      }

      if (isLancadorRole(role)) {
        if (req.method === 'GET' && pathname === '/') return redirect(res, '/productions/new');
        if (!isLancadorAllowed(req.method, pathname)) {
          return sendHtml(res, pageLayout({
            title: 'Acesso restrito',
            content: '<section class="panel"><p>O perfil Lançador acessa lançamentos, consulta de OPs, célula, ocorrências e etiquetas de entrada.</p><p><a class="btn" href="/productions/new">Ir para lançamentos</a></p></section>',
            error: 'Acesso não permitido para este perfil.',
            role
          }), 403);
        }
      }

      if (isHourlyLauncherRole(role)) {
        const allowed = (
          (req.method === 'GET' && pathname === '/') ||
          (req.method === 'GET' && pathname === '/productions/hourly') ||
          (['GET', 'POST'].includes(req.method) && pathname === '/productions/hourly/quadro') ||
          (req.method === 'GET' && pathname === '/api/op-preview') ||
          (req.method === 'POST' && pathname === '/productions/hourly') ||
          (req.method === 'POST' && pathname === '/productions/hourly/validate') ||
          (req.method === 'POST' && /^\/productions\/hourly\/(\d+\/fix|zero\/\d+\/delete)$/.test(pathname)) ||
          (req.method === 'GET' && pathname === '/login') ||
          (req.method === 'POST' && pathname === '/logout')
        );
        if (!allowed) {
          return sendHtml(res, pageLayout({
            title: 'Acesso restrito',
            content: '<section class="panel"><p>Esse perfil pode acessar somente o dashboard e o lançamento por hora.</p></section>',
            error: 'Acesso não permitido para este perfil.',
            role
          }), 403);
        }
      }

      if (req.method === 'GET' && pathname === '/') return sendHtml(res, renderDashboard(query, role));
      if (req.method === 'GET' && pathname === '/ops') return sendHtml(res, renderOpListPage(query, role));
      if (req.method === 'GET' && pathname === '/ops/new') return sendHtml(res, renderOpForm({}, '', role));
      if (req.method === 'POST' && pathname === '/ops') return handleCreateOp({ ...(await parseBody(req)), _role: role }, res);

      if (req.method === 'GET' && pathname === '/billing-reconciliation') return sendHtml(res, renderBillingReconciliationPage(query, query.error || '', null, role));
      if (req.method === 'POST' && pathname === '/billing-reconciliation') return handleBillingReconciliation(await parseBody(req), res, role);

      if (req.method === 'GET' && pathname === '/cadastros') {
        if (requireAdmin(req, res, role)) return;
        return sendHtml(res, renderCadastrosPage(query, {}, '', role));
      }
      if (req.method === 'GET' && pathname === '/op-extra-times') return sendHtml(res, renderOpExtraTimesPage(query, {}, '', role));
      if (req.method === 'GET' && pathname === '/op-extra-times/report') return sendHtml(res, renderOpExtraTimeReportPage(query, role));
      if (req.method === 'GET' && pathname === '/op-extra-times/report/export') return sendHtml(res, renderOpExtraTimeExportPage(query, role));
      if (req.method === 'POST' && pathname === '/op-extra-times') return handleCreateOpExtraTime(await parseBody(req), res, role);
      if (req.method === 'GET' && pathname === '/admin/access') {
        if (requireAdmin(req, res, role)) return;
        return sendHtml(res, renderAccessAdminPage(query, {}, query.error || '', query.notice || ''));
      }
      if (req.method === 'POST' && pathname === '/admin/access/users') return handleCreateCompanyUser(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/admin/access/password') return handleResetCompanyUserPassword(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/brands') return handleCreateBrand(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/collections') return handleCreateCollection(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/cells') return handleCreateCell(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/work-schedules') return handleCreateWorkSchedule(await parseBody(req), res, role);
      if (req.method === 'GET' && pathname === '/parametros') {
        if (requireAdmin(req, res, role)) return;
        return sendHtml(res, renderParametersPage(query, null, query.error || '', role));
      }
      if (req.method === 'POST' && pathname === '/parametros') return handleSaveParameters(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/parametros/alertas') return handleSaveAlerts(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/parametros/api') return handleSaveApi(await parseBody(req), res, role);
      const workScheduleToggleMatch = pathname.match(/^\/work-schedules\/(\d+)\/toggle$/);
      if (req.method === 'POST' && workScheduleToggleMatch) return handleToggleWorkSchedule(Number(workScheduleToggleMatch[1]), res, role);
      const workScheduleUpdateMatch = pathname.match(/^\/work-schedules\/(\d+)$/);
      if (req.method === 'POST' && workScheduleUpdateMatch) return handleUpdateWorkSchedule(Number(workScheduleUpdateMatch[1]), await parseBody(req), res, role);
      if (req.method === 'GET' && pathname === '/cells/report') return sendHtml(res, renderCellReportPage(query, role));
      if (req.method === 'GET' && pathname === '/cells/closures') return sendHtml(res, renderCellClosuresPage(query, {}, '', role));
      if (req.method === 'POST' && pathname === '/cells/closures') return handleCreateCellClosure(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/settings/company') return handleSaveCompanyName(await parseBody(req), res, role);

      if (req.method === 'GET' && pathname === '/estornos') {
        if (requireAdmin(req, res, role)) return;
        return sendHtml(res, renderEstornosPage(query, role));
      }
      if (req.method === 'POST' && pathname === '/estornos/op/reverse') return handleReverseOp(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/estornos/op/correct') return handleCorrectOp(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/estornos/op/without-industrialization') return handleMarkOpWithoutIndustrialization(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/estornos/production/reverse') return handleReverseProduction(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/estornos/production/correct') return handleCorrectProduction(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/estornos/shipment/reverse') return handleReverseShipment(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/estornos/shipment/correct') return handleCorrectShipment(await parseBody(req), res, role);

      if (req.method === 'GET' && pathname === '/employees') return sendHtml(res, renderEmployeeList(query, {}, '', role));
      if (req.method === 'GET' && pathname === '/employees/new') return redirect(res, '/employees');
      if (req.method === 'GET' && pathname === '/employees/whatsapp-resultados') return sendHtml(res, renderEmployeeWhatsAppQueuePage(role));
      if (req.method === 'POST' && pathname === '/employees') return handleCreateEmployee(await parseBody(req), res);

      const opDeliveryMatch = pathname.match(/^\/ops\/(\d+)\/delivery-date$/);
      if (req.method === 'POST' && opDeliveryMatch) return handleUpdateOpDeliveryDate(Number(opDeliveryMatch[1]), await parseBody(req), res, role);

      const employeeUpdateMatch = pathname.match(/^\/employees\/(\d+)$/);
      if (req.method === 'POST' && employeeUpdateMatch) return handleUpdateEmployee(Number(employeeUpdateMatch[1]), await parseBody(req), res);

      const opExtraUpdateMatch = pathname.match(/^\/op-extra-times\/(\d+)$/);
      if (req.method === 'POST' && opExtraUpdateMatch) return handleUpdateOpExtraTime(Number(opExtraUpdateMatch[1]), await parseBody(req), res, role);

      const opExtraToggleMatch = pathname.match(/^\/op-extra-times\/(\d+)\/toggle$/);
      if (req.method === 'POST' && opExtraToggleMatch) return handleToggleOpExtraTime(Number(opExtraToggleMatch[1]), res, role);

      const opExtraDeleteMatch = pathname.match(/^\/op-extra-times\/(\d+)\/delete$/);
      if (req.method === 'POST' && opExtraDeleteMatch) return handleDeleteOpExtraTime(Number(opExtraDeleteMatch[1]), res, role);

      const toggleCellMatch = pathname.match(/^\/cells\/(\d+)\/toggle$/);
      if (req.method === 'POST' && toggleCellMatch) return handleToggleCell(Number(toggleCellMatch[1]), res, role);

      if (req.method === 'GET' && pathname === '/productions/hourly') {
        if (requireHourlyLauncherAccess(res, role)) return;
        return sendHtml(res, renderHourlyProductionPage(query, query.error || '', query.notice || '', role));
      }
      if (req.method === 'POST' && pathname === '/productions/hourly') {
        if (requireHourlyLauncherAccess(res, role)) return;
        return handleCreateHourlyProduction(await parseBody(req), res);
      }
      if (req.method === 'GET' && pathname === '/productions/hourly/quadro') {
        if (requireHourlyLauncherAccess(res, role)) return;
        return sendHtml(res, renderHourlyGridPage(query, query.error || '', query.notice || '', role));
      }
      if (req.method === 'POST' && pathname === '/productions/hourly/quadro') {
        if (requireHourlyLauncherAccess(res, role)) return;
        return handleSaveHourlyGrid(await parseBody(req), res, role);
      }
      if (req.method === 'POST' && pathname === '/productions/hourly/validate') {
        if (requireHourlyLauncherAccess(res, role)) return;
        return handleValidateHourlyProductionDay(await parseBody(req), res);
      }
      const zeroDelete = pathname.match(/^\/productions\/hourly\/zero\/(\d+)\/delete$/);
      if (req.method === 'POST' && zeroDelete) {
        if (requireHourlyLauncherAccess(res, role)) return;
        return handleDeleteZeroHour(zeroDelete[1], await parseBody(req), res, role);
      }
      const hourlyFix = pathname.match(/^\/productions\/hourly\/(\d+)\/fix$/);
      if (req.method === 'POST' && hourlyFix) {
        if (requireHourlyLauncherAccess(res, role)) return;
        return handleFixHourlyProduction(hourlyFix[1], await parseBody(req), res, role);
      }
      if (req.method === 'POST' && pathname === '/productions/hourly/unvalidate') {
        if (requireAdmin(req, res, role)) return;
        return handleUnvalidateHourlyProductionDay(await parseBody(req), res, role);
      }
      if (req.method === 'GET' && pathname === '/productions/new') return sendHtml(res, renderProductionForm(query, query.error || '', query.notice || '', role));
      if (req.method === 'POST' && pathname === '/productions') return handleCreateProduction(await parseBody(req), res);
      if (pathname.startsWith('/productions/extra') && (isLancadorRole(role) || isHourlyLauncherRole(role))) return requireAdmin(req, res, role);
      if (req.method === 'GET' && pathname === '/productions/extra') return sendHtml(res, renderExtraLaunchPage(query, query.error || '', query.notice || '', role));
      if (req.method === 'POST' && pathname === '/productions/extra') return handleCreateExtraLaunch(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/productions/extra/worked') return handleUpdateWorkedTime(await parseBody(req), res, role);
      if (req.method === 'POST' && pathname === '/productions/extra/worked-bulk') return handleBulkWorkedTime(await parseBody(req), res, role);

      if (req.method === 'GET' && pathname === '/labels/entry') return sendHtml(res, renderEntryLabelsPage(query, role));
      if (req.method === 'GET' && pathname === '/labels/shipment') return sendHtml(res, renderShipmentLabelsPage(query, role));
      if (req.method === 'GET' && pathname === '/shipments/new') return sendHtml(res, renderShipmentCreatePage(query, '', query.notice || '', role));
      if (req.method === 'GET' && pathname === '/shipments') return sendHtml(res, renderShipmentListPage(query, role));
      if (req.method === 'POST' && pathname === '/shipments') return handleCreateShipment(await parseBody(req), res);

      if (req.method === 'GET' && pathname === '/closures') return sendHtml(res, renderMonthlyClosurePage(query, role));
      if (req.method === 'GET' && pathname === '/ausencias/importar') return isAdminRole(role) ? sendHtml(res, renderAbsenceImportUpload(role)) : requireAdmin(req, res, role);
      if (req.method === 'POST' && pathname === '/ausencias/importar') return handleAbsenceImport(req, res, role);
      if (req.method === 'GET' && pathname === '/closures/export') return sendHtml(res, renderClosureExportPage(query, role));
      if (req.method === 'POST' && pathname === '/closures/resolve') return handleUpsertClosureJustification(await parseBody(req), res);
      if (req.method === 'POST' && pathname === '/closures/absence') return handleUpsertClosureAbsence(await parseBody(req), res);
      if (req.method === 'GET' && pathname === '/acompanhamento/diario') return sendHtml(res, renderDailyTrackingPage(query, role));
      if (req.method === 'GET' && pathname === '/acompanhamento/diario/export') return sendHtml(res, renderDailyTrackingExportPage(query, role));
      if (req.method === 'GET' && pathname === '/premios/producao') return sendHtml(res, renderProductionPrizePage(query, role));
      if (req.method === 'GET' && pathname === '/premios/producao/export') return sendHtml(res, renderProductionPrizeExportPage(query, role));

      const shipmentLabelsMatch = pathname.match(/^\/shipments\/(\d+)\/labels$/);
      if (req.method === 'GET' && shipmentLabelsMatch) return sendHtml(res, renderShipmentLabelsByShipmentPage(shipmentLabelsMatch[1], query, role));

      const shipmentDetailMatch = pathname.match(/^\/shipments\/(\d+)$/);
      if (req.method === 'GET' && shipmentDetailMatch) return sendHtml(res, renderShipmentDetailPage(shipmentDetailMatch[1], query, role));

      const cellClosureDetailMatch = pathname.match(/^\/cells\/closures\/(\d+)$/);
      if (req.method === 'GET' && cellClosureDetailMatch) return sendHtml(res, renderCellClosureDetailPage(cellClosureDetailMatch[1], query, role));

      const opDetailMatch = pathname.match(/^\/ops\/(\d+)$/);
      if (req.method === 'GET' && opDetailMatch) return sendHtml(res, renderOpDetailPage(opDetailMatch[1], query, role));

      const opOccurrenceMatch = pathname.match(/^\/ops\/(\d+)\/occurrences$/);
      if (req.method === 'POST' && opOccurrenceMatch) return handleOpenOccurrence(Number(opOccurrenceMatch[1]), await parseBody(req), res);

      const opProblemMatch = pathname.match(/^\/ops\/(\d+)\/problem-items$/);
      if (req.method === 'POST' && opProblemMatch) return handleCreateOpProblemItem(Number(opProblemMatch[1]), await parseBody(req), res);

      const returnWithoutSewingMatch = pathname.match(/^\/ops\/(\d+)\/return-without-sewing$/);
      if (req.method === 'POST' && returnWithoutSewingMatch) return handleReturnRemainingWithoutSewing(Number(returnWithoutSewingMatch[1]), await parseBody(req), res, role);

      const concludeOccurrenceMatch = pathname.match(/^\/ops\/(\d+)\/occurrences\/(\d+)\/conclude$/);
      if (req.method === 'POST' && concludeOccurrenceMatch) {
        return handleConcludeOccurrence(Number(concludeOccurrenceMatch[1]), Number(concludeOccurrenceMatch[2]), await parseBody(req), res);
      }

      const sendCellMatch = pathname.match(/^\/ops\/(\d+)\/cell\/send$/);
      if (req.method === 'POST' && sendCellMatch) return handleSendOpToCell(Number(sendCellMatch[1]), await parseBody(req), res, role);

      const returnCellMatch = pathname.match(/^\/ops\/(\d+)\/cell\/return$/);
      if (req.method === 'POST' && returnCellMatch) return handleReturnOpFromCell(Number(returnCellMatch[1]), await parseBody(req), res, role);

      sendText(res, 'Not found', 404);
    });
  } catch (error) {
    console.error(error);
    const status = String(error.message || '').includes('Nenhum banco da empresa') ? 401 : 500;
    if (status === 401) {
      clearSessionCookie(res);
      return redirect(res, '/login?error=' + encodeURIComponent('Sua sessão expirou. Entre novamente.'));
    }
    sendHtml(res, pageLayout({ title: 'Erro', content: '<section class="panel"><p>Erro interno.</p></section>', error: error.message }), 500);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Controle de OPs rodando em http://0.0.0.0:${PORT}`);
  console.log(`Banco mestre: ${MASTER_DB_PATH}`);
  console.log(`Empresa padrão: ${DEFAULT_COMPANY?.name || 'não configurada'}`);
  console.log(`Banco tenant padrão: ${DEFAULT_COMPANY ? resolveTenantDbPath(DEFAULT_COMPANY.db_path) : 'não configurado'}`);
});
