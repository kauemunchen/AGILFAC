#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');
const TENANTS_DIR = path.join(DATA_DIR, 'tenants');
const MASTER_DB_PATH = path.join(DATA_DIR, 'master.sqlite');
const MASTER_SCHEMA_PATH = path.join(ROOT, 'database', 'master-schema.sql');
const TENANT_SCHEMA_PATH = path.join(ROOT, 'database', 'schema.sql');

function arg(name, fallback = '') {
  const prefix = `--${name}=`;
  const item = process.argv.find(entry => entry.startsWith(prefix));
  return item ? item.slice(prefix.length) : fallback;
}

function slugify(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    || 'empresa';
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password || ''), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

const name = String(arg('name')).trim();
const slug = slugify(arg('slug', name));
const username = String(arg('username', 'admin')).trim() || 'admin';
const password = String(arg('password')).trim();
const cloneFrom = String(arg('clone-from')).trim();

if (!name || !password) {
  console.error('Uso: node scripts/create-company.js --name="Empresa B" --slug="empresa-b" --username="admin" --password="senha-forte" [--clone-from="mais-textil"]');
  process.exit(1);
}

fs.mkdirSync(TENANTS_DIR, { recursive: true });
const masterDb = new DatabaseSync(MASTER_DB_PATH);
masterDb.exec(fs.readFileSync(MASTER_SCHEMA_PATH, 'utf8'));

const existing = masterDb.prepare('SELECT id FROM companies WHERE LOWER(slug) = LOWER(?) LIMIT 1').get(slug);
if (existing) {
  console.error(`Já existe uma empresa com slug "${slug}".`);
  process.exit(1);
}

const tenantRelativePath = path.join('data', 'tenants', `${slug}.sqlite`);
const tenantAbsolutePath = path.join(ROOT, tenantRelativePath);

if (cloneFrom) {
  const source = masterDb.prepare('SELECT db_path FROM companies WHERE LOWER(slug) = LOWER(?) LIMIT 1').get(cloneFrom);
  if (!source) {
    console.error(`Empresa origem não encontrada: ${cloneFrom}`);
    process.exit(1);
  }
  const sourcePath = path.isAbsolute(source.db_path) ? source.db_path : path.join(ROOT, source.db_path);
  fs.copyFileSync(sourcePath, tenantAbsolutePath);
} else {
  const tenantDb = new DatabaseSync(tenantAbsolutePath);
  tenantDb.exec(fs.readFileSync(TENANT_SCHEMA_PATH, 'utf8'));
  tenantDb.prepare(`
    INSERT INTO app_settings (key, value, updated_at)
    VALUES ('company_name', ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
  `).run(name);
  tenantDb.close();
}

const result = masterDb.prepare(`
  INSERT INTO companies (slug, name, db_path, is_active, updated_at)
  VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
`).run(slug, name, tenantRelativePath);

masterDb.prepare(`
  INSERT INTO company_users (company_id, username, full_name, password_hash, role, is_active, updated_at)
  VALUES (?, ?, 'Administrador inicial', ?, 'adm', 1, CURRENT_TIMESTAMP)
`).run(result.lastInsertRowid, username, hashPassword(password));

console.log(JSON.stringify({
  ok: true,
  company: { id: Number(result.lastInsertRowid), name, slug, db_path: tenantRelativePath },
  admin: { username }
}, null, 2));
