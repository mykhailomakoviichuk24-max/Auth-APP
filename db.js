const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const config = require('./config');

fs.mkdirSync(path.dirname(path.resolve(config.dbPath)), { recursive: true });
const db = new Database(path.resolve(config.dbPath));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash   TEXT,                              -- NULL для користувачів, що увійшли лише через OIDC
  role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  is_active       INTEGER NOT NULL DEFAULT 0,        -- активація e-mail (Завдання 3)
  is_blocked      INTEGER NOT NULL DEFAULT 0,        -- ручне блокування адміном (Завдання 4)
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until    INTEGER,                           -- тимчасове блокування brute force (ms epoch)
  totp_secret     TEXT,
  totp_enabled    INTEGER NOT NULL DEFAULT 0,
  oidc_sub        TEXT UNIQUE,
  created_at      INTEGER NOT NULL,
  last_login_at   INTEGER
);

-- Одноразові токени: activation | reset. Зберігається лише SHA-256 хеш токена.
CREATE TABLE IF NOT EXISTS tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type        TEXT NOT NULL CHECK (type IN ('activation','reset')),
  token_hash  TEXT NOT NULL UNIQUE,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);

-- Журнал спроб входу (Завдання 4)
CREATE TABLE IF NOT EXISTS login_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
  email      TEXT NOT NULL,
  ip         TEXT,
  user_agent TEXT,
  success    INTEGER NOT NULL,
  reason     TEXT,
  method     TEXT NOT NULL DEFAULT 'password',       -- password | 2fa | oidc
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_log_email ON login_log(email);
CREATE INDEX IF NOT EXISTS idx_login_log_created ON login_log(created_at);

-- Журнал дій адміністраторів
CREATE TABLE IF NOT EXISTS admin_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  target_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action     TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Вихідні листи (режим розробки, коли SMTP не налаштований)
CREATE TABLE IF NOT EXISTS outbox (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  to_email   TEXT NOT NULL,
  subject    TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  sid     TEXT PRIMARY KEY,
  data    TEXT NOT NULL,
  expires INTEGER NOT NULL
);
`);

// Початковий адміністратор
function seedAdmin() {
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(config.admin.email);
  if (exists) return;
  const hash = bcrypt.hashSync(config.admin.password, config.bcryptRounds);
  db.prepare(
    `INSERT INTO users (email, password_hash, role, is_active, created_at)
     VALUES (?, ?, 'admin', 1, ?)`
  ).run(config.admin.email, hash, Date.now());
  console.log(`[seed] Створено адміністратора ${config.admin.email}`);
}
seedAdmin();

module.exports = db;
