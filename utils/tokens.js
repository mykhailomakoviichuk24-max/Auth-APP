const crypto = require('crypto');
const db = require('../db');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/**
 * Створює одноразовий токен (32 випадкові байти). У БД зберігається лише SHA-256 хеш,
 * тож витік бази не дає змоги скористатися посиланнями. Попередні невикористані токени
 * цього типу для користувача анулюються.
 */
function createToken(userId, type, ttlMinutes) {
  const raw = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('DELETE FROM tokens WHERE user_id = ? AND type = ? AND used_at IS NULL').run(userId, type);
  db.prepare('INSERT INTO tokens (user_id, type, token_hash, expires_at) VALUES (?,?,?,?)')
    .run(userId, type, sha256(raw), now + ttlMinutes * 60 * 1000);
  return raw;
}

/** Повертає запис токена, якщо він дійсний (не використаний, не прострочений). */
function findValidToken(raw, type) {
  if (typeof raw !== 'string' || !/^[a-f0-9]{64}$/.test(raw)) return null;
  const row = db.prepare('SELECT * FROM tokens WHERE token_hash = ? AND type = ?').get(sha256(raw), type);
  if (!row || row.used_at || row.expires_at < Date.now()) return null;
  return row;
}

/** Атомарно позначає токен використаним; false, якщо його вже використали. */
function consumeToken(id) {
  return db.prepare('UPDATE tokens SET used_at = ? WHERE id = ? AND used_at IS NULL').run(Date.now(), id).changes === 1;
}

function purgeExpired() {
  db.prepare('DELETE FROM tokens WHERE expires_at < ? OR used_at IS NOT NULL AND used_at < ?')
    .run(Date.now() - 24 * 3600 * 1000, Date.now() - 24 * 3600 * 1000);
  db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now());
}

module.exports = { createToken, findValidToken, consumeToken, purgeExpired };
