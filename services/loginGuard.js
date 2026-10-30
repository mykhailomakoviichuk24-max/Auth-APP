// Захист від Brute Force (Завдання 4): лічильник невдалих спроб + тимчасове блокування.
const db = require('../db');
const config = require('../config');

function isLocked(user) {
  return !!(user.locked_until && user.locked_until > Date.now());
}

function lockRemainingMin(user) {
  return Math.max(1, Math.ceil((user.locked_until - Date.now()) / 60000));
}

/** Реєструє невдалу спробу. Повертає { locked, remaining }. */
function registerFailure(user) {
  const attempts = user.failed_attempts + 1;
  if (attempts >= config.maxFailedAttempts) {
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?')
      .run(Date.now() + config.lockMinutes * 60000, user.id);
    return { locked: true, remaining: 0 };
  }
  db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(attempts, user.id);
  return { locked: false, remaining: config.maxFailedAttempts - attempts };
}

function registerSuccess(userId) {
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?')
    .run(Date.now(), userId);
}

module.exports = { isLocked, lockRemainingMin, registerFailure, registerSuccess };
