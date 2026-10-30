const session = require('express-session');
const db = require('../db');

// Мінімальне сховище сесій у SQLite (без додаткових залежностей).
class SQLiteStore extends session.Store {
  get(sid, cb) {
    try {
      const row = db.prepare('SELECT data, expires FROM sessions WHERE sid = ?').get(sid);
      if (!row) return cb(null, null);
      if (row.expires < Date.now()) {
        db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
        return cb(null, null);
      }
      cb(null, JSON.parse(row.data));
    } catch (e) { cb(e); }
  }

  set(sid, sess, cb) {
    try {
      const expires = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      db.prepare('INSERT INTO sessions (sid, data, expires) VALUES (?,?,?) ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires')
        .run(sid, JSON.stringify(sess), expires);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }

  destroy(sid, cb) {
    try {
      db.prepare('DELETE FROM sessions WHERE sid = ?').run(sid);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }

  touch(sid, sess, cb) {
    try {
      const expires = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      db.prepare('UPDATE sessions SET expires = ? WHERE sid = ?').run(expires, sid);
      cb && cb(null);
    } catch (e) { cb && cb(e); }
  }
}

module.exports = SQLiteStore;
