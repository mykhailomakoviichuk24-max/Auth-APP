// Панель адміністратора (RBAC: лише роль admin)
const express = require('express');
const db = require('../db');
const { requireRole } = require('../middleware/security');
const { logAdmin } = require('../services/audit');
const { destroyUserSessions } = require('../services/session');

const router = express.Router();
router.use('/admin', requireRole('admin'));

router.get('/admin', (req, res) => res.redirect('/admin/users'));

// Список користувачів та їх статус
router.get('/admin/users', (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 100);
  const users = db.prepare(
    `SELECT u.*,
            (SELECT COUNT(*) FROM login_log l WHERE l.email = u.email AND l.success = 0) AS failed_total
       FROM users u
      WHERE u.email LIKE ? ESCAPE '\\'
      ORDER BY u.created_at DESC
      LIMIT 500`
  ).all(`%${q.replace(/[%_\\]/g, '\\$&')}%`);
  res.render('admin_users', { title: 'Користувачі', users, q, now: Date.now() });
});

function target(req, res) {
  const id = Number(req.params.id);
  const u = Number.isInteger(id) ? db.prepare('SELECT * FROM users WHERE id = ?').get(id) : null;
  if (!u) { req.flash('error', 'Користувача не знайдено.'); res.redirect('/admin/users'); return null; }
  return u;
}

router.post('/admin/users/:id/block', (req, res) => {
  const u = target(req, res); if (!u) return;
  if (u.id === req.user.id) { req.flash('error', 'Не можна заблокувати власний обліковий запис.'); return res.redirect('/admin/users'); }
  if (u.role === 'admin') { req.flash('error', 'Адміністраторів блокувати не можна.'); return res.redirect('/admin/users'); }
  db.prepare('UPDATE users SET is_blocked = 1 WHERE id = ?').run(u.id);
  destroyUserSessions(u.id);
  logAdmin(req.user.id, u.id, 'block');
  req.flash('success', `Обліковий запис ${u.email} заблоковано.`);
  res.redirect('/admin/users');
});

router.post('/admin/users/:id/unblock', (req, res) => {
  const u = target(req, res); if (!u) return;
  // Розблокування знімає і ручне блокування, і тимчасове (brute force)
  db.prepare('UPDATE users SET is_blocked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?').run(u.id);
  logAdmin(req.user.id, u.id, 'unblock');
  req.flash('success', `Обліковий запис ${u.email} розблоковано.`);
  res.redirect('/admin/users');
});

// Журнал входів: підсумок «хто і скільки разів» + детальний список
router.get('/admin/logs', (req, res) => {
  const email = String(req.query.email || '').trim().toLowerCase().slice(0, 254);
  const status = ['ok', 'fail'].includes(req.query.status) ? req.query.status : '';
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const perPage = 50;

  const summary = db.prepare(
    `SELECT email,
            COUNT(*)                               AS attempts,
            SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failures,
            SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS successes,
            MAX(created_at)                        AS last_at,
            (SELECT ip FROM login_log x WHERE x.email = l.email ORDER BY created_at DESC LIMIT 1) AS last_ip
       FROM login_log l
      GROUP BY email
      ORDER BY failures DESC, last_at DESC
      LIMIT 100`
  ).all();

  const where = [];
  const args = [];
  if (email) { where.push("email LIKE ? ESCAPE '\\'"); args.push(`%${email.replace(/[%_\\]/g, '\\$&')}%`); }
  if (status) { where.push('success = ?'); args.push(status === 'ok' ? 1 : 0); }
  const clause = where.length ? 'WHERE ' + where.join(' AND ') : '';

  const total = db.prepare(`SELECT COUNT(*) AS c FROM login_log ${clause}`).get(...args).c;
  const rows = db.prepare(`SELECT * FROM login_log ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`)
    .all(...args, perPage, (page - 1) * perPage);

  const actions = db.prepare(
    `SELECT a.*, adm.email AS admin_email, t.email AS target_email
       FROM admin_log a
       LEFT JOIN users adm ON adm.id = a.admin_id
       LEFT JOIN users t ON t.id = a.target_id
      ORDER BY a.id DESC LIMIT 20`
  ).all();

  res.render('admin_logs', {
    title: 'Журнал входів', summary, rows, actions, email, status,
    page, pages: Math.max(1, Math.ceil(total / perPage)), total,
  });
});

module.exports = router;
