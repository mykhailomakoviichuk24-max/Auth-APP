const db = require('../db');

function logLogin(req, { userId = null, email, success, reason = null, method = 'password' }) {
  db.prepare(
    `INSERT INTO login_log (user_id, email, ip, user_agent, success, reason, method, created_at)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(
    userId,
    String(email || '').slice(0, 254).toLowerCase(),
    req.ip || null,
    String(req.get('user-agent') || '').slice(0, 300),
    success ? 1 : 0,
    reason,
    method,
    Date.now()
  );
}

function logAdmin(adminId, targetId, action) {
  db.prepare('INSERT INTO admin_log (admin_id, target_id, action, created_at) VALUES (?,?,?,?)')
    .run(adminId, targetId, action, Date.now());
}

module.exports = { logLogin, logAdmin };
