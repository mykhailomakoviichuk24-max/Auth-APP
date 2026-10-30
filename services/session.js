const db = require('../db');
const { logLogin } = require('./audit');
const { registerSuccess } = require('./loginGuard');

const regenerate = (req) => new Promise((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve())));
const save = (req) => new Promise((resolve, reject) => req.session.save((e) => (e ? reject(e) : resolve())));

/** Новий ідентифікатор сесії (захист від session fixation). */
async function freshSession(req) {
  await regenerate(req);
}

/** Завершує вхід: нова сесія, скидання лічильників, запис у журнал. */
async function completeLogin(req, user, method = 'password') {
  await regenerate(req);
  req.session.userId = user.id;
  registerSuccess(user.id);
  logLogin(req, { userId: user.id, email: user.email, success: true, method });
  await save(req);
}

/** Видаляє всі сесії користувача (після блокування або зміни пароля). */
function destroyUserSessions(userId) {
  db.prepare("DELETE FROM sessions WHERE json_extract(data, '$.userId') = ?").run(userId);
}

module.exports = { freshSession, completeLogin, destroyUserSessions, save };
