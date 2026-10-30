const crypto = require('crypto');
const db = require('../db');

/** CSRF: токен у сесії + приховане поле _csrf у кожній формі (синхронізований токен). */
function csrf(req, res, next) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  res.locals.csrfToken = req.session.csrf;

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const sent = String((req.body && req.body._csrf) || '');
    const real = req.session.csrf;
    const ok = sent.length === real.length && crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(real));
    if (!ok) {
      res.status(403);
      return res.render('error', { title: 'Помилка безпеки', message: 'Недійсний CSRF-токен. Оновіть сторінку та спробуйте ще раз.' });
    }
  }
  next();
}

/** Flash-повідомлення (одноразові) */
function flash(req, res, next) {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  req.flash = (type, text) => { req.session.flash = { type, text }; };
  next();
}

/** Підвантажує поточного користувача з БД на кожен запит (блокування діє миттєво). */
function loadUser(req, res, next) {
  res.locals.currentUser = null;
  req.user = null;
  if (req.session.userId) {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
    if (!u || u.is_blocked) {
      req.session.destroy(() => {});
      return next();
    }
    req.user = u;
    res.locals.currentUser = u;
  }
  next();
}

/** RBAC: доступ лише для автентифікованих. */
function requireAuth(req, res, next) {
  if (!req.user) {
    req.flash('error', 'Увійдіть, щоб продовжити.');
    return res.redirect('/login');
  }
  next();
}

/** RBAC: доступ лише для вказаних ролей. */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      req.flash('error', 'Увійдіть, щоб продовжити.');
      return res.redirect('/login');
    }
    if (!roles.includes(req.user.role)) {
      res.status(403);
      return res.render('error', { title: 'Доступ заборонено', message: 'У вас немає прав для перегляду цієї сторінки.' });
    }
    next();
  };
}

function guestOnly(req, res, next) {
  if (req.user) return res.redirect('/profile');
  next();
}

module.exports = { csrf, flash, loadUser, requireAuth, requireRole, guestOnly };
