const express = require('express');
const svgCaptcha = require('svg-captcha');
const { authenticator } = require('otplib');
const db = require('../db');
const config = require('../config');
const { validatePassword, hashPassword, verifyPassword } = require('../utils/password');
const { createToken, findValidToken, consumeToken } = require('../utils/tokens');
const rateLimit = require('../utils/rateLimit');
const { sendActivation } = require('../services/mailer');
const { logLogin } = require('../services/audit');
const guard = require('../services/loginGuard');
const { completeLogin, freshSession, save } = require('../services/session');
const { guestOnly, requireAuth } = require('../middleware/security');
const oidc = require('../services/oidc');
const { devMode } = require('../services/mailer');

authenticator.options = { window: 1 };

const router = express.Router();

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
const normEmail = (v) => String(v || '').trim().toLowerCase().slice(0, 254);

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 40, message: 'Забагато спроб входу з вашої адреси. Спробуйте за 15 хвилин.' });
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: 'Забагато реєстрацій з вашої адреси. Спробуйте пізніше.' });
const resendLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10 });

// ---------- CAPTCHA (Завдання 2) ----------
router.get('/captcha', (req, res) => {
  const captcha = svgCaptcha.create({ size: 5, noise: 4, color: true, ignoreChars: '0oO1ilIL', width: 160, height: 50 });
  req.session.captcha = { text: captcha.text.toLowerCase(), exp: Date.now() + 5 * 60 * 1000 };
  res.set({ 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
  res.send(captcha.data);
});

/** Перевірка CAPTCHA: одноразова, з обмеженим терміном дії. */
function checkCaptcha(req) {
  const c = req.session.captcha;
  delete req.session.captcha; // відповідь не можна використати вдруге
  const answer = String(req.body.captcha || '').trim().toLowerCase();
  return !!(c && c.exp > Date.now() && answer && answer === c.text);
}

// ---------- Реєстрація (Завдання 1) ----------
router.get('/register', guestOnly, (req, res) => {
  res.render('register', { title: 'Реєстрація', errors: [], values: {} });
});

router.post('/register', guestOnly, registerLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const password = String(req.body.password || '');
    const confirm = String(req.body.confirm || '');
    const errors = [];

    if (!EMAIL_RE.test(email)) errors.push('Вкажіть коректну адресу e-mail');
    errors.push(...validatePassword(password, email));
    if (password !== confirm) errors.push('Паролі не збігаються');
    if (!checkCaptcha(req)) errors.push('Невірна або прострочена CAPTCHA');

    if (errors.length) {
      return res.status(400).render('register', { title: 'Реєстрація', errors, values: { email } });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (!existing) {
      const hash = await hashPassword(password);
      const info = db.prepare('INSERT INTO users (email, password_hash, role, is_active, created_at) VALUES (?,?,?,0,?)')
        .run(email, hash, 'user', Date.now());
      const token = createToken(info.lastInsertRowid, 'activation', config.activationTtlMin);
      await sendActivation(email, token);
    }
    // Однакова відповідь для нових і існуючих адрес — не розкриваємо, хто зареєстрований.
    req.flash('success', 'Реєстрацію прийнято. Ми надіслали лист із посиланням для активації облікового запису.'
      + (devMode && !config.isProd ? ' (Режим розробки: лист дивіться в консолі сервера або на /dev/outbox)' : ''));
    res.redirect('/login');
  } catch (e) { next(e); }
});

// ---------- Активація (Завдання 3) ----------
// Важливо: маршрут /activate/resend має бути оголошений ДО /activate/:token
router.get('/activate/resend', (req, res) => res.render('resend', { title: 'Повторне надсилання активації' }));

router.get('/activate/:token', (req, res) => {
  const t = findValidToken(req.params.token, 'activation');
  if (!t || !consumeToken(t.id)) {
    req.flash('error', 'Посилання активації недійсне, вже використане або прострочене. Запросіть нове.');
    return res.redirect('/activate/resend');
  }
  db.prepare('UPDATE users SET is_active = 1 WHERE id = ?').run(t.user_id);
  req.flash('success', 'Обліковий запис активовано. Тепер ви можете увійти.');
  res.redirect('/login');
});

router.post('/activate/resend', resendLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (u && !u.is_active && !u.is_blocked) {
      await sendActivation(u.email, createToken(u.id, 'activation', config.activationTtlMin));
    }
    req.flash('success', 'Якщо обліковий запис існує і ще не активований, ми надіслали новий лист.');
    res.redirect('/login');
  } catch (e) { next(e); }
});

// ---------- Вхід (Завдання 1, 4) ----------
router.get('/login', guestOnly, (req, res) => {
  res.render('login', { title: 'Вхід', error: null, email: '', oidcEnabled: oidc.isConfigured(), oidcLabel: config.oidc.label });
});

router.post('/login', guestOnly, loginLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const password = String(req.body.password || '');
    const view = (error, status = 401) =>
      res.status(status).render('login', { title: 'Вхід', error, email, oidcEnabled: oidc.isConfigured(), oidcLabel: config.oidc.label });
    const generic = 'Невірний e-mail або пароль';

    const user = email ? db.prepare('SELECT * FROM users WHERE email = ?').get(email) : null;

    if (!user) {
      await verifyPassword(password, null); // вирівнюємо час відповіді
      logLogin(req, { email, success: false, reason: 'unknown_user' });
      return view(generic);
    }

    if (guard.isLocked(user)) {
      logLogin(req, { userId: user.id, email, success: false, reason: 'locked' });
      return view(`Забагато невдалих спроб. Вхід тимчасово заблоковано, спробуйте приблизно через ${guard.lockRemainingMin(user)} хв.`, 429);
    }

    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) {
      const r = guard.registerFailure(user);
      logLogin(req, { userId: user.id, email, success: false, reason: r.locked ? 'bad_password_locked' : 'bad_password' });
      if (r.locked) return view(`Забагато невдалих спроб. Вхід заблоковано на ${config.lockMinutes} хв.`, 429);
      return view(`${generic}. Залишилось спроб: ${r.remaining}`);
    }

    if (user.is_blocked) {
      logLogin(req, { userId: user.id, email, success: false, reason: 'blocked_by_admin' });
      return view('Обліковий запис заблоковано адміністратором.', 403);
    }
    if (!user.is_active) {
      logLogin(req, { userId: user.id, email, success: false, reason: 'not_activated' });
      return view('Обліковий запис не активовано. Перейдіть за посиланням з листа або запросіть новий лист на сторінці «Повторна активація».', 403);
    }

    if (user.totp_enabled) {
      await freshSession(req);
      req.session.pending2fa = { userId: user.id, at: Date.now() };
      await save(req);
      return res.redirect('/login/2fa');
    }

    await completeLogin(req, user, 'password');
    res.redirect('/profile');
  } catch (e) { next(e); }
});

// ---------- Другий фактор при вході (Завдання 5) ----------
function pending(req) {
  const p = req.session.pending2fa;
  if (!p || Date.now() - p.at > 5 * 60 * 1000) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(p.userId) || null;
}

router.get('/login/2fa', guestOnly, (req, res) => {
  if (!pending(req)) { req.flash('error', 'Сесію входу завершено. Увійдіть ще раз.'); return res.redirect('/login'); }
  res.render('login_2fa', { title: 'Двофакторна автентифікація', error: null });
});

router.post('/login/2fa', guestOnly, loginLimiter, async (req, res, next) => {
  try {
    const user = pending(req);
    if (!user) { req.flash('error', 'Сесію входу завершено. Увійдіть ще раз.'); return res.redirect('/login'); }

    if (guard.isLocked(user)) {
      delete req.session.pending2fa;
      req.flash('error', 'Забагато невдалих спроб. Вхід тимчасово заблоковано.');
      return res.redirect('/login');
    }
    if (user.is_blocked) {
      delete req.session.pending2fa;
      req.flash('error', 'Обліковий запис заблоковано адміністратором.');
      return res.redirect('/login');
    }

    const code = String(req.body.code || '').replace(/\s/g, '');
    if (/^\d{6}$/.test(code) && authenticator.check(code, user.totp_secret)) {
      await completeLogin(req, user, '2fa');
      return res.redirect('/profile');
    }

    const r = guard.registerFailure(user);
    logLogin(req, { userId: user.id, email: user.email, success: false, reason: r.locked ? 'bad_2fa_locked' : 'bad_2fa', method: '2fa' });
    if (r.locked) {
      delete req.session.pending2fa;
      req.flash('error', `Забагато невдалих спроб. Вхід заблоковано на ${config.lockMinutes} хв.`);
      return res.redirect('/login');
    }
    res.status(401).render('login_2fa', { title: 'Двофакторна автентифікація', error: `Невірний код. Залишилось спроб: ${r.remaining}` });
  } catch (e) { next(e); }
});

// ---------- Вихід ----------
router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.redirect('/login');
  });
});

module.exports = router;
