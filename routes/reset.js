// Відновлення пароля через e-mail (Завдання 7)
const express = require('express');
const db = require('../db');
const config = require('../config');
const { validatePassword, hashPassword } = require('../utils/password');
const { createToken, findValidToken, consumeToken } = require('../utils/tokens');
const rateLimit = require('../utils/rateLimit');
const { sendReset } = require('../services/mailer');
const { destroyUserSessions } = require('../services/session');
const { guestOnly } = require('../middleware/security');
const { devMode } = require('../services/mailer');

const router = express.Router();
const limiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10 });

router.get('/forgot', guestOnly, (req, res) => res.render('forgot', { title: 'Відновлення пароля' }));

router.post('/forgot', guestOnly, limiter, async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase().slice(0, 254);
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (user && !user.is_blocked) {
      await sendReset(user.email, createToken(user.id, 'reset', config.resetTtlMin));
    }
    // Однакова відповідь незалежно від того, чи існує адреса
    req.flash('success', `Якщо така адреса зареєстрована, ми надіслали лист із посиланням для відновлення (дійсне ${config.resetTtlMin} хв).`
      + (devMode && !config.isProd ? ' (Режим розробки: лист у консолі сервера або на /dev/outbox)' : ''));
    res.redirect('/login');
  } catch (e) { next(e); }
});

router.get('/reset/:token', (req, res) => {
  if (!findValidToken(req.params.token, 'reset')) {
    req.flash('error', 'Посилання недійсне, вже використане або прострочене. Запросіть нове.');
    return res.redirect('/forgot');
  }
  res.render('reset', { title: 'Новий пароль', token: req.params.token, errors: [] });
});

router.post('/reset/:token', limiter, async (req, res, next) => {
  try {
    const t = findValidToken(req.params.token, 'reset');
    if (!t) {
      req.flash('error', 'Посилання недійсне, вже використане або прострочене. Запросіть нове.');
      return res.redirect('/forgot');
    }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(t.user_id);
    const password = String(req.body.password || '');
    const errors = validatePassword(password, user.email);
    if (password !== String(req.body.confirm || '')) errors.push('Паролі не збігаються');
    if (errors.length) {
      return res.status(400).render('reset', { title: 'Новий пароль', token: req.params.token, errors });
    }

    if (!consumeToken(t.id)) { // захист від гонки: токен одноразовий
      req.flash('error', 'Посилання вже використано.');
      return res.redirect('/forgot');
    }
    const hash = await hashPassword(password);
    // Доступ до пошти підтверджено → активуємо акаунт і знімаємо тимчасове блокування
    db.prepare('UPDATE users SET password_hash = ?, is_active = 1, failed_attempts = 0, locked_until = NULL WHERE id = ?')
      .run(hash, user.id);
    destroyUserSessions(user.id); // усі старі сесії стають недійсними
    req.flash('success', 'Пароль змінено. Увійдіть з новим паролем.');
    res.redirect('/login');
  } catch (e) { next(e); }
});

module.exports = router;
