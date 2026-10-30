// Вхід через OpenID Connect (Завдання 6)
const express = require('express');
const { generators } = require('openid-client');
const db = require('../db');
const config = require('../config');
const oidc = require('../services/oidc');
const { logLogin } = require('../services/audit');
const { completeLogin } = require('../services/session');
const { guestOnly } = require('../middleware/security');

const router = express.Router();

router.get('/auth/oidc', guestOnly, async (req, res) => {
  if (!oidc.isConfigured()) {
    req.flash('error', 'Вхід через зовнішній провайдер не налаштовано (див. OIDC_* у .env).');
    return res.redirect('/login');
  }
  try {
    const client = await oidc.getClient();
    const state = generators.state();
    const nonce = generators.nonce();
    const verifier = generators.codeVerifier();
    req.session.oidc = { state, nonce, verifier };
    const url = client.authorizationUrl({
      scope: 'openid email profile',
      state,
      nonce,
      code_challenge: generators.codeChallenge(verifier),
      code_challenge_method: 'S256',
    });
    res.redirect(url);
  } catch (e) {
    console.error('[oidc] discovery/start error:', e.message);
    req.flash('error', 'Не вдалося зв\'язатися з провайдером автентифікації.');
    res.redirect('/login');
  }
});

router.get('/auth/oidc/callback', guestOnly, async (req, res) => {
  const saved = req.session.oidc;
  delete req.session.oidc;
  const fail = (msg, email = 'oidc') => {
    logLogin(req, { email, success: false, reason: 'oidc_failed', method: 'oidc' });
    req.flash('error', msg);
    res.redirect('/login');
  };

  if (!saved || !oidc.isConfigured()) return fail('Сесію OIDC втрачено. Спробуйте ще раз.');

  try {
    const client = await oidc.getClient();
    const params = client.callbackParams(req);
    // Перевіряє state, nonce, підпис id_token, issuer, audience, PKCE
    const tokenSet = await client.callback(config.oidc.redirectUri, params, {
      state: saved.state,
      nonce: saved.nonce,
      code_verifier: saved.verifier,
    });
    const claims = tokenSet.claims();
    const email = String(claims.email || '').toLowerCase();
    if (!email || claims.email_verified === false) {
      return fail('Провайдер не підтвердив вашу адресу e-mail.', email || 'oidc');
    }

    // 1) за ідентифікатором провайдера; 2) за підтвердженим e-mail; 3) новий користувач
    let user = db.prepare('SELECT * FROM users WHERE oidc_sub = ?').get(claims.sub);
    if (!user) {
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (user) {
        if (!user.is_active) {
          // Акаунт зареєстровано, але e-mail не підтверджено: власник адреси тепер підтверджений провайдером.
          // Скидаємо пароль, щоб той, хто «зайняв» чужу адресу при реєстрації, не зберіг доступ.
          db.prepare('UPDATE users SET oidc_sub = ?, is_active = 1, password_hash = NULL WHERE id = ?').run(claims.sub, user.id);
        } else {
          db.prepare('UPDATE users SET oidc_sub = ? WHERE id = ?').run(claims.sub, user.id);
        }
      } else {
        const info = db.prepare(
          `INSERT INTO users (email, password_hash, role, is_active, oidc_sub, created_at) VALUES (?, NULL, 'user', 1, ?, ?)`
        ).run(email, claims.sub, Date.now());
        user = { id: info.lastInsertRowid };
      }
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    }

    if (user.is_blocked) {
      logLogin(req, { userId: user.id, email: user.email, success: false, reason: 'blocked_by_admin', method: 'oidc' });
      req.flash('error', 'Обліковий запис заблоковано адміністратором.');
      return res.redirect('/login');
    }

    await completeLogin(req, user, 'oidc');
    res.redirect('/profile');
  } catch (e) {
    console.error('[oidc] callback error:', e.message);
    fail('Помилка входу через провайдера. Спробуйте ще раз.');
  }
});

module.exports = router;
