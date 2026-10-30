const express = require('express');
const QRCode = require('qrcode');
const { authenticator } = require('otplib');
const db = require('../db');
const { requireAuth } = require('../middleware/security');

authenticator.options = { window: 1 };
const router = express.Router();

// RBAC: користувач бачить лише власні дані (id береться з сесії, а не з URL/форми)
router.get('/profile', requireAuth, (req, res) => {
  res.render('profile', { title: 'Профіль' });
});

// ---------- Налаштування 2FA (TOTP) ----------
router.get('/profile/2fa', requireAuth, async (req, res, next) => {
  try {
    if (req.user.totp_enabled) return res.render('twofa', { title: 'Двофакторна автентифікація', enabled: true });
    const secret = authenticator.generateSecret();
    req.session.pendingTotpSecret = secret;
    const uri = authenticator.keyuri(req.user.email, 'AuthApp', secret);
    const qr = await QRCode.toDataURL(uri, { margin: 1, width: 220 });
    res.render('twofa', { title: 'Двофакторна автентифікація', enabled: false, qr, secret });
  } catch (e) { next(e); }
});

router.post('/profile/2fa/enable', requireAuth, (req, res) => {
  const secret = req.session.pendingTotpSecret;
  const code = String(req.body.code || '').replace(/\s/g, '');
  if (req.user.totp_enabled || !secret) return res.redirect('/profile/2fa');
  if (!/^\d{6}$/.test(code) || !authenticator.check(code, secret)) {
    req.flash('error', 'Невірний код. Перевірте час на телефоні та спробуйте ще раз.');
    return res.redirect('/profile/2fa');
  }
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').run(secret, req.user.id);
  delete req.session.pendingTotpSecret;
  req.flash('success', 'Двофакторну автентифікацію увімкнено.');
  res.redirect('/profile');
});

router.post('/profile/2fa/disable', requireAuth, (req, res) => {
  const code = String(req.body.code || '').replace(/\s/g, '');
  if (!req.user.totp_enabled) return res.redirect('/profile');
  if (!/^\d{6}$/.test(code) || !authenticator.check(code, req.user.totp_secret)) {
    req.flash('error', 'Невірний код — 2FA не вимкнено.');
    return res.redirect('/profile/2fa');
  }
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').run(req.user.id);
  req.flash('success', 'Двофакторну автентифікацію вимкнено.');
  res.redirect('/profile');
});

module.exports = router;
