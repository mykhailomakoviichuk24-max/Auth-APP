const nodemailer = require('nodemailer');
const config = require('../config');
const db = require('../db');

const transport = config.smtp.host
  ? nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
    })
  : null;

const devMode = !transport;

async function sendMail(to, subject, text) {
  if (!transport) {
    // Режим розробки: друкуємо в консоль і зберігаємо в outbox (видно на /dev/outbox)
    db.prepare('INSERT INTO outbox (to_email, subject, body, created_at) VALUES (?,?,?,?)').run(to, subject, text, Date.now());
    console.log(`\n--- [MAIL → ${to}] ${subject}\n${text}\n---\n`);
    return;
  }
  await transport.sendMail({ from: config.smtp.from, to, subject, text });
}

async function sendActivation(email, rawToken) {
  const link = `${config.baseUrl}/activate/${rawToken}`;
  await sendMail(
    email,
    'Активація облікового запису',
    `Вітаємо!\n\nЩоб активувати обліковий запис, перейдіть за посиланням (дійсне ${config.activationTtlMin} хв, одноразове):\n${link}\n\nЯкщо ви не реєструвалися — просто проігноруйте цей лист.`
  );
}

async function sendReset(email, rawToken) {
  const link = `${config.baseUrl}/reset/${rawToken}`;
  await sendMail(
    email,
    'Відновлення пароля',
    `Ми отримали запит на відновлення пароля.\n\nПосилання (дійсне ${config.resetTtlMin} хв, одноразове):\n${link}\n\nЯкщо це були не ви — проігноруйте лист, пароль залишиться без змін.`
  );
}

module.exports = { sendActivation, sendReset, devMode };
