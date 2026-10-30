require('dotenv').config();

const num = (v, d) => (v !== undefined && v !== '' ? Number(v) : d);

module.exports = {
  port: num(process.env.PORT, 3000),
  baseUrl: process.env.BASE_URL || `http://localhost:${num(process.env.PORT, 3000)}`,
  sessionSecret: process.env.SESSION_SECRET || 'dev-only-change-me-' + require('crypto').randomBytes(8).toString('hex'),
  isProd: process.env.NODE_ENV === 'production',
  dbPath: process.env.DB_PATH || './data/app.db',

  // Паролі
  bcryptRounds: num(process.env.BCRYPT_ROUNDS, 12),

  // Brute force (Завдання 4)
  maxFailedAttempts: num(process.env.MAX_FAILED_ATTEMPTS, 5),
  lockMinutes: num(process.env.LOCK_MINUTES, 15),

  // Терміни дії токенів (хвилини)
  activationTtlMin: num(process.env.ACTIVATION_TTL_MIN, 60 * 24),
  resetTtlMin: num(process.env.RESET_TTL_MIN, 30),

  // SMTP. Якщо SMTP_HOST порожній — листи виводяться в консоль і зберігаються в таблиці outbox
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: num(process.env.SMTP_PORT, 587),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.MAIL_FROM || 'Auth App <no-reply@localhost>',
  },

  // OpenID Connect (Завдання 6) — Google за замовчуванням
  oidc: {
    issuer: process.env.OIDC_ISSUER || 'https://accounts.google.com',
    clientId: process.env.OIDC_CLIENT_ID || '',
    clientSecret: process.env.OIDC_CLIENT_SECRET || '',
    redirectUri: process.env.OIDC_REDIRECT_URI || `${process.env.BASE_URL || 'http://localhost:' + num(process.env.PORT, 3000)}/auth/oidc/callback`,
    label: process.env.OIDC_LABEL || 'Google',
  },

  // Початковий адміністратор (створюється при першому запуску)
  admin: {
    email: (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase(),
    password: process.env.ADMIN_PASSWORD || 'Admin#12345',
  },
};
