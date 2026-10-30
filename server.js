const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const config = require('./config');
const db = require('./db');
const SQLiteStore = require('./middleware/sessionStore');
const { csrf, flash, loadUser } = require('./middleware/security');
const { purgeExpired } = require('./utils/tokens');
const mailer = require('./services/mailer');

const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'img-src': ["'self'", 'data:'],
        'script-src': ["'self'"],
        'upgrade-insecure-requests': config.isProd ? [] : null,
      },
    },
    hsts: config.isProd,
  })
);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(
  session({
    name: 'sid',
    secret: config.sessionSecret,
    store: new SQLiteStore(),
    resave: false,
    saveUninitialized: true, // потрібно для CAPTCHA та CSRF до входу
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: config.isProd,
      maxAge: 2 * 60 * 60 * 1000, // 2 години неактивності
    },
  })
);
app.use(flash);
app.use(loadUser); // перед csrf, щоб сторінка помилки CSRF мала доступ до currentUser
app.use(csrf);
app.use((req, res, next) => {
  res.locals.path = req.path;
  next();
});

app.get('/', (req, res) => (req.user ? res.redirect('/profile') : res.render('index', { title: 'Головна' })));

app.use(require('./routes/auth'));
app.use(require('./routes/reset'));
app.use(require('./routes/oidc'));
app.use(require('./routes/profile'));
app.use(require('./routes/admin'));

// Перегляд «надісланих» листів у режимі розробки (коли SMTP не налаштований)
if (mailer.devMode && !config.isProd) {
  app.get('/dev/outbox', (req, res) => {
    const mails = db.prepare('SELECT * FROM outbox ORDER BY id DESC LIMIT 20').all();
    res.render('outbox', { title: 'Dev outbox', mails });
  });
}

app.use((req, res) => {
  res.status(404).render('error', { title: '404', message: 'Сторінку не знайдено.' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', { title: 'Помилка', message: 'Внутрішня помилка сервера.' });
});

purgeExpired();
setInterval(purgeExpired, 60 * 60 * 1000).unref();

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`Сервер запущено: ${config.baseUrl}`);
    if (config.sessionSecret.startsWith('dev-only')) console.warn('[!] SESSION_SECRET не задано — використано тимчасовий ключ');
  });
}

module.exports = app;
