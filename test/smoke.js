// Наскрізний тест (HTTP + тимчасова БД). Запуск: npm test
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const PORT = 3999;
const DB = path.join(__dirname, '..', 'data', 'test.db');
for (const f of [DB, DB + '-wal', DB + '-shm']) if (fs.existsSync(f)) fs.unlinkSync(f);

Object.assign(process.env, {
  DB_PATH: DB, PORT: String(PORT), BASE_URL: `http://localhost:${PORT}`, BCRYPT_ROUNDS: '4',
  MAX_FAILED_ATTEMPTS: '3', LOCK_MINUTES: '15', SMTP_HOST: '', NODE_ENV: 'test',
  ADMIN_EMAIL: 'admin@test.local', ADMIN_PASSWORD: 'Admin#12345', SESSION_SECRET: 'test-secret',
});

const app = require('../server');
const db = require('../db');
const BASE = `http://localhost:${PORT}`;

class Client {
  constructor() { this.cookie = ''; }
  async req(method, url, form) {
    const headers = {};
    if (this.cookie) headers.cookie = this.cookie;
    let body;
    if (form) { headers['content-type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form).toString(); }
    const r = await fetch(BASE + url, { method, headers, body, redirect: 'manual' });
    for (const c of r.headers.getSetCookie()) {
      const kv = c.split(';')[0];
      const name = kv.split('=')[0];
      this.cookie = this.cookie.split('; ').filter((x) => x && !x.startsWith(name + '=')).concat(kv).join('; ');
    }
    return { status: r.status, loc: r.headers.get('location'), text: await r.text() };
  }
  get(url) { return this.req('GET', url); }
  async post(url, form, csrfFrom) {
    const page = await this.get(csrfFrom || url);
    const m = /name="_csrf" value="([^"]+)"/.exec(page.text);
    assert(m, 'CSRF-токен не знайдено на ' + (csrfFrom || url));
    return this.req('POST', url, { _csrf: m[1], ...form });
  }
}

const captchaText = () =>
  db.prepare("SELECT json_extract(data,'$.captcha.text') AS t FROM sessions WHERE json_extract(data,'$.captcha.text') IS NOT NULL ORDER BY rowid DESC LIMIT 1").get().t;
const lastToken = (email, kind) => {
  const m = db.prepare('SELECT body FROM outbox WHERE to_email = ? ORDER BY id DESC').all(email)
    .map((r) => new RegExp(`/${kind}/([a-f0-9]{64})`).exec(r.body)).find(Boolean);
  return m && m[1];
};

async function register(email, password) {
  const c = new Client();
  await c.get('/captcha');
  const res = await c.post('/register', { email, password, confirm: password, captcha: captchaText() }, '/register');
  return { c, res };
}

let n = 0;
const ok = (name) => console.log(`  ✓ ${++n}. ${name}`);

(async () => {
  const server = app.listen(PORT);
  const USER = 'user@test.local';
  const PASS = 'Str0ng#Pass!';
  try {
    // --- Завдання 1: політика пароля
    const c0 = new Client();
    await c0.get('/captcha');
    let r = await c0.post('/register', { email: USER, password: 'weak', confirm: 'weak', captcha: captchaText() }, '/register');
    assert.strictEqual(r.status, 400);
    assert(r.text.includes('щонайменше 8 символів'));
    ok('слабкий пароль відхилено');

    for (const bad of ['alllowercase1!', 'ALLUPPERCASE1!', 'NoDigits!!', 'NoSymbol123A']) {
      const x = new Client(); await x.get('/captcha');
      const rr = await x.post('/register', { email: USER, password: bad, confirm: bad, captcha: captchaText() }, '/register');
      assert.strictEqual(rr.status, 400, 'має відхилити ' + bad);
    }
    ok('політика пароля: літери/цифра/символ обов\'язкові');

    // --- Завдання 2: CAPTCHA
    const c1 = new Client(); await c1.get('/captcha');
    r = await c1.post('/register', { email: USER, password: PASS, confirm: PASS, captcha: 'zzzzz' }, '/register');
    assert.strictEqual(r.status, 400);
    assert(r.text.includes('CAPTCHA'));
    ok('невірна CAPTCHA відхилена');

    // --- реєстрація + хеш у БД
    const reg = await register(USER, PASS);
    assert.strictEqual(reg.res.status, 302);
    const row = db.prepare('SELECT * FROM users WHERE email = ?').get(USER);
    assert(row && row.password_hash.startsWith('$2') && !row.password_hash.includes(PASS));
    assert.strictEqual(row.is_active, 0);
    ok('користувача створено, пароль захешовано bcrypt');

    // --- Завдання 3: активація
    const u = new Client();
    r = await u.post('/login', { email: USER, password: PASS }, '/login');
    assert.strictEqual(r.status, 403);
    ok('вхід без активації заборонено');

    const tok = lastToken(USER, 'activate');
    assert(tok, 'лист з токеном має бути в outbox');
    assert(!db.prepare('SELECT 1 FROM tokens WHERE token_hash = ?').get(tok), 'у БД не має бути сирого токена');
    r = await u.get('/activate/' + tok);
    assert.strictEqual(r.status, 302);
    assert.strictEqual(db.prepare('SELECT is_active FROM users WHERE email = ?').get(USER).is_active, 1);
    r = await u.get('/activate/' + tok);
    assert.strictEqual(r.loc, '/activate/resend');
    ok('активація токеном; повторне використання неможливе');

    db.prepare("UPDATE tokens SET expires_at = 1 WHERE type = 'activation'").run();
    r = await u.get('/activate/' + 'a'.repeat(64));
    assert.strictEqual(r.loc, '/activate/resend');
    ok('невідомий/прострочений токен відхиляється');

    // --- вхід, профіль, вихід
    r = await u.post('/login', { email: USER, password: PASS }, '/login');
    assert.strictEqual(r.status, 302); assert.strictEqual(r.loc, '/profile');
    r = await u.get('/profile');
    assert.strictEqual(r.status, 200); assert(r.text.includes('Активовано'));
    ok('вхід успішний, профіль показує статус активації');

    // --- RBAC
    r = await u.get('/admin/users'); assert.strictEqual(r.status, 403);
    r = await u.get('/admin/logs'); assert.strictEqual(r.status, 403);
    r = await u.req('POST', '/admin/users/1/block', { _csrf: 'x' }); assert.strictEqual(r.status, 403);
    r = await new Client().get('/profile'); assert.strictEqual(r.loc, '/login');
    r = await new Client().get('/admin/users'); assert.strictEqual(r.loc, '/login');
    ok('RBAC: користувач не має доступу до /admin, анонім — на /login');

    // --- CSRF
    r = await new Client().req('POST', '/login', { email: USER, password: PASS });
    assert.strictEqual(r.status, 403);
    ok('POST без CSRF-токена відхиляється');

    r = await u.post('/logout', {}, '/profile');
    assert.strictEqual(r.loc, '/login');
    r = await u.get('/profile'); assert.strictEqual(r.loc, '/login');
    ok('вихід з системи');

    // --- Завдання 4: brute force
    const b = new Client();
    r = await b.post('/login', { email: USER, password: 'Wrong#Pass1' }, '/login'); assert.strictEqual(r.status, 401);
    r = await b.post('/login', { email: USER, password: 'Wrong#Pass2' }, '/login'); assert.strictEqual(r.status, 401);
    r = await b.post('/login', { email: USER, password: 'Wrong#Pass3' }, '/login'); assert.strictEqual(r.status, 429);
    r = await b.post('/login', { email: USER, password: PASS }, '/login');
    assert.strictEqual(r.status, 429, 'навіть правильний пароль під час блокування відхиляється');
    ok('brute force: блокування після 3 невдалих спроб');

    // --- Адмін: журнал, блокування/розблокування
    const a = new Client();
    r = await a.post('/login', { email: 'admin@test.local', password: 'Admin#12345' }, '/login');
    assert.strictEqual(r.loc, '/profile');
    r = await a.get('/admin/users'); assert.strictEqual(r.status, 200); assert(r.text.includes(USER));
    r = await a.get('/admin/logs'); assert.strictEqual(r.status, 200);
    assert(r.text.includes('bad_password') && r.text.includes(USER));
    ok('адмін бачить користувачів і журнал входів');

    const uid = db.prepare('SELECT id FROM users WHERE email = ?').get(USER).id;
    r = await a.post(`/admin/users/${uid}/unblock`, {}, '/admin/users');
    assert.strictEqual(db.prepare('SELECT locked_until FROM users WHERE id = ?').get(uid).locked_until, null);
    r = await b.post('/login', { email: USER, password: PASS }, '/login'); assert.strictEqual(r.loc, '/profile');
    ok('адмін зняв тимчасове блокування — вхід можливий');

    r = await a.post(`/admin/users/${uid}/block`, {}, '/admin/users');
    r = await b.get('/profile');
    assert.strictEqual(r.loc, '/login', 'активна сесія заблокованого користувача має припинитися');
    r = await new Client().post('/login', { email: USER, password: PASS }, '/login'); assert.strictEqual(r.status, 403);
    r = await a.post('/admin/users/1/block', {}, '/admin/users');
    assert.strictEqual(db.prepare('SELECT is_blocked FROM users WHERE id = 1').get().is_blocked, 0);
    ok('адмін заблокував користувача: сесія завершена, вхід заборонено; адміна/себе блокувати не можна');
    await a.post(`/admin/users/${uid}/unblock`, {}, '/admin/users');

    // --- Завдання 7: відновлення пароля
    const f = new Client();
    r = await f.post('/forgot', { email: 'nobody@test.local' }, '/forgot'); assert.strictEqual(r.loc, '/login');
    assert.strictEqual(db.prepare("SELECT COUNT(*) c FROM outbox WHERE to_email='nobody@test.local'").get().c, 0);
    r = await f.post('/forgot', { email: USER }, '/forgot'); assert.strictEqual(r.loc, '/login');
    const rt = lastToken(USER, 'reset'); assert(rt);
    r = await f.get('/reset/' + rt); assert.strictEqual(r.status, 200);
    r = await f.post('/reset/' + rt, { password: 'weak', confirm: 'weak' }); assert.strictEqual(r.status, 400);
    const NEWP = 'N3w#Password!';
    r = await f.post('/reset/' + rt, { password: NEWP, confirm: NEWP }); assert.strictEqual(r.loc, '/login');
    r = await f.get('/reset/' + rt); assert.strictEqual(r.loc, '/forgot');
    r = await new Client().post('/login', { email: USER, password: PASS }, '/login'); assert.strictEqual(r.status, 401);
    r = await new Client().post('/login', { email: USER, password: NEWP }, '/login'); assert.strictEqual(r.loc, '/profile');
    ok('відновлення пароля: токен одноразовий, новий пароль працює, старий — ні');

    // прострочений reset-токен
    await f.post('/forgot', { email: USER }, '/forgot');
    const rt2 = lastToken(USER, 'reset');
    db.prepare("UPDATE tokens SET expires_at = 1 WHERE type = 'reset'").run();
    r = await f.get('/reset/' + rt2); assert.strictEqual(r.loc, '/forgot');
    ok('прострочений токен відновлення відхиляється');

    console.log(`\nУсі перевірки пройдено (${n}).`);
    server.close();
    process.exit(0);
  } catch (e) {
    console.error('\n✗ ПОМИЛКА ТЕСТУ:', e && e.stack ? e.stack : e);
    server.close();
    process.exit(1);
  }
})();
