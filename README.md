# AuthApp — безпечне керування обліковими записами

Node.js + Express + SQLite (better-sqlite3) + EJS. Реалізовано завдання 1–7 та RBAC.

## Запуск

```bash
npm install
cp .env.example .env      # задайте SESSION_SECRET (довгий випадковий рядок)
npm start                 # http://localhost:3000
```

При першому запуску створюється адміністратор (`ADMIN_EMAIL` / `ADMIN_PASSWORD` з `.env`,
за замовчуванням `admin@example.com` / `Admin#12345` — **змініть**).

Без налаштованого SMTP листи (активація, відновлення пароля) друкуються в консоль сервера і
показуються на сторінці `/dev/outbox` (лише поза production).

## Відповідність завданням

| Завдання | Реалізація |
|---|---|
| 1. Реєстрація/вхід | `routes/auth.js`, політика пароля в `utils/password.js` (≥8 символів, великі+малі літери, цифра, символ; перевірка поширених паролів; індикатор сили в `public/app.js`). Хешування — **bcrypt** (`bcryptjs`, cost 12, сіль вбудована). Автентифікація — порівняння хешу введеного пароля із збереженим (`bcrypt.compare`). Профіль `/profile`, вихід `POST /logout`. |
| 2. CAPTCHA | `GET /captcha` (svg-captcha), відповідь у сесії, одноразова, діє 5 хв; перевіряється при реєстрації. |
| 3. Активація | Після реєстрації лист із посиланням `/activate/<токен>`: 32 випадкові байти, у БД лише SHA-256 хеш, одноразовий, діє `ACTIVATION_TTL_MIN` (24 год). Статус показано в профілі. Вхід без активації неможливий; є повторне надсилання. |
| 4. Brute force + журнал | `services/loginGuard.js`: після `MAX_FAILED_ATTEMPTS` (5) невдалих спроб — блокування на `LOCK_MINUTES` (15). Додатково ліміт запитів за IP. Журнал `login_log` (e-mail, IP, User-Agent, результат, причина, метод). Адмін: `/admin/logs` (підсумок «хто і скільки разів» + деталізація з фільтрами), `/admin/users` (блокування/розблокування). |
| 5. 2FA | TOTP (RFC 6238): налаштування через QR на `/profile/2fa`, вмикання/вимикання в профілі (вимкнення потребує поточного коду). Невдалі коди 2FA враховуються в brute-force лічильнику. |
| 6. OpenID Connect | `routes/oidc.js`, `services/oidc.js` (openid-client): Authorization Code + PKCE + state + nonce. За замовчуванням Google; інший провайдер — через `OIDC_ISSUER`. |
| 7. Відновлення пароля | `/forgot` → лист із `/reset/<токен>` (одноразовий, діє `RESET_TTL_MIN` = 30 хв, хеш у БД). Відповідь не розкриває, чи існує e-mail. Після зміни пароля старі сесії знищуються. |

### RBAC
Ролі `user` та `admin` (колонка `users.role`). Middleware `requireAuth` / `requireRole('admin')` в `middleware/security.js`.
Користувач бачить лише власний профіль (id береться з сесії, не з URL). Усі маршрути `/admin/*` — тільки для адміністратора (інакше 403).
Адміністратор бачить список користувачів і статуси, журнал входів, може блокувати/розблокувати (не себе і не інших адмінів).
Блокування миттєво знищує активні сесії користувача.

## Налаштування OIDC (Google)
1. Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web application).
2. Authorized redirect URI: `http://localhost:3000/auth/oidc/callback`.
3. Впишіть `OIDC_CLIENT_ID` і `OIDC_CLIENT_SECRET` у `.env`, перезапустіть — на сторінці входу з'явиться кнопка.

Нюанси: вхід приймається лише з підтвердженим e-mail; якщо e-mail збігається з існуючим акаунтом — він прив'язується.
Якщо той акаунт не був активований, його локальний пароль скидається (захист від «попередньої реєстрації» чужої адреси).
Вхід через OIDC не вимагає локальної 2FA — другий фактор забезпечує провайдер.

## Інші заходи безпеки
CSRF-токени у всіх POST-формах; helmet (CSP, без inline-скриптів); cookie `httpOnly` + `sameSite=lax` (+ `secure` у production);
нова сесія після входу (захист від session fixation); параметризовані SQL-запити; екранування в EJS;
однакові відповіді для невідомих e-mail (реєстрація, відновлення, активація); вирівнювання часу відповіді при невідомому користувачі.

## Production
`NODE_ENV=production`, HTTPS, за зворотним проксі — `TRUST_PROXY=1`, власний `SESSION_SECRET`, реальний SMTP, змінений пароль адміна.

## Структура
```
server.js  config.js  db.js
middleware/  sessionStore.js  security.js (CSRF, flash, RBAC)
routes/      auth.js  reset.js  profile.js  oidc.js  admin.js
services/    mailer.js  audit.js  loginGuard.js  session.js  oidc.js
utils/       password.js  tokens.js  rateLimit.js
views/ public/ test/smoke.js
```

## Тест
`npm test` (сервер має бути зупинений) — наскрізна перевірка: політика пароля, CAPTCHA, активація, brute force, RBAC, відновлення пароля.
