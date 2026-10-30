const bcrypt = require('bcryptjs');
const config = require('../config');

// Невеликий список поширених паролів (додатково до політики, Завдання 1)
const COMMON = new Set([
  'password', 'password1', 'password123', 'p@ssw0rd', 'p@ssword1', 'qwerty', 'qwerty123', 'qwerty12',
  'qwertyuiop', '12345678', '123456789', '1234567890', '11111111', '00000000', 'abc12345', 'abcd1234',
  'iloveyou', 'admin123', 'admin', 'letmein', 'welcome', 'welcome1', 'monkey123', 'dragon123',
  'football', 'baseball', 'sunshine', 'princess', 'master123', 'login123', 'passw0rd', 'zaq12wsx',
  '1q2w3e4r', '1qaz2wsx', 'qazwsxedc', 'trustno1', 'changeme', 'test1234', 'user1234', 'ukraine',
  'slava ukraini', 'slavaukraini', 'parol123', 'qwerty1', 'asdfghjkl', 'zxcvbnm1',
]);

/**
 * Перевірка політики:
 *  - >= 8 символів
 *  - великі і малі літери (Unicode)
 *  - цифра
 *  - символ (не літера і не цифра)
 * Також: обмеження 72 байти (ліміт bcrypt) та відсутність у списку поширених паролів.
 * Повертає масив повідомлень про помилки (порожній — пароль прийнятний).
 */
function validatePassword(pw, email = '') {
  const errors = [];
  if (typeof pw !== 'string') return ['Пароль обов\'язковий'];
  if (pw.length < 8) errors.push('Пароль має містити щонайменше 8 символів');
  if (Buffer.byteLength(pw, 'utf8') > 72) errors.push('Пароль задовгий (максимум 72 байти)');
  if (!/\p{Lu}/u.test(pw)) errors.push('Потрібна хоча б одна велика літера');
  if (!/\p{Ll}/u.test(pw)) errors.push('Потрібна хоча б одна мала літера');
  if (!/\p{Nd}/u.test(pw)) errors.push('Потрібна хоча б одна цифра');
  if (!/[^\p{L}\p{N}]/u.test(pw)) errors.push('Потрібен хоча б один символ (не літера і не цифра)');
  if (COMMON.has(pw.toLowerCase())) errors.push('Цей пароль надто поширений');
  const local = String(email).split('@')[0].toLowerCase();
  if (local.length >= 4 && pw.toLowerCase().includes(local)) errors.push('Пароль не повинен містити частину e-mail');
  return errors;
}

/** Оцінка сили 0..4 (дублюється на клієнті у public/app.js) */
function strength(pw) {
  if (!pw) return 0;
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/\p{Lu}/u.test(pw) && /\p{Ll}/u.test(pw)) s++;
  if (/\p{Nd}/u.test(pw) && /[^\p{L}\p{N}]/u.test(pw)) s++;
  if (COMMON.has(pw.toLowerCase())) s = Math.min(s, 1);
  return Math.min(s, 4);
}

// bcrypt: адаптивний хеш із вбудованою випадковою сіллю.
// compare() обчислює хеш введеного пароля з тією ж сіллю/ціною й порівнює з збереженим.
function hashPassword(pw) {
  return bcrypt.hash(pw, config.bcryptRounds);
}

// Хеш-пустушка для вирівнювання часу відповіді, коли користувача не існує
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', config.bcryptRounds);

async function verifyPassword(pw, hash) {
  return bcrypt.compare(pw, hash || DUMMY_HASH).then((ok) => (hash ? ok : false));
}

module.exports = { validatePassword, strength, hashPassword, verifyPassword };
