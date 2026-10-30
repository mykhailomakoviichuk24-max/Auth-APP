// Індикатор сили та вимог до пароля (дублює серверну політику; сервер перевіряє все повторно)
(function () {
  var pw = document.getElementById('password');
  if (pw) {
    var bar = document.getElementById('meter-bar');
    var label = document.getElementById('meter-label');
    var rules = document.querySelectorAll('#rules li');
    var COMMON = ['password', 'password1', 'password123', 'p@ssw0rd', 'qwerty', 'qwerty123', '12345678', '123456789',
      'abc12345', 'iloveyou', 'admin123', 'letmein', 'welcome1', 'passw0rd', '1q2w3e4r', 'changeme', 'test1234'];
    var names = ['Дуже слабкий', 'Слабкий', 'Середній', 'Добрий', 'Сильний'];
    var colors = ['#d64545', '#d64545', '#d97706', '#6aa84f', '#1f9d55'];

    var checks = {
      len: function (v) { return v.length >= 8; },
      upper: function (v) { return /\p{Lu}/u.test(v); },
      lower: function (v) { return /\p{Ll}/u.test(v); },
      digit: function (v) { return /\p{Nd}/u.test(v); },
      symbol: function (v) { return /[^\p{L}\p{N}]/u.test(v); }
    };

    pw.addEventListener('input', function () {
      var v = pw.value;
      rules.forEach(function (li) { li.classList.toggle('ok', checks[li.dataset.rule](v)); });
      var s = 0;
      if (v.length >= 8) s++;
      if (v.length >= 12) s++;
      if (checks.upper(v) && checks.lower(v)) s++;
      if (checks.digit(v) && checks.symbol(v)) s++;
      if (COMMON.indexOf(v.toLowerCase()) !== -1) s = Math.min(s, 1);
      s = Math.min(s, 4);
      bar.style.width = v ? (s + 1) * 20 + '%' : '0';
      bar.style.background = colors[s];
      label.textContent = v ? 'Сила пароля: ' + names[s] : 'Сила пароля';
    });
  }

  var refresh = document.getElementById('captcha-refresh');
  var img = document.getElementById('captcha-img');
  if (refresh && img) {
    refresh.addEventListener('click', function () { img.src = '/captcha?t=' + Date.now(); });
  }
})();
