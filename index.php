<?php
session_start();
require __DIR__ . '/config.php';
require __DIR__ . '/mailer.php';

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$errors = [];
$done   = false;
$old    = ['nickname' => '', 'email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        $errors[] = 'Сессия устарела, обновите страницу и попробуйте снова.';
    }
    if (!empty($_POST['website'])) {
        $errors[] = 'Ошибка отправки формы.';
    }
    if (time() - ($_SESSION['last_try'] ?? 0) < 2) {
        $errors[] = 'Слишком часто. Подождите пару секунд.';
    }
    $_SESSION['last_try'] = time();

    if (!$errors) {

        // ---------- Шаг 1: данные -> отправка кода ----------
        if ($action === 'register') {
            $nickname = trim($_POST['nickname'] ?? '');
            $email    = trim($_POST['email'] ?? '');
            $pass     = (string)($_POST['password'] ?? '');
            $pass2    = (string)($_POST['password2'] ?? '');
            $agree    = !empty($_POST['agree']);
            $old = ['nickname' => $nickname, 'email' => $email];

            if (!preg_match('/^[A-Za-z]+_[A-Za-z]+$/', $nickname) || strlen($nickname) < 5 || strlen($nickname) > 24) {
                $errors[] = 'Ник должен быть в формате Имя_Фамилия (латиница, 5–24 символа).';
            }
            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 32) {
                $errors[] = 'Укажите корректный e-mail (до 32 символов).';
            }
            if (strlen($pass) < 6 || strlen($pass) > 32) {
                $errors[] = 'Пароль должен быть от 6 до 32 символов.';
            }
            if ($pass !== $pass2) {
                $errors[] = 'Пароли не совпадают.';
            }
            if (!$agree) {
                $errors[] = 'Необходимо принять пользовательское соглашение.';
            }

            if (!$errors) {
                try {
                    $st = db()->prepare('SELECT nickname, email FROM accounts WHERE nickname = ? OR email = ? LIMIT 2');
                    $st->execute([$nickname, $email]);
                    foreach ($st->fetchAll() as $row) {
                        if (strcasecmp($row['nickname'], $nickname) === 0) $errors[] = 'Этот ник уже занят.';
                        if (strcasecmp($row['email'], $email) === 0)       $errors[] = 'Этот e-mail уже зарегистрирован.';
                    }
                    $errors = array_values(array_unique($errors));
                } catch (PDOException $ex) {
                    error_log('Reg check: ' . $ex->getMessage());
                    $errors[] = 'Ошибка сервера. Попробуйте позже.' . (defined('DEBUG') && DEBUG ? ' [' . $ex->getMessage() . ']' : '');
                }
            }

            if (!$errors) {
                $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
                if (!mail_send($email, 'Код подтверждения — САТУРН РП', mail_code_html($nickname, $code))) {
                    $errors[] = 'Не удалось отправить письмо. Проверьте e-mail или попробуйте позже.';
                } else {
                    $salt = make_salt();
                    $_SESSION['pending'] = [
                        'nickname'  => $nickname,
                        'email'     => $email,
                        'salt'      => $salt,
                        'hash'      => game_hash($pass, $salt), // пароль в открытом виде не храним
                        'code_hash' => hash('sha256', $code . session_id()),
                        'expires'   => time() + CODE_TTL,
                        'sent_at'   => time(),
                        'attempts'  => 0,
                    ];
                }
            }
        }

        // ---------- Шаг 2: проверка кода -> создание аккаунта ----------
        elseif ($action === 'verify' && !empty($_SESSION['pending'])) {
            $p    = &$_SESSION['pending'];
            $code = preg_replace('/\D/', '', (string)($_POST['code'] ?? ''));

            if (time() > $p['expires']) {
                unset($_SESSION['pending']);
                $errors[] = 'Код истёк. Пройдите регистрацию заново.';
            } elseif ($p['attempts'] >= CODE_ATTEMPTS) {
                unset($_SESSION['pending']);
                $errors[] = 'Слишком много неверных попыток. Начните заново.';
            } elseif (!hash_equals($p['code_hash'], hash('sha256', $code . session_id()))) {
                $p['attempts']++;
                $left = CODE_ATTEMPTS - $p['attempts'];
                $errors[] = 'Неверный код. Осталось попыток: ' . $left . '.';
                if ($left <= 0) unset($_SESSION['pending']);
            } else {
                try {
                    $pdo = db();
                    $st = $pdo->prepare('SELECT 1 FROM accounts WHERE nickname = ? OR email = ? LIMIT 1');
                    $st->execute([$p['nickname'], $p['email']]);
                    if ($st->fetch()) {
                        unset($_SESSION['pending']);
                        $errors[] = 'Ник или e-mail уже заняты.';
                    } else {
                        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $ip = '0.0.0.0';

                        $ins = $pdo->prepare(
                            'INSERT INTO accounts
                             (nickname, email, password, pSaltHash, ip, sex, color, age, nation,
                              health, money, bank, level, pJob, gauth_code, gauth_status, AdminCode, test)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)'
                        );
                        $ins->execute([
                            $p['nickname'], $p['email'], $p['hash'], $p['salt'], $ip,
                            START_SEX, START_COLOR, START_AGE, START_NATION,
                            START_HEALTH, START_MONEY, START_BANK, START_LEVEL,
                            0, '', 0, 0,
                        ]);
                        unset($_SESSION['pending']);
                        $_SESSION['csrf'] = bin2hex(random_bytes(32));
                        $done = true;
                    }
                } catch (PDOException $ex) {
                    if ($ex->getCode() === '23000') {
                        $errors[] = 'Ник или e-mail уже заняты.';
                    } else {
                        error_log('Registration error: ' . $ex->getMessage());
                        $errors[] = 'Ошибка сервера. Попробуйте позже.' . (defined('DEBUG') && DEBUG ? ' [' . $ex->getMessage() . ']' : '');
                    }
                }
            }
            unset($p);
        }

        // ---------- Повторная отправка кода ----------
        elseif ($action === 'resend' && !empty($_SESSION['pending'])) {
            $p = &$_SESSION['pending'];
            $wait = RESEND_DELAY - (time() - $p['sent_at']);
            if ($wait > 0) {
                $errors[] = 'Повторная отправка через ' . $wait . ' сек.';
            } else {
                $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
                if (mail_send($p['email'], 'Код подтверждения — САТУРН РП', mail_code_html($p['nickname'], $code))) {
                    $p['code_hash'] = hash('sha256', $code . session_id());
                    $p['expires']   = time() + CODE_TTL;
                    $p['sent_at']   = time();
                    $p['attempts']  = 0;
                } else {
                    $errors[] = 'Не удалось отправить письмо.';
                }
            }
            unset($p);
        }

        // ---------- Отмена ----------
        elseif ($action === 'cancel') {
            unset($_SESSION['pending']);
        }
    }
}

$pending = $_SESSION['pending'] ?? null;
if ($pending && time() > $pending['expires']) { unset($_SESSION['pending']); $pending = null; }

$maskedEmail = '';
$resendLeft  = 0;
if ($pending) {
    [$loc, $dom] = explode('@', $pending['email'], 2);
    $maskedEmail = mb_substr($loc, 0, 2) . str_repeat('*', max(1, strlen($loc) - 2)) . '@' . $dom;
    $resendLeft  = max(0, RESEND_DELAY - (time() - $pending['sent_at']));
}
$step = $done ? 3 : ($pending ? 2 : 1);
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#070b18">
<meta name="robots" content="noindex">
<link rel="shortcut icon" href="wp-content/themes/mobile_theme/img/favicons/favicon.ico" type="image/x-icon">
<link rel="stylesheet" href="register.css?v=<?= @filemtime(__DIR__ . '/register.css') ?: 1 ?>">
<title>Регистрация | САТУРН РП</title>
</head>
<body>

<div class="space" aria-hidden="true">
  <i class="stars"></i><i class="stars stars--2"></i>
  <div class="planet"></div>
</div>

<header class="top">
  <div class="wrap top__in">
    <a class="brand" href="index.html">
      <span class="brand__icon"></span>
      <span class="brand__text"><b>SATURN</b><small>role play</small></span>
    </a>
    <button class="burger" id="burger" type="button" aria-label="Меню"><span></span><span></span><span></span></button>
    <nav class="nav" id="nav">
      <a href="index.html">Главная</a>
      <a href="forum">Форум</a>
      <a href="index.html#news">Новости</a>
      <a href="rate/index.html">Рейтинг</a>
      <a href="about.html">О нас</a>
      <a href="donate.html">Донат</a>
      <a href="wiki">WIKI</a>
      <a class="nav__cta" href="/cabinet">Личный кабинет</a>
    </nav>
  </div>
</header>

<main class="page wrap">
  <h1 class="title">Регистрация <span>аккаунта</span></h1>

  <div class="card <?= $errors ? 'is-shake' : '' ?>">

    <ol class="steps" data-step="<?= (int)$step ?>">
      <li class="<?= $step > 1 ? 'done' : 'now' ?>"><b>1</b><span>Данные</span></li>
      <li class="<?= $step > 2 ? 'done' : ($step === 2 ? 'now' : '') ?>"><b>2</b><span>Почта</span></li>
      <li class="<?= $step === 3 ? 'now done' : '' ?>"><b>3</b><span>Готово</span></li>
    </ol>

    <?php if ($errors): ?>
      <div class="alert">
        <ul><?php foreach ($errors as $err): ?><li><?= e($err) ?></li><?php endforeach; ?></ul>
      </div>
    <?php endif; ?>

<?php if ($step === 3): ?>

    <div class="ok">
      <svg class="ok__check" viewBox="0 0 52 52"><circle cx="26" cy="26" r="24"/><path d="M14 27l8 8 16-17"/></svg>
      <h2>Аккаунт создан!</h2>
      <p>Почта подтверждена. Теперь можно заходить в игру.</p>
      <a href="test.html" class="btn">Начать игру</a>
    </div>

<?php elseif ($step === 2): ?>

    <p class="lead">Мы отправили 6-значный код на<br><b><?= e($maskedEmail) ?></b></p>

    <form method="post" action="index.php" autocomplete="off" novalidate>
      <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
      <input type="hidden" name="action" value="verify">
      <input class="hp" type="text" name="website" tabindex="-1" autocomplete="off">

      <div class="field" style="--i:1">
        <label for="code">Код из письма</label>
        <input class="input input--code" type="text" id="code" name="code" maxlength="6"
               inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="000000" autofocus required>
      </div>
      <button type="submit" class="btn">Подтвердить</button>
    </form>

    <div class="links">
      <form method="post" action="index.php">
        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="resend">
        <input class="hp" type="text" name="website" tabindex="-1" autocomplete="off">
        <button type="submit" class="link" id="resend" data-left="<?= (int)$resendLeft ?>">Отправить код ещё раз</button>
      </form>
      <form method="post" action="index.php">
        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
        <input type="hidden" name="action" value="cancel">
        <button type="submit" class="link">Изменить данные</button>
      </form>
    </div>

<?php else: ?>

    <p class="lead">Создайте аккаунт и начните играть на своём телефоне</p>

    <form method="post" action="index.php" autocomplete="off" novalidate>
      <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
      <input type="hidden" name="action" value="register">
      <input class="hp" type="text" name="website" tabindex="-1" autocomplete="off">

      <div class="field" style="--i:1">
        <label for="nickname">Игровой ник</label>
        <input class="input" type="text" id="nickname" name="nickname" maxlength="24" placeholder="Name_Surname" value="<?= e($old['nickname']) ?>" autocapitalize="words" required>
        <small>Формат: Имя_Фамилия, только латиница</small>
      </div>

      <div class="field" style="--i:2">
        <label for="email">E-mail</label>
        <input class="input" type="email" id="email" name="email" maxlength="32" placeholder="you@mail.ru" value="<?= e($old['email']) ?>" required>
        <small>На почту придёт код подтверждения</small>
      </div>

      <div class="field" style="--i:3">
        <label for="password">Пароль</label>
        <div class="pw">
          <input class="input" type="password" id="password" name="password" maxlength="32" placeholder="От 6 до 32 символов" required>
          <button type="button" class="pw__eye" data-eye="password">показать</button>
        </div>
        <div class="meter"><span></span></div>
      </div>

      <div class="field" style="--i:4">
        <label for="password2">Повторите пароль</label>
        <div class="pw">
          <input class="input" type="password" id="password2" name="password2" maxlength="32" required>
          <button type="button" class="pw__eye" data-eye="password2">показать</button>
        </div>
      </div>

      <label class="agree" style="--i:5">
        <input type="checkbox" name="agree" value="1">
        <span>Я принимаю <a href="docs/agreement-ready.html" target="_blank">пользовательское соглашение</a> и <a href="docs/privacy-policy.html" target="_blank">политику конфиденциальности</a></span>
      </label>

      <button type="submit" class="btn">Получить код</button>
    </form>

    <div class="foot-note">Уже есть аккаунт? <a href="/cabinet">Войти в кабинет</a></div>

<?php endif; ?>
  </div>
</main>

<footer class="foot">
  <div class="wrap">
    <div class="foot__links">
      <a href="docs/privacy-policy.html">Политика конфиденциальности</a>
      <a href="docs/agreement-ready.html">Пользовательское соглашение</a>
      <a href="docs/agreement.html">Оферта</a>
    </div>
    <p>Связь: strnrp@bk.ru</p>
    <p>&copy; 2025–2026 САТУРН РП</p>
  </div>
</footer>

<script>
(function () {
  var $ = function (s) { return document.querySelector(s); };

  // Бургер-меню
  var burger = $('#burger'), nav = $('#nav');
  if (burger) burger.addEventListener('click', function () {
    burger.classList.toggle('open'); nav.classList.toggle('open');
  });

  // Только цифры в поле кода
  var code = $('#code');
  if (code) code.addEventListener('input', function () {
    this.value = this.value.replace(/\D/g, '').slice(0, 6);
  });

  // Таймер повторной отправки
  var btn = $('#resend');
  if (btn) {
    var left = parseInt(btn.dataset.left, 10) || 0, label = btn.textContent;
    (function tick() {
      if (left > 0) { btn.disabled = true; btn.textContent = label + ' (' + left + ')'; left--; setTimeout(tick, 1000); }
      else { btn.disabled = false; btn.textContent = label; }
    })();
  }

  // Показать / скрыть пароль
  document.querySelectorAll('[data-eye]').forEach(function (b) {
    b.addEventListener('click', function () {
      var i = document.getElementById(b.dataset.eye), show = i.type === 'password';
      i.type = show ? 'text' : 'password';
      b.textContent = show ? 'скрыть' : 'показать';
    });
  });

  // Надёжность пароля
  var pw = $('#password'), bar = $('.meter span');
  if (pw && bar) pw.addEventListener('input', function () {
    var v = pw.value, s = 0;
    if (v.length >= 6) s++;
    if (v.length >= 10) s++;
    if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++;
    if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v)) s++;
    bar.style.width = (v ? Math.max(1, s) * 25 : 0) + '%';
    bar.className = 's' + s;
  });

  // Состояние загрузки на кнопке
  document.querySelectorAll('form').forEach(function (f) {
    f.addEventListener('submit', function () {
      var b = f.querySelector('.btn');
      if (b) { b.classList.add('loading'); }
    });
  });
})();
</script>
</body>
</html>
