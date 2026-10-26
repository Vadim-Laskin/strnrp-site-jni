<?php
// ===== База данных =====
const DB_HOST = '185.207.214.14';
const DB_NAME = 'gs355033';
const DB_USER = 'gs355033';
const DB_PASS = 'TnDm5cadWTLr';

// ===== Почта (SMTP). Если SMTP_HOST пустой — используется обычный mail() =====
const SMTP_HOST   = 'smtp.mail.ru';
const SMTP_PORT   = 465;
const SMTP_SECURE = 'ssl';
const SMTP_USER   = 'strnrp@bk.ru';
const SMTP_PASS   = 'ka1eC9E9ZGNyfQkWPU1f';
const MAIL_FROM   = 'strnrp@bk.ru';
const MAIL_NAME   = 'САТУРН РП';

// ===== Подтверждение =====
const CODE_TTL      = 600;  // код живёт 10 минут
const CODE_ATTEMPTS = 5;    // попыток ввода кода
const RESEND_DELAY  = 60;   // повторная отправка не чаще раза в 60 сек

// ===== Хэш пароля под игровой мод =====
// Формат для SHA256_PassHash из Pawn: SHA256(пароль . соль), HEX в верхнем регистре.
// Если ваш мод хранит пароль иначе — поменяйте функцию game_hash().
function game_hash(string $pass, string $salt): string {
    return strtoupper(hash('sha256', $pass . $salt));
}
function make_salt(int $len = 16): string {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    $s = '';
    for ($i = 0; $i < $len; $i++) $s .= $chars[random_int(0, strlen($chars) - 1)];
    return $s;
}

// ===== Стартовые значения нового аккаунта (поля без DEFAULT в таблице) =====
const START_SEX    = 0;
const START_COLOR  = 0;
const START_AGE    = 0;
const START_NATION = 0;
const START_HEALTH = 100;
const START_MONEY  = 0;
const START_BANK   = 0;
const START_LEVEL  = 1;

function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO(
            'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
            DB_USER, DB_PASS,
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]
        );
    }
    return $pdo;
}
