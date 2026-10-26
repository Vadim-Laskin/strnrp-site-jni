<?php
// Минимальный SMTP-клиент (без зависимостей). Без SMTP_HOST используется mail().

function mail_send(string $to, string $subject, string $html): bool {
    $subjectEnc = '=?UTF-8?B?' . base64_encode($subject) . '?=';
    $fromName   = '=?UTF-8?B?' . base64_encode(MAIL_NAME) . '?=';
    $headers = "MIME-Version: 1.0\r\n"
             . "Content-Type: text/html; charset=UTF-8\r\n"
             . "Content-Transfer-Encoding: base64\r\n"
             . "From: $fromName <" . MAIL_FROM . ">\r\n";
    $body = chunk_split(base64_encode($html));

    if (SMTP_HOST === '') {
        return @mail($to, $subjectEnc, $body, $headers);
    }

    $read = function ($fp): string {
        $out = '';
        while (($line = fgets($fp, 515)) !== false) {
            $out .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') break;
        }
        return $out;
    };
    $cmd = function ($fp, string $c, string $ok) use ($read): bool {
        fwrite($fp, $c . "\r\n");
        return strpos($read($fp), $ok) === 0;
    };

    $prefix = SMTP_SECURE === 'ssl' ? 'ssl://' : '';
    $fp = @stream_socket_client($prefix . SMTP_HOST . ':' . SMTP_PORT, $en, $es, 10);
    if (!$fp) return false;
    stream_set_timeout($fp, 10);

    if (strpos($read($fp), '220') !== 0) return false;
    if (!$cmd($fp, 'EHLO ' . (gethostname() ?: 'localhost'), '250')) return false;

    if (SMTP_SECURE === 'tls') {
        if (!$cmd($fp, 'STARTTLS', '220')) return false;
        if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) return false;
        if (!$cmd($fp, 'EHLO ' . (gethostname() ?: 'localhost'), '250')) return false;
    }
    if (SMTP_USER !== '') {
        if (!$cmd($fp, 'AUTH LOGIN', '334')) return false;
        if (!$cmd($fp, base64_encode(SMTP_USER), '334')) return false;
        if (!$cmd($fp, base64_encode(SMTP_PASS), '235')) return false;
    }
    if (!$cmd($fp, 'MAIL FROM:<' . MAIL_FROM . '>', '250')) return false;
    if (!$cmd($fp, 'RCPT TO:<' . $to . '>', '250')) return false;
    if (!$cmd($fp, 'DATA', '354')) return false;

    $msg = "To: <$to>\r\nSubject: $subjectEnc\r\nDate: " . date('r') . "\r\n" . $headers . "\r\n" . $body;
    $msg = preg_replace('/^\./m', '..', $msg);
    $ok = $cmd($fp, $msg . "\r\n.", '250');
    $cmd($fp, 'QUIT', '221');
    fclose($fp);
    return $ok;
}

function mail_code_html(string $nick, string $code): string {
    $nick = htmlspecialchars($nick, ENT_QUOTES, 'UTF-8');
    return '<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border-radius:12px;background:#f4f6fb;color:#1c2333">'
        . '<h2 style="margin:0 0 12px;color:#2f6bff">САТУРН РП</h2>'
        . '<p>Здравствуйте, <b>' . $nick . '</b>!</p>'
        . '<p>Ваш код подтверждения регистрации:</p>'
        . '<div style="font-size:34px;letter-spacing:10px;font-weight:bold;text-align:center;background:#fff;border-radius:10px;padding:16px;margin:16px 0">' . $code . '</div>'
        . '<p style="font-size:13px;color:#667">Код действует 10 минут. Если вы не регистрировались — просто проигнорируйте письмо.</p>'
        . '</div>';
}
