const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { db, ensurePending, json } = require('./_db');
const { makeSalt, hashPassword } = require('./_hash');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  let b;
  try { b = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Bad request' }); }

  if (b.website) return json(400, { error: 'Ошибка отправки формы.' }); // honeypot

  const nickname = String(b.nickname || '').trim();
  const email = String(b.email || '').trim().toLowerCase();
  const pass = String(b.password || '');
  const errors = [];
  if (!/^[A-Za-z]+_[A-Za-z]+$/.test(nickname) || nickname.length < 5 || nickname.length > 24)
    errors.push('Ник должен быть в формате Имя_Фамилия (латиница, 5–24 символа).');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 32)
    errors.push('Укажите корректный e-mail (до 32 символов).');
  if (pass.length < 6 || pass.length > 32) errors.push('Пароль должен быть от 6 до 32 символов.');
  if (errors.length) return json(400, { errors });

  const ip = (event.headers['x-nf-client-connection-ip'] || event.headers['x-forwarded-for'] || '').split(',')[0].trim();

  try {
    const p = db();
    await ensurePending(p);
    await p.query('DELETE FROM pending_reg WHERE expires < NOW()');

    const [[{ n }]] = await p.query(
      'SELECT COUNT(*) n FROM pending_reg WHERE ip = ? AND created > NOW() - INTERVAL 10 MINUTE', [ip]);
    if (n >= 5) return json(429, { errors: ['Слишком много попыток. Подождите несколько минут.'] });

    const [rows] = await p.query('SELECT nickname, email FROM accounts WHERE nickname = ? OR email = ? LIMIT 2', [nickname, email]);
    for (const r of rows) {
      if (r.nickname.toLowerCase() === nickname.toLowerCase()) errors.push('Этот ник уже занят.');
      if (r.email.toLowerCase() === email) errors.push('Этот e-mail уже зарегистрирован.');
    }
    if (errors.length) return json(409, { errors: [...new Set(errors)] });

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const token = crypto.randomBytes(16).toString('hex');
    const salt = makeSalt(10);

    await p.query('DELETE FROM pending_reg WHERE email = ? OR nickname = ?', [email, nickname]);
    await p.query(
      `INSERT INTO pending_reg (token, nickname, email, pass_hash, salt, code_hash, expires, ip)
       VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL 10 MINUTE, ?)`,
      [token, nickname, email, hashPassword(pass, salt), salt, sha(token + code), ip]);

    const port = +process.env.SMTP_PORT || 465;
    const mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST, port, secure: port === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    await mailer.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Код подтверждения — САТУРН РП',
      text: `Ваш код подтверждения: ${code}\nОн действует 10 минут.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;background:#0f1420;color:#fff;border-radius:12px">
        <h2 style="margin:0 0 8px">САТУРН РП</h2>
        <p style="color:#9aa4b8">Код подтверждения регистрации аккаунта <b>${nickname}</b>:</p>
        <div style="font-size:36px;letter-spacing:10px;font-weight:700;color:#4da3ff;margin:16px 0">${code}</div>
        <p style="color:#9aa4b8;font-size:13px">Код действует 10 минут. Если это были не вы — просто игнорируйте письмо.</p></div>`,
    });

    return json(200, { token });
  } catch (e) {
    console.error('register error', e);
    return json(500, { errors: ['Ошибка сервера. Попробуйте позже.'] });
  }
};
