const crypto = require('crypto');
const { db, ensurePending, json } = require('./_db');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Значения новых аккаунтов для столбцов без значения по умолчанию.
// Поменяйте под ваш мод при необходимости.
const DEFAULTS = {
  sex: 1, color: 0, age: 18, nation: 0, health: 100,
  money: 0, bank: 0, level: 1, pJob: 0,
  gauth_code: '', gauth_status: 0, AdminCode: 0,
  econfirmed: 1,      // e-mail подтверждён
  tester_status: 1,   // «test = 1»
};

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  let b;
  try { b = JSON.parse(event.body || '{}'); } catch { return json(400, { error: 'Bad request' }); }
  const token = String(b.token || '');
  const code = String(b.code || '').replace(/\D/g, '');
  if (!/^[a-f0-9]{32}$/.test(token) || code.length !== 6)
    return json(400, { errors: ['Введите 6-значный код.'] });

  const p = db();
  const conn = await p.getConnection();
  try {
    await ensurePending(conn);
    await conn.beginTransaction();
    const [[row]] = await conn.query('SELECT * FROM pending_reg WHERE token = ? FOR UPDATE', [token]);
    if (!row || new Date(row.expires) < new Date()) {
      await conn.rollback();
      return json(410, { errors: ['Код истёк. Начните регистрацию заново.'], expired: true });
    }
    if (row.attempts >= 5) {
      await conn.query('DELETE FROM pending_reg WHERE token = ?', [token]);
      await conn.commit();
      return json(429, { errors: ['Слишком много неверных попыток. Начните заново.'], expired: true });
    }
    if (sha(token + code) !== row.code_hash) {
      await conn.query('UPDATE pending_reg SET attempts = attempts + 1 WHERE token = ?', [token]);
      await conn.commit();
      return json(400, { errors: [`Неверный код. Осталось попыток: ${4 - row.attempts}.`] });
    }

    const [dup] = await conn.query('SELECT id FROM accounts WHERE nickname = ? OR email = ? LIMIT 1', [row.nickname, row.email]);
    if (dup.length) {
      await conn.query('DELETE FROM pending_reg WHERE token = ?', [token]);
      await conn.commit();
      return json(409, { errors: ['Ник или e-mail уже заняты.'], expired: true });
    }

    const data = { nickname: row.nickname, email: row.email, password: row.pass_hash, pSaltHash: row.salt, ip: row.ip || '0.0.0.0', ...DEFAULTS };
    const cols = Object.keys(data);
    await conn.query(
      `INSERT INTO accounts (${cols.map((c) => '`' + c + '`').join(',')}) VALUES (${cols.map(() => '?').join(',')})`,
      cols.map((c) => data[c]));
    await conn.query('DELETE FROM pending_reg WHERE token = ?', [token]);
    await conn.commit();
    return json(200, { ok: true });
  } catch (e) {
    await conn.rollback().catch(() => {});
    console.error('confirm error', e);
    return json(500, { errors: ['Ошибка сервера. Попробуйте позже.'] });
  } finally {
    conn.release();
  }
};
