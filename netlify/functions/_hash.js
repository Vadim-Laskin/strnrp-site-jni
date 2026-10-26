const c = require('crypto');
const sha = (s) => c.createHash('sha256').update(s).digest('hex').toUpperCase();
const md5 = (s) => c.createHash('md5').update(s).digest('hex').toUpperCase();
const ABC = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

exports.makeSalt = (n = 10) =>
  Array.from(c.randomBytes(n), (b) => ABC[b % ABC.length]).join('');

// ВАЖНО: схема должна совпадать с той, что использует ваш игровой мод при входе.
exports.hashPassword = (pass, salt) => {
  switch (process.env.HASH_MODE || 'sha256_pass_salt') {
    case 'sha256_pass_salt': return sha(pass + salt);
    case 'sha256_salt_pass': return sha(salt + pass);
    case 'sha256_double':    return sha(sha(pass) + salt);
    case 'md5_pass_salt':    return md5(pass + salt);
    case 'md5_double':       return md5(md5(pass) + salt);
    default: throw new Error('Unknown HASH_MODE');
  }
};
