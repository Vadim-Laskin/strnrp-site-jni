const mysql = require('mysql2/promise');
let pool;
exports.db = () => pool || (pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: +process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 2,
  connectTimeout: 8000,
}));
exports.ensurePending = (p) => p.query(`CREATE TABLE IF NOT EXISTS pending_reg (
  token CHAR(32) PRIMARY KEY,
  nickname VARCHAR(32) NOT NULL,
  email VARCHAR(32) NOT NULL,
  pass_hash VARCHAR(70) NOT NULL,
  salt VARCHAR(16) NOT NULL,
  code_hash CHAR(64) NOT NULL,
  attempts TINYINT NOT NULL DEFAULT 0,
  expires DATETIME NOT NULL,
  ip VARCHAR(45),
  created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) CHARACTER SET utf8mb4`);
exports.json = (code, obj) => ({
  statusCode: code,
  headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  body: JSON.stringify(obj),
});
