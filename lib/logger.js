/**
 * lib/logger.js - tiny structured logger (no dependency).
 * Production: one JSON object per line (easy for log tools to parse).
 * Development: human-readable text.
 * NEVER log passwords, tokens or message text.
 */
const config = require('../config');

function write(level, msg, extra = {}) {
  const hasExtra = Object.keys(extra).length > 0;
  const line = config.isProd
    ? JSON.stringify({ time: new Date().toISOString(), level, msg, ...extra })
    : `[${level}] ${msg}${hasExtra ? ' ' + JSON.stringify(extra) : ''}`;
  (level === 'error' ? console.error : console.log)(line);
}

/** Express middleware: logs method, path, status and duration for every finished request. */
function requestLogger(req, res, next) {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    if (req.path === '/healthz') return;                       // keep health-check noise out
    const ms = Math.round(Number(process.hrtime.bigint() - start) / 1e6);
    write('info', 'http', { method: req.method, path: req.path, status: res.statusCode, ms, user: req.user && req.user.id });
  });
  next();
}

module.exports = {
  info: (m, e) => write('info', m, e),
  warn: (m, e) => write('warn', m, e),
  error: (m, e) => write('error', m, e),
  requestLogger,
};
