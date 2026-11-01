/**
 * lib/auth.js - session handling with a signed JWT stored in an httpOnly cookie.
 *
 * WHY A COOKIE AND NOT localStorage?
 *   - httpOnly: JavaScript on the page can never read it, so an XSS bug cannot steal the login.
 *   - SameSite=Strict: the browser will not attach it to requests started by other websites (CSRF).
 *   - Secure (production): only sent over HTTPS.
 *   - The same cookie authenticates the WebSocket handshake automatically.
 */
const jwt = require('jsonwebtoken');
const config = require('../config');

const COOKIE = 'ss_token';
const cookieOptions = () => ({ httpOnly: true, sameSite: 'strict', secure: config.cookieSecure, path: '/' });

const sign = (user) =>
  jwt.sign({ id: String(user._id || user.id), username: user.username }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: `${config.sessionDays}d`,
  });

// `algorithms` is pinned so a forged token cannot choose a weaker algorithm (e.g. "none")
const verify = (token) => jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    const val = part.slice(i + 1).trim();
    try { out[key] = decodeURIComponent(val); } catch { out[key] = val; }
  }
  return out;
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE, token, { ...cookieOptions(), maxAge: config.sessionDays * 24 * 60 * 60 * 1000 });
}
const clearAuthCookie = (res) => res.clearCookie(COOKIE, cookieOptions());

/** Express middleware: sets req.user = { id, username } or answers 401. */
function auth(req, res, next) {
  try {
    const token = parseCookies(req.headers.cookie)[COOKIE];
    const payload = verify(token);
    req.user = { id: payload.id, username: payload.username };
    next();
  } catch {
    res.status(401).json({ error: 'Please log in' });
  }
}

/**
 * Is this Origin allowed? Same host is always fine; extra hosts come from ALLOWED_ORIGINS.
 * Used for CSRF defence-in-depth on API calls and for the WebSocket handshake.
 */
function originAllowed(origin, host) {
  if (!origin) return true;                                   // non-browser clients send no Origin
  if (config.allowedOrigins.includes(origin)) return true;
  try { return new URL(origin).host === host; } catch { return false; }
}

module.exports = { COOKIE, sign, verify, parseCookies, setAuthCookie, clearAuthCookie, auth, originAllowed };
