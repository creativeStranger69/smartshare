/**
 * config.js  -  ONE place for every setting (12-factor style: config comes from the environment).
 * Values are read from real environment variables or from a local `.env` file (see .env.example).
 *
 * PRODUCTION GUARD: when NODE_ENV=production the server REFUSES to start with a weak/missing
 * JWT_SECRET or without MONGO_URI. A default secret in production would let anyone forge logins.
 */
const path = require('path');
require('dotenv').config();           // loads .env into process.env (does not override real env vars)

const env = process.env;
const isProd = env.NODE_ENV === 'production';

const config = {
  isProd,
  port: parseInt(env.PORT, 10) || 3000,
  mongoUri: env.MONGO_URI || 'mongodb://127.0.0.1:27017/smartshare',
  jwtSecret: env.JWT_SECRET || 'dev-only-secret-do-not-use-in-production',
  sessionDays: 7,
  bcryptRounds: 12,
  maxFileMb: Number(env.MAX_FILE_MB) > 0 ? Number(env.MAX_FILE_MB) : 25,
  uploadDir: path.resolve(env.UPLOAD_DIR || path.join(__dirname, 'uploads')),
  // Cookie must be "Secure" (HTTPS only) in production. Override with COOKIE_SECURE=false
  // ONLY if you run production mode over plain http for a local demo.
  cookieSecure: env.COOKIE_SECURE ? env.COOKIE_SECURE === 'true' : isProd,
  // Number of reverse proxies in front of the app (nginx/Caddy/Render = 1). Needed so
  // rate-limiting sees the real client IP instead of the proxy's IP.
  trustProxy: Number(env.TRUST_PROXY ?? (isProd ? 1 : 0)),
  // Extra origins allowed to call the API/WebSocket (comma separated). Same-origin is always allowed.
  // Fraud-link check: optional Google Safe Browsing key (without it, built-in heuristics are used)
  safeBrowsingKey: env.SAFE_BROWSING_API_KEY || '',
  // Auto-translate: mymemory (free, no key) | libretranslate (self-hosted) | google (paid) | none
  translateProvider: (env.TRANSLATE_PROVIDER || 'mymemory').toLowerCase(),
  libreTranslateUrl: env.LIBRETRANSLATE_URL || '',
  libreTranslateKey: env.LIBRETRANSLATE_API_KEY || '',
  googleTranslateKey: env.GOOGLE_TRANSLATE_KEY || '',
  myMemoryEmail: env.MYMEMORY_EMAIL || '',
  allowedOrigins: (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean),
};
config.maxFileBytes = config.maxFileMb * 1024 * 1024;

if (isProd) {
  const problems = [];
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) problems.push('JWT_SECRET must be set and at least 32 characters');
  if (!env.MONGO_URI) problems.push('MONGO_URI must be set');
  if (problems.length) throw new Error('Invalid production configuration: ' + problems.join('; '));
}

module.exports = config;
