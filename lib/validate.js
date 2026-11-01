/**
 * lib/validate.js - input validation. NEVER trust req.body.
 *
 * Why the `typeof === 'string'` checks matter (viva point - NoSQL injection):
 *   A client can send {"username": {"$ne": null}} as JSON. If that object reaches
 *   User.findOne({ username }), MongoDB treats it as an operator and matches ANY user.
 *   By forcing every field to be a plain string first, operators can never get through.
 */
class ValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}

const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;
const asString = (v) => (typeof v === 'string' ? v : '');

/** usernames are stored lower-case so "Alice" and "alice" cannot be two different people */
function username(v) {
  const s = asString(v).trim();
  if (!USERNAME_RE.test(s)) throw new ValidationError('Username must be 3-20 characters: letters, numbers or underscore');
  return s.toLowerCase();
}

function email(v) {
  const s = asString(v).trim().toLowerCase();
  if (s.length > 254 || !EMAIL_RE.test(s)) throw new ValidationError('Enter a valid email address');
  return s;
}

// bcrypt only uses the first 72 bytes, so longer passwords are rejected instead of silently cut
function password(v) {
  const s = asString(v);
  if (s.length < 8 || Buffer.byteLength(s) > 72) throw new ValidationError('Password must be 8-72 characters');
  return s;
}

function groupName(v) {
  const s = asString(v).trim();
  if (!s || s.length > 50) throw new ValidationError('Group name must be 1-50 characters');
  return s;
}

/** Returns the cleaned text, or null when empty / too long. */
function messageText(v) {
  const s = asString(v).trim();
  return s && s.length <= 4000 ? s : null;
}

function caption(v) {
  const s = asString(v).trim();
  if (s.length > 1000) throw new ValidationError('Caption is too long (max 1000 characters)');
  return s;
}

/** Optional list of usernames; silently drops invalid entries, caps the size. */
function usernameList(v, max = 50) {
  if (!Array.isArray(v)) return [];
  const out = new Set();
  for (const item of v.slice(0, max)) {
    const s = asString(item).trim();
    if (USERNAME_RE.test(s)) out.add(s.toLowerCase());
  }
  return [...out];
}

const isObjectId = (v) => typeof v === 'string' && OBJECT_ID_RE.test(v);

module.exports = { ValidationError, username, email, password, groupName, messageText, caption, usernameList, isObjectId };
