/**
 * server.js  -  BACKEND ENTRY POINT
 * ------------------------------------------------------------------
 * Layers in this file:
 *   0. Security middleware   helmet (headers + CSP), rate limits, same-origin check
 *   1. Auth routes           register / login / logout / me   (JWT in httpOnly cookie)
 *   2. Group routes          list / create / add members / user suggestions / one-to-one chats
 *   3. Message routes        paged history, serialisation, broadcast, edit, delete-for-everyone
 *   4. Media routes          upload (+ dedup), authenticated file download, gallery, stats
 *   5. Socket.io             real-time delivery, typing indicator, per-socket rate limit
 *   6. Lifecycle             start, health check, graceful shutdown
 *
 * REQUEST LIFECYCLE (typical):
 *   Browser --HTTP--> security middleware -> auth -> membership check -> route -> MongoDB
 *                                                              └──> io.to(room).emit(...) --WebSocket--> online members
 *
 * Helper modules:  config.js (settings) · lib/auth.js · lib/validate.js · lib/files.js · lib/logger.js · dedup.js
 */
const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const helmet = require('helmet');
const compression = require('compression');
const rl = require('express-rate-limit');
const { Server } = require('socket.io');

const config = require('./config');
const log = require('./lib/logger');
const v = require('./lib/validate');
const authLib = require('./lib/auth');
const { servingInfo, contentDisposition } = require('./lib/files');
const { User, Group, Message, FileHash } = require('./models');
const { dedupMiddleware, UPLOAD_DIR } = require('./dedup');
const { findLinks } = require('./lib/links');
const { linkParts, textSegments, buildTranslation, translationFor } = require('./lib/messageView');
const { assessLinks } = require('./lib/linkRisk');
const { createTranslator } = require('./lib/translate');
const { detectLanguage } = require('./lib/langdetect');
const languages = require('./lib/languages');
const path = require('path');
const fsp = require('fs').promises;
const chats = require('./lib/chats');

// AUTO-TRANSLATE service (mymemory | libretranslate | google | none) - see lib/translate.js
const translator = createTranslator({
  provider: config.translateProvider,
  libreUrl: config.libreTranslateUrl, libreKey: config.libreTranslateKey,
  googleKey: config.googleTranslateKey, myMemoryEmail: config.myMemoryEmail,
});

const rateLimit = rl.rateLimit || rl;
const MAX_GROUP_MEMBERS = 256;

const app = express();
const server = http.createServer(app);       // Socket.io needs the raw HTTP server
const io = new Server(server, { maxHttpBufferSize: 100 * 1024 }); // socket messages are tiny; cap at 100 KB

// Express 4 does not catch errors thrown inside async handlers. This wrapper forwards them
// to the central error handler at the bottom (otherwise the request would hang forever).
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* ===================================================================
 * 0. SECURITY MIDDLEWARE
 * =================================================================== */
app.set('trust proxy', config.trustProxy);   // real client IP behind nginx/Caddy/Render (for rate limits)
app.use(helmet({
  // Content-Security-Policy: the browser will only run OUR scripts and load OUR media.
  // Even if an attacker managed to inject HTML, inline scripts would not execute.
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'img-src': ["'self'", 'data:', 'blob:'],
      'media-src': ["'self'", 'blob:'],
      'connect-src': ["'self'"],
      'object-src': ["'none'"],
      // "upgrade to https" would break plain-http local/LAN demos, so only enable it when cookies are Secure
      'upgrade-insecure-requests': config.cookieSecure ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
}));
app.use(compression());
app.use(log.requestLogger);
app.use(express.json({ limit: '10kb' }));    // JSON bodies are tiny; reject anything bigger

const limiter = (windowMs, limit, extra = {}) => rateLimit({
  windowMs, limit, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many requests - please slow down and try again shortly' }, ...extra,
});
const apiLimiter = limiter(60 * 1000, 300);
// Strict in production; relaxed in development so demos, tests and `npm run smoke` never lock you out.
const loginLimiter = limiter(15 * 60 * 1000, config.isProd ? 10 : 200, { skipSuccessfulRequests: true }); // brute-force guard
const registerLimiter = limiter(60 * 60 * 1000, config.isProd ? 10 : 200);
const uploadLimiter = limiter(60 * 1000, 30);
const fileLimiter = limiter(60 * 1000, 600);
const translateLimiter = limiter(60 * 1000, 30);

// CSRF defence in depth (cookie is already SameSite=Strict): block state-changing requests
// whose Origin header names a different site.
function sameOrigin(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (authLib.originAllowed(req.headers.origin, req.headers.host)) return next();
  res.status(403).json({ error: 'Cross-origin request blocked' });
}

app.get('/healthz', (req, res) => {          // used by Docker / load balancers
  const dbUp = mongoose.connection.readyState === 1;
  res.status(dbUp ? 200 : 503).json({ status: dbUp ? 'ok' : 'degraded', db: dbUp });
});

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: config.isProd ? '1h' : 0,
  // the service worker file must never be cached for long, or users would be stuck on an old version of the app
  setHeaders: (res, file) => { if (file.endsWith('sw.js')) res.setHeader('Cache-Control', 'no-cache'); },
}));
// NOTE: uploads are NOT served statically any more - see GET /files/... (membership checked)

app.use('/api', apiLimiter, sameOrigin);
const { auth } = authLib;

/* ===================================================================
 * 1. AUTHENTICATION
 * =================================================================== */
const publicUser = (u) => ({ id: String(u._id || u.id), username: u.username });
const settingsOf = (u) => ({ language: languages.isSupported(u.language) ? u.language : 'en', autoTranslate: u.autoTranslate !== false });
// everything the browser needs to know right after login / page load
const sessionInfo = (u) => ({
  user: publicUser(u),
  settings: settingsOf(u),
  translation: { enabled: translator.enabled, languages: languages.LANGUAGES },
  maxFileMb: config.maxFileMb,
});
// Compared against when the username does not exist, so "wrong user" and "wrong password"
// take the same time (otherwise response time reveals which usernames are registered).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', config.bcryptRounds);

// Public: languages a reader can choose (used by the register form before anyone is logged in)
app.get('/api/languages', (req, res) => res.json({ enabled: translator.enabled, languages: languages.LANGUAGES }));

app.post('/api/register', registerLimiter, ah(async (req, res) => {
  const body = req.body || {};
  const data = { username: v.username(body.username), email: v.email(body.email) };
  const hashed = await bcrypt.hash(v.password(body.password), config.bcryptRounds);
  if (languages.isSupported(body.language)) data.language = body.language;     // reading language chosen at sign-up
  try {
    const user = await User.create({ ...data, password: hashed });
    authLib.setAuthCookie(res, authLib.sign(user));
    res.status(201).json(sessionInfo(user));
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'Username or email already taken' });
    throw err;
  }
}));

app.post('/api/login', loginLimiter, ah(async (req, res) => {
  const body = req.body || {};
  const name = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const pass = typeof body.password === 'string' ? body.password : '';
  const user = name ? await User.findOne({ username: name }) : null;
  const ok = await bcrypt.compare(pass, user ? user.password : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Wrong username or password' });
  authLib.setAuthCookie(res, authLib.sign(user));
  res.json(sessionInfo(user));
}));

app.post('/api/logout', (req, res) => {
  authLib.clearAuthCookie(res);
  res.json({ ok: true });
});

// The browser cannot read the httpOnly cookie, so it asks the server "who am I?" on page load.
app.get('/api/me', auth, ah(async (req, res) => {
  const user = await User.findById(req.user.id, 'username language autoTranslate').lean();
  if (!user) return res.status(401).json({ error: 'Please log in' });
  res.json(sessionInfo(user));
}));

// Change reading language / turn auto-translate on or off.
app.patch('/api/me/settings', auth, ah(async (req, res) => {
  const body = req.body || {};
  const update = {};
  if (body.language !== undefined) {
    if (!languages.isSupported(body.language)) return res.status(400).json({ error: 'Unsupported language' });
    update.language = body.language;
  }
  if (body.autoTranslate !== undefined) {
    if (typeof body.autoTranslate !== 'boolean') return res.status(400).json({ error: 'autoTranslate must be true or false' });
    update.autoTranslate = body.autoTranslate;
  }
  if (!Object.keys(update).length) return res.status(400).json({ error: 'Nothing to change' });
  const user = await User.findByIdAndUpdate(req.user.id, { $set: update }, { new: true }).select('language autoTranslate').lean();
  if (!user) return res.status(401).json({ error: 'Please log in' });
  // The server decides per socket which language to translate into, so keep this user's open tabs in sync
  // (works on a single server; with several servers you would publish this change through the Redis adapter).
  for (const s of await io.in('user:' + req.user.id).fetchSockets()) s.data.prefs = settingsOf(user);
  res.json({ settings: settingsOf(user) });
}));

/* ===================================================================
 * 2. GROUPS
 * =================================================================== */
// Authorisation: is the logged-in user a member of :groupId ?  (used by every group route)
const requireMember = ah(async (req, res, next) => {
  if (!v.isObjectId(req.params.groupId)) return res.status(400).json({ error: 'Bad group id' });
  const group = await Group.findOne({ _id: req.params.groupId, members: req.user.id }, 'name members isDirect');
  if (!group) return res.status(403).json({ error: 'You are not a member of this group' });
  req.group = group;
  next();
});

// What the browser sees of a chat. A one-to-one chat has no name of its own: each person sees the OTHER person's name.
function groupToClient(g, viewerId, nameOf = {}) {
  const base = { id: String(g._id || g.id), isDirect: !!g.isDirect, memberCount: g.members.length };
  if (!g.isDirect) return { ...base, name: g.name };
  const other = g.members.map(String).find((id) => id !== String(viewerId));
  return { ...base, name: nameOf[other] || 'unknown user', peerId: other || null };
}

// Usernames of the "other person" in every direct chat of a list (one query for the whole list).
async function peerNames(groups, viewerId) {
  const ids = new Set();
  groups.filter((g) => g.isDirect).forEach((g) => g.members.map(String).forEach((id) => id !== String(viewerId) && ids.add(id)));
  if (!ids.size) return {};
  const users = await User.find({ _id: { $in: [...ids] } }, 'username').lean();
  return Object.fromEntries(users.map((u) => [String(u._id), u.username]));
}

// Make the members' open sockets join the new group's room and tell them to refresh their list.
async function notifyMembers(userIds, group) {
  const names = group.isDirect ? await peerNames([group], '') : {};    // viewer '' -> names of both members
  userIds.forEach((id) => {
    io.in('user:' + id).socketsJoin('group:' + group.id);
    io.to('user:' + id).emit('groupAdded', groupToClient(group, id, names));
  });
}

app.get('/api/groups', auth, ah(async (req, res) => {
  const groups = await Group.find({ members: req.user.id }).lean();
  const names = await peerNames(groups, req.user.id);
  res.json(groups.map((g) => groupToClient(g, req.user.id, names)).sort((a, b) => a.name.localeCompare(b.name)));
}));

app.post('/api/groups', auth, ah(async (req, res) => {
  const name = v.groupName((req.body || {}).name);
  const wanted = v.usernameList((req.body || {}).memberUsernames);
  const found = wanted.length ? await User.find({ username: { $in: wanted } }, 'username').lean() : [];
  const ids = [...new Set([req.user.id, ...found.map((u) => String(u._id))])];
  if (ids.length > MAX_GROUP_MEMBERS) return res.status(400).json({ error: `A group can have at most ${MAX_GROUP_MEMBERS} members` });
  const group = await Group.create({ name, members: ids });
  await notifyMembers(ids, group);
  const foundNames = new Set(found.map((u) => u.username));
  res.status(201).json({ ...groupToClient(group, req.user.id), notFound: wanted.filter((n) => !foundNames.has(n)) });
}));

// SUGGESTIONS: every registered user (except me), alphabetical, filtered by what I typed. With ?groupId=...
// the people who are already in that group are flagged so the picker can grey them out.
app.get('/api/users', auth, ah(async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 200);
  const rows = await User.find(chats.userFilter(req.user.id, req.query.q), 'username').sort({ username: 1 }).limit(limit + 1).lean();
  const hasMore = rows.length > limit;
  if (hasMore) rows.pop();
  let inGroup = new Set();
  if (req.query.groupId !== undefined) {
    if (!v.isObjectId(req.query.groupId)) return res.status(400).json({ error: 'Bad group id' });
    const g = await Group.findOne({ _id: req.query.groupId, members: req.user.id }, 'members').lean();
    if (!g) return res.status(403).json({ error: 'You are not a member of this group' });
    inGroup = new Set(g.members.map(String));
  }
  res.json({ users: rows.map((u) => ({ id: String(u._id), username: u.username, inGroup: inGroup.has(String(u._id)) })), hasMore });
}));

// ONE-TO-ONE CHAT: open the chat with :username, creating it the first time.
app.post('/api/chats/direct', auth, ah(async (req, res) => {
  const other = await User.findOne({ username: v.username((req.body || {}).username) }, '_id username').lean();
  if (!other) return res.status(404).json({ error: 'No such user' });
  if (String(other._id) === String(req.user.id)) return res.status(400).json({ error: 'You cannot start a chat with yourself' });
  const key = chats.directKey(req.user.id, other._id);
  let group = await Group.findOne({ directKey: key });
  let created = false;
  if (!group) {
    try {
      group = await Group.create({ name: 'direct', isDirect: true, directKey: key, members: [req.user.id, String(other._id)] });
      created = true;
    } catch (err) {
      if (err.code !== 11000) throw err;                       // both people pressed "chat" at once: the unique index let only one through
      group = await Group.findOne({ directKey: key });
    }
  }
  if (created) await notifyMembers([String(req.user.id), String(other._id)], group);
  res.status(created ? 201 : 200).json(groupToClient(group, req.user.id, { [String(other._id)]: other.username }));
}));

// Add one (username) or several (usernames: [...]) people to a group.
app.post('/api/groups/:groupId/members', auth, requireMember, ah(async (req, res) => {
  if (req.group.isDirect) return res.status(400).json({ error: 'You cannot add people to a one-to-one chat - create a group instead' });
  const body = req.body || {};
  const wanted = body.usernames !== undefined ? v.usernameList(body.usernames) : [v.username(body.username)];
  if (!wanted.length) return res.status(400).json({ error: 'Choose at least one user' });
  const found = await User.find({ username: { $in: wanted } }, 'username').lean();
  const current = new Set(req.group.members.map(String));
  const fresh = found.filter((u) => !current.has(String(u._id)));
  if (!found.length) return res.status(404).json({ error: 'No such user' });
  if (current.size + fresh.length > MAX_GROUP_MEMBERS) return res.status(400).json({ error: 'Group is full' });
  if (fresh.length) {
    await Group.updateOne({ _id: req.group._id }, { $addToSet: { members: { $each: fresh.map((u) => u._id) } } });
    req.group.members.push(...fresh.map((u) => u._id));
    await notifyMembers(fresh.map((u) => String(u._id)), req.group);
  }
  const foundNames = new Set(found.map((u) => u.username));
  res.json({
    ok: true,
    added: fresh.map((u) => u.username),
    alreadyMembers: found.filter((u) => current.has(String(u._id))).map((u) => u.username),
    notFound: wanted.filter((n) => !foundNames.has(n)),
  });
}));

/* ===================================================================
 * 3. MESSAGES - serialisation, broadcast, history
 * DB rows only hold ids. Before sending to the browser we "join" in the sender's name and
 * (for media / duplicate alerts) the file's details: 3 queries for a whole page of messages.
 * =================================================================== */
// LINK DETECTION (display side): split the text into [text][link]... parts and attach, to every
// link that was shared before, who shared it first and when. The browser renders the parts as
// real <a> tags and shows a "🔁 already shared" note - no innerHTML involved.
async function viewerOf(userId) {
  const u = await User.findById(userId, 'language autoTranslate').lean();
  return u ? { id: String(userId), ...settingsOf(u) } : null;
}

// `viewer` = who is reading ({id, language, autoTranslate}); without it no translation is attached.
async function toClient(input, viewer = null) {
  const list = Array.isArray(input) ? input : [input];
  const refs = [...new Set(list.flatMap((m) => [m.mediaRef, m.similar && m.similar.fileId]).filter((x) => v.isObjectId(x)))];
  const files = refs.length ? await FileHash.find({ _id: { $in: refs } }).lean() : [];
  // the "original" messages that earlier-shared links point to (for the duplicate-link note)
  const dupIds = [...new Set(list.flatMap((m) => (m.links || []).map((l) => l.dupOf).filter(Boolean).map(String)))];
  const origs = dupIds.length ? await Message.find({ _id: { $in: dupIds }, deleted: { $ne: true } }, 'senderId timestamp').lean() : [];
  const userIds = [...new Set([
    ...list.map((m) => String(m.senderId)),
    ...files.map((f) => String(f.originalSenderId)),
    ...origs.map((o) => String(o.senderId)),
  ])];
  const users = await User.find({ _id: { $in: userIds } }, 'username').lean();
  const nameOf = Object.fromEntries(users.map((u) => [String(u._id), u.username]));
  const origOf = Object.fromEntries(origs.map((o) => [String(o._id), {
    messageId: String(o._id), senderName: nameOf[String(o.senderId)] || 'unknown', timestamp: o.timestamp,
  }]));

  const fileOf = Object.fromEntries(files.map((f) => [String(f._id), {
    url: `/files/${f.groupId}/${f._id}`,                       // authenticated download route (section 4)
    name: f.originalName,
    mimeType: servingInfo(f.physicalFilePath).type,            // derived from extension, never from the uploader
    originalSenderName: nameOf[String(f.originalSenderId)] || 'unknown',
    originalTimestamp: f.originalTimestamp,
  }]));

  const out = list.map((m) => {
    if (m.deleted) {                                           // tombstone: nothing of the original survives
      return { id: String(m._id), groupId: String(m.groupId), senderId: String(m.senderId), senderName: nameOf[String(m.senderId)] || 'unknown',
        text: '', timestamp: m.timestamp, isMedia: false, type: 'deleted', deleted: true, file: null, parts: null, similar: null, translation: null, canTranslate: false };
    }
    const parts = linkParts(m, origOf);                        // null unless the text contains links
    const translation = translationFor(m, parts, viewer);      // cached translation into the viewer's language, if any
    // Old message with no translation yet that is NOT already in the reader's language -> show a "Translate" button
    const detected = m.text ? detectLanguage(m.text) : null;
    const canTranslate = !!(viewer && viewer.autoTranslate && translator.enabled && !translation && detected
      && detected.lang !== viewer.language && String(m.senderId) !== viewer.id && !(m.mediaRef && !m.isMedia));
    return {
      id: String(m._id),
      groupId: String(m.groupId),
      senderId: String(m.senderId),
      senderName: nameOf[String(m.senderId)] || 'unknown',
      text: m.text,
      timestamp: m.timestamp,
      isMedia: m.isMedia,
      mediaRef: m.mediaRef,
      // type tells the frontend which bubble style to draw
      type: m.isMedia ? 'media' : m.mediaRef ? 'duplicate' : 'text',
      file: m.mediaRef ? fileOf[m.mediaRef] || null : null,
      parts,
      // SIMILAR-IMAGE note: "looks 94% like a photo already shared by bob"
      similar: m.similar && m.similar.fileId
        ? { similarity: Math.round(m.similar.similarity * 100), file: fileOf[m.similar.fileId] || null }
        : null,
      translation,
      canTranslate,
      edited: !!m.editedAt,
    };
  });
  return Array.isArray(input) ? out : out[0];
}

// Save + broadcast. The ONE place where "new message" becomes real-time.
// LINK DETECTION (save side): find links in the text and, for each, look up the EARLIEST message in this group
// that already contained the same normalised link (indexed on groupId + links.key), then FRAUD-LINK CHECK it:
// heuristics + (if a key is configured) Google Safe Browsing. Used for new messages AND for edited ones, so an
// edit can never smuggle in an unchecked link.
async function buildLinks(groupId, text, beforeId = null) {
  const found = findLinks(text);
  if (!found.length) return [];
  const risks = await assessLinks(found, { safeBrowsingKey: config.safeBrowsingKey });
  return Promise.all(found.map(async (l, i) => {
    const q = { groupId, 'links.key': l.key, deleted: { $ne: true } };
    if (beforeId) q._id = { $lt: beforeId };
    const first = await Message.findOne(q, '_id').sort({ _id: 1 }).lean();
    const { score, level, reasons } = risks[i];
    return { url: l.url, key: l.key, dupOf: first ? first._id : null, risk: { score, level, reasons } };
  }));
}

async function saveAndBroadcast(data) {
  const isDuplicateAlert = data.mediaRef && !data.isMedia;     // system alerts never contain user links
  if (data.text && !isDuplicateAlert) {
    const links = await buildLinks(data.groupId, data.text);
    if (links.length) data.links = links;
  }
  const doc = await Message.create(data);
  const payload = await toClient(doc.toObject());
  io.to('group:' + data.groupId).emit('newMessage', payload);       // 1) delivered immediately, in the original language
  translateAndPush(payload).catch((err) => log.warn('translateAndPush failed', { err: err.message }));   // 2) translations follow
  return payload;
}

// AUTO-TRANSLATE (push side). Called AFTER the message was delivered, so a slow or failing translation
// service can never delay or lose a message. For every language that some online reader chose, translate
// once (cached in the DB) and send each reader "messageTranslated" in THEIR language. The sender never gets one.
async function translateAndPush(payload) {
  if (!translator.enabled || !payload.text || payload.type === 'duplicate') return;
  const segs = textSegments(payload.text, payload.parts);
  if (!segs.some((s) => detectLanguage(s))) return;                // only emoji / numbers: nothing to translate

  const wanted = new Map();                                        // language code -> [sockets that want it]
  for (const s of await io.in('group:' + payload.groupId).fetchSockets()) {
    const prefs = s.data && s.data.prefs;
    if (!prefs || !prefs.autoTranslate || (s.data.user && s.data.user.id === payload.senderId)) continue;
    if (!wanted.has(prefs.language)) wanted.set(prefs.language, []);
    wanted.get(prefs.language).push(s);
  }
  await Promise.all([...wanted.keys()].slice(0, 8).map(async (lang) => {   // at most 8 languages per message
    try {
      const out = await translator.translateSegments(segs, lang);
      if (out.every((t, i) => t === segs[i])) return;              // already in that language
      await Message.updateOne({ _id: payload.id }, { $set: { [`translations.${lang}`]: out } });
      const translation = buildTranslation(payload.parts, out, lang);
      wanted.get(lang).forEach((s) => s.emit('messageTranslated', { id: payload.id, groupId: payload.groupId, translation }));
    } catch (err) {
      log.warn('translation failed', { lang, err: err.message });  // readers simply keep seeing the original
    }
  }));
}

// Paged history: newest 50 first; "load older" passes ?before=<oldest message id>.
app.get('/api/groups/:groupId/messages', auth, requireMember, ah(async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
  const query = { groupId: req.group._id };
  if (req.query.before !== undefined) {
    if (!v.isObjectId(req.query.before)) return res.status(400).json({ error: 'Bad "before" id' });
    query._id = { $lt: req.query.before };
  }
  const rows = await Message.find(query).sort({ _id: -1 }).limit(limit + 1).lean();
  const hasMore = rows.length > limit;
  if (hasMore) rows.pop();
  rows.reverse();                                              // oldest -> newest for display
  res.json({ messages: await toClient(rows, await viewerOf(req.user.id)), hasMore });
}));

// EDIT (text messages only, by the sender, within 15 minutes). Links are re-checked, old translations are dropped
// and re-created, and everybody in the chat gets "messageUpdated".
app.patch('/api/groups/:groupId/messages/:messageId', auth, requireMember, ah(async (req, res) => {
  if (!v.isObjectId(req.params.messageId)) return res.status(400).json({ error: 'Bad message id' });
  const text = v.messageText((req.body || {}).text);
  if (!text) return res.status(400).json({ error: 'Message must be 1-4000 characters' });
  const m = await Message.findOne({ _id: req.params.messageId, groupId: req.group._id }).lean();
  const problem = chats.editProblem(m, req.user.id);
  if (problem) return res.status(problem.status).json({ error: problem.error });
  const links = await buildLinks(req.group._id, text, m._id);
  const doc = await Message.findOneAndUpdate(
    { _id: m._id, deleted: { $ne: true } },
    { $set: { text, links, editedAt: new Date() }, $unset: { translations: 1 } }, { new: true }).lean();
  if (!doc) return res.status(404).json({ error: 'Message not found' });
  const payload = await toClient(doc);
  io.to('group:' + req.group.id).emit('messageUpdated', payload);
  translateAndPush(payload).catch((err) => log.warn('translateAndPush failed', { err: err.message }));
  res.json({ message: payload });
}));

// DELETE FOR EVERYONE (sender only). The row becomes a tombstone. If it was the group's copy of a file, the file is
// released with reference counting (see lib/chats.js): bytes leave the disk only when no other group uses them.
app.delete('/api/groups/:groupId/messages/:messageId', auth, requireMember, ah(async (req, res) => {
  if (!v.isObjectId(req.params.messageId)) return res.status(400).json({ error: 'Bad message id' });
  const m = await Message.findOne({ _id: req.params.messageId, groupId: req.group._id }).lean();
  if (!m || m.deleted) return res.status(404).json({ error: 'Message not found' });
  if (String(m.senderId) !== String(req.user.id)) return res.status(403).json({ error: 'You can only delete your own messages' });

  const wipe = { $set: { deleted: true, text: '', links: [], isMedia: false }, $unset: { mediaRef: 1, similar: 1, translations: 1, editedAt: 1 } };
  const ids = [String(m._id)];
  let release = { removed: false, physicalDeleted: false, bytesFreed: 0 };
  if (m.isMedia && m.mediaRef && v.isObjectId(m.mediaRef)) {
    release = await chats.releaseFile({ FileHash, fileId: m.mediaRef, groupId: req.group._id, uploadDir: UPLOAD_DIR, unlink: fsp.unlink });
    // "duplicate" alerts and "looks similar" notes that pointed at this file would now point at nothing
    const alerts = await Message.find({ groupId: req.group._id, isMedia: false, mediaRef: m.mediaRef, deleted: { $ne: true } }, '_id').lean();
    if (alerts.length) {
      await Message.deleteMany({ _id: { $in: alerts.map((a) => a._id) } });      // system notices: removed completely, no tombstone
      ids.push(...alerts.map((a) => String(a._id)));
    }
    await Message.updateMany({ groupId: req.group._id, 'similar.fileId': m.mediaRef }, { $unset: { similar: 1 } });
  }
  await Message.updateOne({ _id: m._id }, wipe);
  io.to('group:' + req.group.id).emit('messageDeleted', { ids, groupId: String(req.group._id) });
  res.json({ ok: true, ids, fileRemoved: release.removed, bytesFreed: release.bytesFreed });
}));

// "Translate" button for OLD messages that were written before the reader's language was set / while the
// translation service was down. Same cache as the live path, so each message is translated at most once per language.
app.post('/api/groups/:groupId/messages/:messageId/translate', translateLimiter, auth, requireMember, ah(async (req, res) => {
  if (!translator.enabled) return res.status(503).json({ error: 'Translation is not enabled on this server' });
  if (!v.isObjectId(req.params.messageId)) return res.status(400).json({ error: 'Bad message id' });
  const viewer = await viewerOf(req.user.id);
  const m = await Message.findOne({ _id: req.params.messageId, groupId: req.group._id }).lean();
  if (!viewer || !m || !m.text || (m.mediaRef && !m.isMedia)) return res.status(404).json({ error: 'Message not found' });
  if (String(m.senderId) === viewer.id) return res.json({ translation: null });           // your own words need no translation

  const payload = await toClient(m, { ...viewer, autoTranslate: true });
  if (payload.translation) return res.json({ translation: payload.translation });          // cached
  const segs = textSegments(payload.text, payload.parts);
  let out;
  try { out = await translator.translateSegments(segs, viewer.language); }
  catch (err) { log.warn('manual translation failed', { err: err.message }); return res.status(502).json({ error: 'Translation service is unavailable right now' }); }
  if (out.every((t, i) => t === segs[i])) return res.json({ translation: null });           // already readable
  await Message.updateOne({ _id: m._id }, { $set: { [`translations.${viewer.language}`]: out } });
  res.json({ translation: buildTranslation(payload.parts, out, viewer.language) });
}));

/* ===================================================================
 * 4. MEDIA: upload (dedup), download, gallery, stats
 * =================================================================== */
// multer keeps the upload in RAM (req.file.buffer) so dedup.js can hash it BEFORE anything
// touches the disk. Trade-off: RAM use = file size x concurrent uploads (hence the size limit + rate limit).
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: config.maxFileBytes, files: 1, fields: 5, parts: 8 },
});

/*   auth -> requireMember -> multer -> dedupMiddleware -> handler
 * The handler only has to look at req.dedup.duplicate:
 *   false -> create a normal media message
 *   true  -> create a "System Alert" pointer message (no new file stored) */
app.post('/api/groups/:groupId/upload', uploadLimiter, auth, requireMember, upload.single('file'), dedupMiddleware,
  ah(async (req, res) => {
    const { duplicate, fileHash, similar } = req.dedup;
    const base = { groupId: req.group._id, senderId: req.user.id, mediaRef: String(fileHash._id) };
    const message = duplicate
      ? await saveAndBroadcast({
          ...base,
          isMedia: false,                       // not a file bubble...
          text: `System Alert: ${req.user.username} tried to share a duplicate file.`, // ...an alert
        })
      : await saveAndBroadcast({
          ...base,
          isMedia: true,
          text: v.caption((req.body || {}).caption),
          // new picture that LOOKS like one already in the group -> the bubble carries a "looks similar" note
          ...(similar ? { similar: { fileId: similar.id, similarity: similar.similarity } } : {}),
        });
    res.status(duplicate ? 200 : 201).json({ duplicate, similar: !!similar, message });
  }));

// Authenticated download. Only members of the group that owns this FileHash row can fetch the bytes.
// The disk path comes from OUR database row (never from the URL) and only its basename is used.
app.get('/files/:groupId/:fileId', fileLimiter, auth, requireMember, ah(async (req, res) => {
  if (!v.isObjectId(req.params.fileId)) return res.status(404).end();
  const file = await FileHash.findOne({ _id: req.params.fileId, groupId: req.group._id }).lean();
  if (!file) return res.status(404).end();

  const { type, inline } = servingInfo(file.physicalFilePath);
  res.setHeader('Content-Type', type);
  res.setHeader('Content-Disposition', contentDisposition(inline, file.originalName));
  // Locked-down CSP on user content. (PDFs cannot be sandboxed - the browser's PDF viewer would break.)
  res.setHeader('Content-Security-Policy', type === 'application/pdf'
    ? "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
    : "default-src 'none'; sandbox");
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable'); // content-addressed: bytes never change
  res.sendFile(path.basename(file.physicalFilePath), { root: config.uploadDir, dotfiles: 'deny', cacheControl: false }, (err) => {
    if (err && !res.headersSent) res.status(err.code === 'ENOENT' ? 404 : 500).end();
  });
}));

// Gallery = every FileHash row of the group. Dedup guarantees one row per unique file,
// so the gallery is automatically duplicate-free: no extra filtering needed.
app.get('/api/groups/:groupId/gallery', auth, requireMember, ah(async (req, res) => {
  const files = await FileHash.find({ groupId: req.group._id }).sort({ originalTimestamp: -1 }).limit(500).lean();
  const users = await User.find({ _id: { $in: [...new Set(files.map((f) => String(f.originalSenderId)))] } }, 'username').lean();
  const nameOf = Object.fromEntries(users.map((u) => [String(u._id), u.username]));
  res.json(files.map((f) => ({
    id: String(f._id),
    url: `/files/${f.groupId}/${f._id}`,
    name: f.originalName,
    mimeType: servingInfo(f.physicalFilePath).type,
    sharedBy: nameOf[String(f.originalSenderId)] || 'unknown',
    sharedAt: f.originalTimestamp,
  })));
}));

// Storage savings dashboard:
//   storedBytes       = sum of sizes of the unique files actually on disk
//   duplicatesBlocked = number of "System Alert" messages (isMedia false + mediaRef set)
//   bytesSaved        = for each blocked duplicate, the size of the file we did NOT store again
app.get('/api/groups/:groupId/stats', auth, requireMember, ah(async (req, res) => {
  const files = await FileHash.find({ groupId: req.group._id }, 'size').lean();
  const sizeOf = Object.fromEntries(files.map((f) => [String(f._id), f.size || 0]));
  const dups = await Message.find(
    { groupId: req.group._id, isMedia: false, deleted: { $ne: true }, mediaRef: { $exists: true, $ne: null } }, 'mediaRef').lean();
  res.json({
    uniqueFiles: files.length,
    storedBytes: files.reduce((s, f) => s + (f.size || 0), 0),
    duplicatesBlocked: dups.length,
    bytesSaved: dups.reduce((s, m) => s + (sizeOf[m.mediaRef] || 0), 0),
  });
}));

/* ---------- unknown API route + central error handler ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const tooBig = err.code === 'LIMIT_FILE_SIZE';
    return res.status(tooBig ? 413 : 400).json({ error: tooBig ? `File too large (max ${config.maxFileMb} MB)` : 'Invalid upload' });
  }
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
  const status = err.status && err.status < 500 ? err.status : 500;
  if (status === 500) log.error('unhandled error', { path: req.path, err: err.stack || String(err) });
  // Never leak internals (stack traces, DB messages) to the client
  res.status(status).json({ error: status === 500 ? 'Something went wrong on our side' : err.message });
});

/* ===================================================================
 * 5. SOCKET.IO LIFECYCLE
 *   connect -> (cookie check) -> join "user:<id>" room
 *   joinGroup   -> verify membership -> join "group:<id>" room
 *   sendMessage -> validate + rate-limit -> save to DB -> emit "newMessage" to the group room
 *   typing      -> relayed to the others in the room (never stored)
 *   disconnect  -> Socket.io removes the socket from all rooms automatically
 * A "room" is just a named list of sockets: emitting to a room reaches only them.
 * =================================================================== */
io.use(async (socket, next) => {                 // runs once per connection attempt
  let payload;
  try {
    const { origin, host, cookie } = socket.handshake.headers;
    if (!authLib.originAllowed(origin, host)) throw new Error('bad origin');   // blocks cross-site WebSocket hijacking
    payload = authLib.verify(authLib.parseCookies(cookie)[authLib.COOKIE]);
  } catch {
    return next(new Error('unauthorized'));
  }
  try {
    // Load the reading-language settings once; translateAndPush() reads them from socket.data
    const user = await User.findById(payload.id, 'language autoTranslate').lean();
    if (!user) return next(new Error('unauthorized'));
    socket.user = { id: payload.id, username: payload.username };
    socket.data.user = socket.user;
    socket.data.prefs = settingsOf(user);
    next();
  } catch (err) {
    log.error('socket auth lookup failed', { err: err.message });
    next(new Error('server error'));               // not "unauthorized": the browser must not log the user out for a DB hiccup
  }
});

// Token bucket: allows a burst of `burst` messages, then `perSecond` sustained. Stops chat flooding.
function makeBucket(burst, perSecond) {
  let tokens = burst;
  let last = Date.now();
  return () => {
    const now = Date.now();
    tokens = Math.min(burst, tokens + ((now - last) / 1000) * perSecond);
    last = now;
    if (tokens < 1) return false;
    tokens -= 1;
    return true;
  };
}

io.on('connection', (socket) => {
  socket.join('user:' + socket.user.id);
  const allowMessage = makeBucket(10, 2);
  let lastTyping = 0;

  socket.on('joinGroup', async (groupId, ack) => {
    let ok = false;
    try {
      ok = v.isObjectId(groupId) && !!(await Group.exists({ _id: groupId, members: socket.user.id }));
      if (ok) socket.join('group:' + groupId);
    } catch (err) { log.error('joinGroup failed', { err: err.message }); }
    if (typeof ack === 'function') ack(ok);
  });

  socket.on('typing', (payload) => {
    const groupId = payload && payload.groupId;
    if (!v.isObjectId(groupId) || !socket.rooms.has('group:' + groupId)) return;
    if (Date.now() - lastTyping < 1000) return;                // at most 1 relay per second
    lastTyping = Date.now();
    socket.to('group:' + groupId).emit('typing', { groupId, username: socket.user.username });
  });

  socket.on('sendMessage', async (payload, ack) => {
    const reply = (r) => { if (typeof ack === 'function') ack(r); };
    try {
      const { groupId, text } = payload || {};
      const clean = v.messageText(text);
      if (!clean) return reply({ ok: false, error: 'Message must be 1-4000 characters' });
      if (!v.isObjectId(groupId) || !socket.rooms.has('group:' + groupId)) return reply({ ok: false, error: 'You are not in this group' });
      if (!allowMessage()) return reply({ ok: false, error: 'You are sending messages too fast' });
      await saveAndBroadcast({ groupId, senderId: socket.user.id, text: clean });
      reply({ ok: true });
    } catch (err) {
      log.error('sendMessage failed', { err: err.message });
      reply({ ok: false, error: 'Could not send the message' });
    }
  });
});

/* ===================================================================
 * 6. LIFECYCLE: start + graceful shutdown
 * =================================================================== */
async function start(mongoUri = config.mongoUri, port = config.port) {
  try {
    await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 10000 });
  } catch (err) {
    log.error(`Cannot connect to MongoDB (${mongoUri.replace(/\/\/[^@]*@/, '//***@')}). Is MongoDB running? Set MONGO_URI if it lives elsewhere.`, { err: err.message });
    throw err;
  }
  // Make sure all indexes exist - above all the UNIQUE (groupId + hash) index that backs deduplication.
  await Promise.all([User, Group, Message, FileHash].map((m) => m.init()));
  await new Promise((resolve, reject) => {
    server.once('error', reject);                              // e.g. EADDRINUSE: port already taken
    server.listen(port, resolve);
  });
  log.info(`SmartShare running on http://localhost:${server.address().port}`, { env: config.isProd ? 'production' : 'development' });
  return server;
}

// On SIGTERM (deploys, Docker stop) finish in-flight work, then close connections cleanly.
async function shutdown(signal) {
  log.info('shutting down', { signal });
  const force = setTimeout(() => process.exit(1), 10000);
  force.unref();
  try {
    await new Promise((resolve) => io.close(resolve));         // also closes the HTTP server
    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    log.error('error during shutdown', { err: err.message });
    process.exit(1);
  }
}

if (require.main === module) {
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => log.error('unhandledRejection', { err: String(reason && reason.stack || reason) }));
  process.on('uncaughtException', (err) => { log.error('uncaughtException', { err: err.stack }); process.exit(1); });
  start().catch(() => process.exit(1));
}

module.exports = { app, server, io, start };
