/**
 * app.js  -  FRONTEND LOGIC (vanilla JS, no framework)
 * ------------------------------------------------------------------
 * Sections:
 *   A. State & helpers        E. Sending text + uploading files
 *   B. Session (login/out)    F. Media gallery + storage stats
 *   C. Chats sidebar, user picker, one-to-one chats
 *   D. Chat window (+ edit / delete for everyone)
 *   G. Socket.io real-time listeners      H. Boot
 *
 * DATA FLOW SUMMARY
 *   login       : form -> POST /api/login -> server sets an httpOnly cookie (JS can't read it)
 *   send text   : input -> socket.emit('sendMessage') -> server saves -> 'newMessage' to room -> render
 *   send file   : input -> fetch POST /upload (multipart) -> server hashes -> 'newMessage' to room -> render
 *                 (server decides: normal media bubble  OR  duplicate "System Alert" bubble)
 * The browser never decides what is a duplicate - the server is the single source of truth.
 *
 * SECURITY NOTE: every piece of user text is inserted with textContent (never innerHTML),
 * so a message like "<img onerror=...>" is shown as plain text and cannot run code (XSS-safe).
 */

/* ===================== A. STATE & HELPERS ===================== */
const $ = (id) => document.getElementById(id);
const state = {
  user: null,
  maxFileMb: 25,
  groups: [],
  activeGroupId: null,
  unread: {},            // groupId -> messages received while another chat is open
  socket: null,
  everConnected: false,  // lets us tell a reconnect from the first connect
  registerMode: false,
  oldestId: null,        // id of the oldest message on screen (cursor for "load older")
  hasMore: false,
  uploading: false,
  settings: { language: 'en', autoTranslate: true },
  translation: { enabled: false, languages: [] },   // is auto-translate available on this server, and which languages
  chatFilter: '',        // text typed in the "Search chats" box
  msgById: {},           // every message on screen by id (so a late translation can update the right bubble)
};

// fetch wrapper: JSON in/out, cookies sent automatically, readable errors.
// A 401 anywhere (session expired) sends the user back to the login screen.
async function api(path, options = {}) {
  const { noAuthRedirect, ...opts } = options;
  const headers = { ...(opts.headers || {}) };
  if (opts.body && !(opts.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, { ...opts, headers, credentials: 'same-origin' });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !noAuthRedirect) { showAuth(); throw new Error('Please log in again'); }
  if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
  return data;
}

function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.classList.remove('hidden');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add('hidden'), 3500);
}

const fmtTime = (d) => new Date(d).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const fmtDate = (d) => new Date(d).toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
const fmtBytes = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB');

// Tiny DOM builder. Uses textContent (never innerHTML) so user text can't inject HTML/XSS.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  children.forEach((c) => node.append(c));
  return node;
}

// Round coloured initial: the colour comes from the name, so the same person always looks the same.
function paintAvatar(node, name, isGroup = false) {
  let h = 0;
  for (const ch of String(name)) h = (h * 31 + ch.charCodeAt(0)) % 360;
  node.textContent = String(name).trim().charAt(0) || '?';
  node.style.setProperty('--h', h);
  node.classList.toggle('group', !!isGroup);
  return node;
}
const avatarFor = (name, isGroup) => {
  const a = paintAvatar(el('span', { className: 'avatar' }), name, isGroup);
  a.setAttribute('aria-hidden', 'true');
  return a;
};

/* ===================== B. SESSION (LOGIN / LOGOUT) ===================== */
function showAuth() {
  if (state.socket) { state.socket.disconnect(); state.socket = null; }
  state.user = null;
  $('app-screen').classList.add('hidden');
  $('auth-screen').classList.remove('hidden');
  $('auth-password').value = '';
}

function setRegisterMode(on) {
  state.registerMode = on;
  $('auth-email-row').classList.toggle('hidden', !on);
  $('auth-email').required = on;
  $('pw-meter').classList.toggle('hidden', !on);
  $('pw-hint').classList.toggle('hidden', !on);
  $('auth-password').autocomplete = on ? 'new-password' : 'current-password';
  $('auth-password').placeholder = on ? 'At least 8 characters' : 'Enter your password';
  $('auth-language-row').classList.toggle('hidden', !(on && state.translation.enabled));
  $('auth-title').textContent = on ? 'Create an account' : 'Welcome back';
  $('auth-sub').textContent = on ? 'Already have an account?' : 'New here?';
  $('auth-toggle').textContent = on ? 'Log in' : 'Create an account';
  $('auth-submit').textContent = on ? 'Create account' : 'Log in';
  $('auth-error').textContent = '';
  updateStrength();
}

// Password strength bar (register only). Purely advisory - the server enforces the real rule (8-72 characters).
function passwordScore(pw) {
  if (pw.length < 8) return pw.length ? 1 : 0;
  let score = 2;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw)) score++;
  else if (/[^A-Za-z0-9]/.test(pw) && pw.length >= 10) score++;
  return Math.min(score, 4);
}
function updateStrength() {
  const pw = $('auth-password').value;
  const score = passwordScore(pw);
  $('pw-meter').dataset.score = score;
  $('pw-hint').textContent = !pw ? 'Use 8+ characters. Mixing letters, numbers and symbols is stronger.'
    : ['', 'Too short - use at least 8 characters', 'Okay - longer is better', 'Good', 'Strong'][score];
}
$('auth-password').oninput = updateStrength;
$('pw-toggle').onclick = () => {
  const show = $('auth-password').type === 'password';
  $('auth-password').type = show ? 'text' : 'password';
  $('pw-toggle').setAttribute('aria-pressed', String(show));
  $('pw-toggle').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
};

// Rotating highlights on the artwork (stops for people who prefer reduced motion)
(function slides() {
  const items = [...document.querySelectorAll('#auth-slides .slide')], dots = [...document.querySelectorAll('#auth-dots .dot')];
  let i = 0, timer;
  const show = (n) => { i = n; items.forEach((x, k) => x.classList.toggle('active', k === n)); dots.forEach((x, k) => x.classList.toggle('active', k === n)); };
  dots.forEach((d, k) => (d.onclick = () => { show(k); restart(); }));
  const restart = () => { clearInterval(timer); if (!matchMedia('(prefers-reduced-motion: reduce)').matches) timer = setInterval(() => show((i + 1) % items.length), 5000); };
  restart();
})();
$('auth-toggle').onclick = (e) => { e.preventDefault(); setRegisterMode(!state.registerMode); };
setRegisterMode(false);

// ---- AUTO-TRANSLATE settings ----
function fillLanguages(select, languages, selected) {
  select.replaceChildren(...languages.map((l) => el('option', { value: l.code, textContent: `${l.native} (${l.name})` })));
  select.value = languages.some((l) => l.code === selected) ? selected : 'en';
}

// Public language list for the register form; the browser's own language is pre-selected.
async function loadLanguages() {
  try {
    const d = await (await fetch('/api/languages')).json();
    state.translation = { enabled: d.enabled, languages: d.languages };
    fillLanguages($('auth-language'), d.languages, (navigator.language || 'en').slice(0, 2));
    setRegisterMode(state.registerMode);
  } catch { /* the form still works without it */ }
}
loadLanguages();

// Called after login / page load with the server's session info.
function applySession(session) {
  state.user = session.user;
  state.settings = session.settings;
  state.translation = session.translation;
  state.maxFileMb = session.maxFileMb || state.maxFileMb;
  fillLanguages($('lang-select'), state.translation.languages, state.settings.language);
  $('auto-translate').checked = state.settings.autoTranslate;
  $('translate-settings').classList.toggle('hidden', !state.translation.enabled);
}

async function saveSettings() {
  try {
    const { settings } = await api('/api/me/settings', { method: 'PATCH', body: { language: $('lang-select').value, autoTranslate: $('auto-translate').checked } });
    state.settings = settings;
    toast('Reading language saved');
    if (state.activeGroupId) openGroup(state.activeGroupId);   // reload the chat: cached translations come back in the new language
  } catch (err) { toast(err.message); }
}
$('lang-select').onchange = saveSettings;
$('auto-translate').onchange = saveSettings;

$('auth-form').onsubmit = async (e) => {
  e.preventDefault();
  const button = $('auth-submit');
  button.disabled = true;
  try {
    const body = { username: $('auth-username').value, password: $('auth-password').value };
    if (state.registerMode) { body.email = $('auth-email').value; body.language = $('auth-language').value; }
    const data = await api(state.registerMode ? '/api/register' : '/api/login', { method: 'POST', body, noAuthRedirect: true });
    await startApp(data);
  } catch (err) {
    $('auth-error').textContent = err.message;
  } finally {
    button.disabled = false;
  }
};

$('logout-btn').onclick = async () => {
  await api('/api/logout', { method: 'POST', noAuthRedirect: true }).catch(() => {});
  location.reload();
};

/* ===================== C. GROUPS SIDEBAR ===================== */
async function startApp(session) {
  const user = session.user;
  applySession(session);
  $('auth-screen').classList.add('hidden');
  $('app-screen').classList.remove('hidden');
  $('me-name').textContent = user.username;
  paintAvatar($('me-avatar'), user.username);
  connectSocket();
  await loadGroups();
}

async function loadGroups() {
  state.groups = await api('/api/groups');
  renderGroups();
  // Join every group's socket room so we get live messages (and unread badges) for all of them
  state.groups.forEach((g) => state.socket && state.socket.emit('joinGroup', g.id));
}

function renderGroups() {
  const list = $('group-list');
  const q = state.chatFilter.trim().toLowerCase();
  const shown = state.groups.filter((g) => !q || g.name.toLowerCase().includes(q));
  if (!shown.length) {
    list.replaceChildren(el('li', { className: 'list-empty', textContent: q ? 'No chat matches your search' : 'No chats yet - press 💬 for a one-to-one chat or 👥 to make a group' }));
    return;
  }
  list.replaceChildren(...shown.map((g) => {
    const li = el('li', { className: g.id === state.activeGroupId ? 'active' : '', tabIndex: 0 },
      avatarFor(g.name, !g.isDirect),
      el('span', { className: 'meta' }, el('strong', { textContent: g.name }), el('small', { textContent: g.isDirect ? 'One-to-one chat' : g.memberCount + ' members' })));
    if (state.unread[g.id]) li.append(el('span', { className: 'badge', textContent: state.unread[g.id] }));
    li.onclick = () => openGroup(g.id);
    li.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openGroup(g.id); } };
    return li;
  }));
}
$('back-btn').onclick = () => {                                  // phones: back to the chat list
  $('app-screen').classList.remove('chat-open');
  state.activeGroupId = null;
  renderGroups();
};
$('chat-filter').oninput = (e) => { state.chatFilter = e.target.value; renderGroups(); };

/* ---------- USER PICKER: every registered user (except me) as suggestions, searchable ---------- */
// multi=true  -> tick several people (new group / add members); selected() returns their usernames
// multi=false -> clicking a person calls onPick(user) straight away (new one-to-one chat)
// getGroupId  -> when set, people who are already in that group are greyed out
function createPicker(root, { multi = true, getGroupId = null, onPick = null } = {}) {
  const chosen = new Set();
  const search = el('input', { type: 'search', placeholder: 'Search people…', autocomplete: 'off', maxLength: 20 });
  search.setAttribute('aria-label', 'Search people');
  const chips = el('div', { className: 'picker-chips' });
  const list = el('ul', { className: 'picker-list', role: 'listbox' });
  const note = el('div', { className: 'picker-note', role: 'status' });
  root.className = 'picker';
  root.replaceChildren(search, chips, list, note);
  let seq = 0, timer;

  function drawChips() {
    chips.replaceChildren(...[...chosen].map((name) => {
      const x = el('button', { type: 'button', textContent: '×', title: 'Remove ' + name });
      x.setAttribute('aria-label', 'Remove ' + name);
      x.onclick = () => { chosen.delete(name); drawChips(); list.querySelectorAll('li').forEach(mark); };
      return el('span', { className: 'chip' }, document.createTextNode(name), x);
    }));
  }
  function mark(li) {
    if (!li.dataset.username || li.classList.contains('disabled')) return;
    const on = chosen.has(li.dataset.username);
    li.classList.toggle('selected', on);
    li.setAttribute('aria-selected', String(on));
    const tick = li.querySelector('.tick');
    if (tick) tick.textContent = on ? '✓' : '';
  }
  function row(u) {
    const li = el('li', { tabIndex: 0, role: 'option' }, avatarFor(u.username), el('span', { className: 'name', textContent: u.username }));
    li.dataset.username = u.username;
    if (u.inGroup) {
      li.classList.add('disabled');
      li.setAttribute('aria-disabled', 'true');
      li.append(el('span', { className: 'tag', textContent: 'already in group' }));
      return li;
    }
    if (multi) li.append(el('span', { className: 'tick' }));
    const act = () => {
      if (!multi) return onPick && onPick(u);
      chosen.has(u.username) ? chosen.delete(u.username) : chosen.add(u.username);
      mark(li); drawChips();
    };
    li.onclick = act;
    li.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); act(); } };
    mark(li);
    return li;
  }
  async function load() {
    const mine = ++seq;
    note.textContent = 'Loading people…';
    try {
      const qs = new URLSearchParams();
      if (search.value.trim()) qs.set('q', search.value.trim());
      if (getGroupId && getGroupId()) qs.set('groupId', getGroupId());
      const { users, hasMore } = await api('/api/users?' + qs);
      if (mine !== seq) return;                                // a newer search already replaced this one
      list.replaceChildren(...users.map(row));
      note.textContent = !users.length ? (search.value.trim() ? 'Nobody found with that name' : 'Nobody else has registered yet')
        : hasMore ? 'Showing the first results - type to find someone' : users.length + (users.length === 1 ? ' person' : ' people');
    } catch (err) { if (mine === seq) note.textContent = err.message; }
  }
  search.oninput = () => { clearTimeout(timer); timer = setTimeout(load, 200); };
  search.onkeydown = (e) => { if (e.key === 'Enter') e.preventDefault(); };      // Enter must not submit the dialog's form
  return {
    load, selected: () => [...chosen],
    reset() { chosen.clear(); search.value = ''; drawChips(); return load(); },
  };
}

// --- New one-to-one chat ---
const chatPicker = createPicker($('chat-picker'), { multi: false, onPick: startDirectChat });
$('new-chat-btn').onclick = () => { $('chat-dialog').showModal(); chatPicker.reset(); };
async function startDirectChat(user) {
  try {
    const g = await api('/api/chats/direct', { method: 'POST', body: { username: user.username } });
    $('chat-dialog').close();
    await loadGroups();
    openGroup(g.id);
  } catch (err) { toast(err.message); }
}
document.querySelectorAll('[data-close]').forEach((b) => (b.onclick = () => $(b.dataset.close).close()));

// --- New group ---
const groupPicker = createPicker($('group-picker'));
$('new-group-btn').onclick = () => { $('group-form').reset(); $('group-dialog').showModal(); groupPicker.reset(); };
$('group-form').onsubmit = async (e) => {
  if (e.submitter && e.submitter.value === 'cancel') return;
  try {
    const g = await api('/api/groups', { method: 'POST', body: { name: $('group-name').value, memberUsernames: groupPicker.selected() } });
    $('group-form').reset();
    if (g.notFound && g.notFound.length) toast('Not registered yet: ' + g.notFound.join(', '));
    await loadGroups();
    openGroup(g.id);
  } catch (err) { toast(err.message); }
};

// --- Add members to the open group ---
const memberPicker = createPicker($('member-picker'), { getGroupId: () => state.activeGroupId });
$('add-member-btn').onclick = () => { $('member-dialog').showModal(); memberPicker.reset(); };
$('member-form').onsubmit = async (e) => {
  if (e.submitter && e.submitter.value === 'cancel') return;
  const usernames = memberPicker.selected();
  if (!usernames.length) { e.preventDefault(); toast('Pick at least one person'); return; }
  try {
    const r = await api(`/api/groups/${state.activeGroupId}/members`, { method: 'POST', body: { usernames } });
    toast(r.added.length ? 'Added: ' + r.added.join(', ') : 'Already in the group');
    await loadGroups();
    if (state.activeGroupId) openGroup(state.activeGroupId);
  } catch (err) { toast(err.message); }
};

/* ===================== D. CHAT WINDOW / RENDERING ===================== */
const olderButton = el('button', { type: 'button', className: 'load-older hidden', textContent: 'Load older messages' });
olderButton.onclick = loadOlder;

async function openGroup(groupId) {
  state.activeGroupId = groupId;
  state.unread[groupId] = 0;
  const group = state.groups.find((g) => g.id === groupId);
  $('empty-state').classList.add('hidden');
  $('chat-view').classList.remove('hidden');
  $('app-screen').classList.add('chat-open');                  // phones: switch from the chat list to the chat
  $('chat-title').textContent = group.name;
  $('chat-sub').textContent = group.isDirect ? 'One-to-one chat' : group.memberCount + ' members';
  paintAvatar($('chat-avatar'), group.name, !group.isDirect);
  $('add-member-btn').classList.toggle('hidden', !!group.isDirect);    // people cannot be added to a 1-to-1 chat
  $('typing').textContent = '';
  renderGroups();

  try {
    // history comes over HTTP (newest page only)...  live messages come over the socket
    const { messages, hasMore } = await api(`/api/groups/${groupId}/messages`);
    if (state.activeGroupId !== groupId) return;           // user already switched to another chat
    state.hasMore = hasMore;
    state.oldestId = messages.length ? messages[0].id : null;
    olderButton.classList.toggle('hidden', !hasMore);
    $('messages').replaceChildren(olderButton, ...messages.map(renderMessage));
    scrollToBottom();
    if (!$('gallery').classList.contains('hidden')) loadGallery();
  } catch (err) { toast(err.message); }
}

async function loadOlder() {
  if (!state.hasMore || !state.oldestId) return;
  olderButton.disabled = true;
  try {
    const box = $('messages');
    const { messages, hasMore } = await api(`/api/groups/${state.activeGroupId}/messages?before=${state.oldestId}`);
    const heightBefore = box.scrollHeight;
    olderButton.after(...messages.map(renderMessage));
    box.scrollTop += box.scrollHeight - heightBefore;      // keep the reader where they were
    state.hasMore = hasMore;
    if (messages.length) state.oldestId = messages[0].id;
    olderButton.classList.toggle('hidden', !hasMore);
  } catch (err) { toast(err.message); }
  olderButton.disabled = false;
}

function scrollToBottom() { const m = $('messages'); m.scrollTop = m.scrollHeight; }

// Turn one message object from the server into a DOM node.
// msg.type is set by the server: 'text' | 'media' | 'duplicate'
function renderMessage(msg) {
  state.msgById[msg.id] = msg;
  if (msg.type === 'duplicate') return renderDuplicateAlert(msg);

  const mine = msg.senderId === state.user.id;
  const bubble = el('div', { className: 'bubble' + (mine ? ' me' : '') + (msg.type === 'deleted' ? ' deleted' : '') });
  bubble.dataset.id = msg.id;                                // lets "jump to original" find this bubble
  if (msg.type === 'deleted') {                              // DELETE FOR EVERYONE leaves only this tombstone
    bubble.append(el('div', { textContent: mine ? '🚫 You deleted this message' : '🚫 This message was deleted' }),
      el('div', { className: 'time', textContent: fmtTime(msg.timestamp) }));
    return bubble;
  }
  if (!mine) bubble.append(el('div', { className: 'who', textContent: msg.senderName }));
  if (mine) bubble.append(renderActions(msg));

  if (msg.type === 'media' && msg.file) bubble.append(renderFile(msg.file));
  if (msg.similar) bubble.append(renderSimilarNote(msg.similar));
  const shown = msg.translation && !msg.showOriginal ? msg.translation : null;   // AUTO-TRANSLATE: show it unless the reader asked for the original
  if (msg.text) bubble.append(renderText(msg, shown));
  const note = renderTranslationNote(msg);
  if (note) bubble.append(note);
  renderLinkNotices(msg).forEach((n) => bubble.append(n));
  bubble.append(el('div', { className: 'time', textContent: (msg.edited ? 'edited · ' : '') + fmtTime(msg.timestamp) }));
  return bubble;
}

function refreshBubble(msg) {
  const node = $('messages').querySelector(`[data-id="${msg.id}"]`);
  if (node) node.replaceWith(renderMessage(msg));
}

// Message text. With link parts: text -> text nodes, links -> safety-checked link chips. Never innerHTML.
// `translation` (optional) replaces the text pieces but keeps the same links.
function renderText(msg, translation) {
  const box = el('div', {});
  const parts = translation && translation.parts ? translation.parts : msg.parts;
  if (!parts) { box.textContent = translation && translation.text !== undefined ? translation.text : msg.text; return box; }
  parts.forEach((p) => box.append(p.type === 'link' ? renderLinkChip(p) : document.createTextNode(p.value)));
  return box;
}

/* ---------- EDIT + DELETE FOR EVERYONE (own messages only; the server re-checks everything) ---------- */
const EDIT_WINDOW_MS = 15 * 60 * 1000;
function renderActions(msg) {
  const box = el('div', { className: 'actions' });
  if (msg.type === 'text' && Date.now() - new Date(msg.timestamp).getTime() < EDIT_WINDOW_MS) {
    const edit = el('button', { type: 'button', textContent: '✏️', title: 'Edit (within 15 minutes)' });
    edit.setAttribute('aria-label', 'Edit message');
    edit.onclick = () => startEdit(msg);
    box.append(edit);
  }
  const del = el('button', { type: 'button', textContent: '🗑', title: 'Delete for everyone' });
  del.setAttribute('aria-label', 'Delete message for everyone');
  del.onclick = () => askDelete(msg);
  box.append(del);
  return box;
}

function startEdit(msg) {
  const node = $('messages').querySelector(`[data-id="${msg.id}"]`);
  if (!node) return;
  const input = el('input', { value: msg.text, maxLength: 4000 });
  input.setAttribute('aria-label', 'Edit message');
  const save = el('button', { type: 'button', textContent: 'Save' });
  const cancel = el('button', { type: 'button', className: 'secondary', textContent: 'Cancel' });
  node.replaceChildren(el('div', { className: 'edit-box' }, input, el('div', { className: 'edit-row' }, cancel, save)));
  input.focus(); input.select();
  const close = () => refreshBubble(state.msgById[msg.id] || msg);
  cancel.onclick = close;
  input.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); save.click(); } else if (e.key === 'Escape') close(); };
  save.onclick = async () => {
    const text = input.value.trim();
    if (!text) return toast('A message cannot be empty');
    if (text === msg.text) return close();
    save.disabled = true;
    try {
      const { message } = await api(`/api/groups/${msg.groupId}/messages/${msg.id}`, { method: 'PATCH', body: { text } });
      state.msgById[message.id] = message;
      refreshBubble(message);
    } catch (err) { toast(err.message); save.disabled = false; }
  };
}

let pendingDelete = null;
function askDelete(msg) {
  pendingDelete = msg;
  $('delete-text').textContent = msg.type === 'media'
    ? 'The message disappears for everyone and the file leaves this chat\'s media gallery. The file is erased from the server only if no other group uses it.'
    : 'The message disappears for everyone in this chat. This cannot be undone.';
  $('delete-dialog').showModal();
  $('delete-cancel').focus();                                 // the safe choice is focused by default
}
$('delete-cancel').onclick = () => $('delete-dialog').close();
$('delete-confirm').onclick = async () => {
  const msg = pendingDelete;
  if (!msg) return;
  $('delete-confirm').disabled = true;
  try {
    const r = await api(`/api/groups/${msg.groupId}/messages/${msg.id}`, { method: 'DELETE' });
    $('delete-dialog').close();
    applyDeleted({ ids: r.ids, groupId: msg.groupId });
    toast(r.fileRemoved ? 'Deleted - the file was removed from this chat' : 'Message deleted');
  } catch (err) { toast(err.message); }
  $('delete-confirm').disabled = false;
};

// ids[0] = the deleted message (becomes a tombstone); any further ids were duplicate-alert notices about that file (removed).
function applyDeleted({ ids, groupId }) {
  ids.forEach((id, i) => {
    const node = $('messages').querySelector(`[data-id="${id}"]`);
    const msg = state.msgById[id];
    if (i === 0 && msg) {
      state.msgById[id] = { ...msg, type: 'deleted', deleted: true, text: '', file: null, parts: null, similar: null, translation: null, canTranslate: false };
      if (node) node.replaceWith(renderMessage(state.msgById[id]));
    } else if (node) node.remove();
    if (i > 0) delete state.msgById[id];
  });
  if (groupId === state.activeGroupId && !$('gallery').classList.contains('hidden')) loadGallery();
}

/* ---------- FRAUD-LINK CHECK: link chip + permission dialog ---------- */
const RISK = {
  safe:       { icon: '✅', label: 'Safe',       title: 'Looks safe',                      color: 'var(--safe)',       btn: '',        open: 'Open link' },
  suspicious: { icon: '⚠️', label: 'Suspicious', title: 'Be careful - suspicious link',    color: 'var(--suspicious)', btn: 'caution', open: 'Open anyway' },
  dangerous:  { icon: '⛔', label: 'Dangerous',  title: 'Dangerous link - likely a scam',  color: 'var(--danger)',     btn: 'danger',  open: 'Open anyway (not recommended)' },
  unknown:    { icon: '❔', label: 'Not checked', title: 'This link was not checked',      color: 'var(--muted)',      btn: 'caution', open: 'Open anyway' },
};
const RISK_NOTE = {
  safe: 'No warning signs were found. That does not guarantee the website is safe - never type passwords, OTPs or card details on a page you did not expect.',
  suspicious: 'Do not enter passwords, OTPs or card details here. If you are unsure, ask the sender on another channel first.',
  dangerous: 'Scammers use links like this to steal money and passwords. Opening it is strongly discouraged.',
  unknown: 'This message was sent before link checks existed. Treat the link with care.',
};

// The link is a BUTTON, not an <a href>: it cannot be opened by a stray click, middle-click or "open in new tab".
// Clicking opens the permission dialog below, which shows the risk and the REAL destination.
function renderLinkChip(p) {
  const level = p.risk ? p.risk.level : 'unknown';
  const cfg = RISK[level] || RISK.unknown;
  const btn = el('button', { type: 'button', className: 'msg-link risk-' + level, textContent: p.value, title: 'Check this link before opening' });
  btn.onclick = () => openLinkDialog(p);
  const badge = el('span', { className: 'risk-badge ' + level, textContent: p.risk ? `${cfg.icon} ${cfg.label} · ${p.risk.score}% risk` : `${cfg.icon} ${cfg.label}` });
  const frag = document.createDocumentFragment();
  frag.append(btn, badge);
  return frag;
}

let pendingLink = null;
function openLinkDialog(p) {
  const level = p.risk ? p.risk.level : 'unknown';
  const cfg = RISK[level] || RISK.unknown;
  pendingLink = { url: p.url, level };
  $('link-icon').textContent = cfg.icon;
  $('link-title').textContent = cfg.title;
  $('link-title').style.color = cfg.color;
  $('link-percent').textContent = p.risk ? `Risk score: ${p.risk.score}%  ·  ${cfg.label}` : 'No risk information available';
  $('risk-fill').style.width = (p.risk ? Math.max(p.risk.score, 3) : 50) + '%';
  $('risk-fill').style.background = cfg.color;
  $('link-host').textContent = p.host || new URL(p.url).hostname;
  $('link-url').textContent = p.url;
  $('link-reasons').replaceChildren(...((p.risk && p.risk.reasons) || []).map((r) => el('li', { textContent: r })));
  $('link-note').textContent = RISK_NOTE[level];
  // Dangerous links need an explicit "I understand" tick before the open button works
  $('link-ack').checked = false;
  $('link-ack-row').classList.toggle('hidden', level !== 'dangerous');
  const open = $('link-open');
  open.textContent = cfg.open;
  open.className = cfg.btn;
  open.disabled = level === 'dangerous';
  $('link-dialog').showModal();
  $('link-cancel').focus();                                   // the safe choice is focused by default
}
$('link-ack').onchange = () => { $('link-open').disabled = !$('link-ack').checked; };
$('link-cancel').onclick = () => $('link-dialog').close();
$('link-open').onclick = () => {
  if (!pendingLink || (pendingLink.level === 'dangerous' && !$('link-ack').checked)) return;
  window.open(pendingLink.url, '_blank', 'noopener,noreferrer');   // noopener: the new page cannot touch this chat
  $('link-dialog').close();
};

/* ---------- SIMILAR-IMAGE note ---------- */
function renderSimilarNote(similar) {
  const f = similar.file;
  const box = el('div', { className: 'similar-note' });
  box.append(document.createTextNode(`🖼 Looks ${similar.similarity}% similar to an image` + (f ? ` shared by ${f.originalSenderName} on ${fmtDate(f.originalTimestamp)} ` : ' already in this group ')));
  if (f) box.append(el('a', { href: f.url, target: '_blank', rel: 'noopener', textContent: 'View it' }));
  return box;
}

/* ---------- AUTO-TRANSLATE note + manual button ---------- */
const langName = (code) => (state.translation.languages.find((l) => l.code === code) || { name: code }).name;

function renderTranslationNote(msg) {
  if (msg.translation) {
    const toggle = el('button', { type: 'button', textContent: msg.showOriginal ? 'Show translation' : 'Show original' });
    toggle.onclick = () => { msg.showOriginal = !msg.showOriginal; refreshBubble(msg); };
    return el('div', { className: 'translated-note' }, document.createTextNode(msg.showOriginal ? '🌐 Original · ' : `🌐 Translated to ${langName(msg.translation.lang)} · `), toggle);
  }
  if (msg.canTranslate) {                                    // old message that has no translation yet
    const btn = el('button', { type: 'button', className: 'translate-btn', textContent: '🌐 Translate' });
    btn.onclick = async () => {
      btn.disabled = true;
      try {
        const { translation } = await api(`/api/groups/${msg.groupId}/messages/${msg.id}/translate`, { method: 'POST' });
        msg.translation = translation;
        msg.canTranslate = false;
        if (!translation) toast('Already in your language');
        refreshBubble(msg);
      } catch (err) { toast(err.message); btn.disabled = false; }
    };
    return el('div', { className: 'translated-note' }, btn);
  }
  return null;
}

// For links already shared earlier in this group: "🔁 Already shared by bob on 28 Oct, 09:30  [Show]"
function renderLinkNotices(msg) {
  const seen = new Set();
  const notices = [];
  (msg.parts || []).forEach((p) => {
    if (p.type !== 'link' || !p.dup || seen.has(p.dup.messageId)) return;
    seen.add(p.dup.messageId);
    const jump = el('button', { type: 'button', className: 'link-jump', textContent: 'Show' });
    jump.onclick = () => jumpToMessage(p.dup.messageId);
    notices.push(el('div', { className: 'link-dup' },
      el('span', { textContent: `🔁 Link already shared by ${p.dup.senderName} on ${fmtDate(p.dup.timestamp)} ` }), jump));
  });
  return notices;
}

function jumpToMessage(id) {
  const target = $('messages').querySelector(`[data-id="${id}"]`);
  if (!target) return toast('The original message is in older history - use "Load older messages"');
  target.scrollIntoView({ block: 'center' });
  target.classList.add('flash');
  setTimeout(() => target.classList.remove('flash'), 1800);
}

function renderFile(file) {
  if (file.mimeType.startsWith('image/')) return el('img', { src: file.url, alt: file.name, loading: 'lazy' });
  if (file.mimeType.startsWith('video/')) return el('video', { src: file.url, controls: true, preload: 'metadata' });
  if (file.mimeType.startsWith('audio/')) return el('audio', { src: file.url, controls: true, preload: 'metadata' });
  return el('a', { className: 'filelink', href: file.url, target: '_blank', rel: 'noopener', textContent: '📄 ' + (file.name || 'file') });
}

// THE DEDUP ALERT: a yellow system bubble instead of a second copy of the file.
function renderDuplicateAlert(msg) {
  const f = msg.file;
  const box = el('div', { className: 'alert' }, el('div', { textContent: '⚠ ' + msg.text }));
  box.dataset.id = msg.id;
  if (f) {
    const link = el('a', { href: f.url, target: '_blank', rel: 'noopener', textContent: 'View original file' });
    box.append(el('span', { className: 'orig' }, link,
      document.createTextNode(` shared by ${f.originalSenderName} on ${fmtDate(f.originalTimestamp)}`)));
  }
  return box;
}

/* ===================== E. SENDING TEXT + FILES ===================== */
$('send-form').onsubmit = (e) => {
  e.preventDefault();
  const text = $('text-input').value.trim();
  if (!text || !state.socket) return;
  $('text-input').value = '';
  // The server answers through the ack callback: ok, or a reason it refused (too fast, too long, ...)
  state.socket.emit('sendMessage', { groupId: state.activeGroupId, text }, (res) => {
    if (res && res.ok) return;
    toast((res && res.error) || 'Message not sent');
    if (!$('text-input').value) $('text-input').value = text;   // give the text back so it isn't lost
  });
};

// Tell the server "I'm typing" (at most once per 1.5 s so we don't flood the socket)
let lastTypingSent = 0;
$('text-input').oninput = () => {
  if (!state.socket || Date.now() - lastTypingSent < 1500) return;
  lastTypingSent = Date.now();
  state.socket.emit('typing', { groupId: state.activeGroupId });
};

async function uploadFile(file) {
  if (!file || state.uploading || !state.activeGroupId) return;
  if (file.size === 0) return toast('That file is empty');
  if (file.size > state.maxFileMb * 1024 * 1024) return toast(`File too large (max ${state.maxFileMb} MB)`);

  const form = new FormData();
  form.append('file', file);                 // multer reads the field named "file"
  state.uploading = true;
  $('attach-label').classList.add('busy');
  toast('Uploading ' + file.name + '…');
  try {
    const result = await api(`/api/groups/${state.activeGroupId}/upload`, { method: 'POST', body: form });
    // The chat bubble itself arrives through the socket; here we only give the uploader feedback.
    toast(result.duplicate ? 'Duplicate detected - nothing was stored twice' : result.similar ? 'Shared - but it looks similar to an image already in the group' : 'File shared');
  } catch (err) { toast(err.message); }
  state.uploading = false;
  $('attach-label').classList.remove('busy');
}

$('file-input').onchange = (e) => {
  const file = e.target.files[0];
  e.target.value = '';                       // allow picking the same file again
  uploadFile(file);
};

// Drag & drop a file anywhere on the chat panel
const chatPanel = document.querySelector('.chat');
['dragenter', 'dragover'].forEach((ev) => chatPanel.addEventListener(ev, (e) => { e.preventDefault(); chatPanel.classList.add('dragging'); }));
['dragleave', 'drop'].forEach((ev) => chatPanel.addEventListener(ev, (e) => { e.preventDefault(); chatPanel.classList.remove('dragging'); }));
chatPanel.addEventListener('drop', (e) => uploadFile(e.dataTransfer.files[0]));

/* ===================== F. MEDIA GALLERY + STORAGE STATS ===================== */
$('gallery-btn').onclick = () => {
  const open = $('gallery').classList.toggle('hidden') === false;
  $('gallery-btn').setAttribute('aria-expanded', String(open));
  if (open) loadGallery();
};

// Storage Savings dashboard: how much space did deduplication save in this group?
async function loadStats() {
  const s = await api(`/api/groups/${state.activeGroupId}/stats`);
  const card = (value, label, cls = '') => el('div', { className: 'stat ' + cls }, el('b', { textContent: value }), el('span', { textContent: label }));
  $('stats').replaceChildren(
    card(s.uniqueFiles, 'unique files'),
    card(fmtBytes(s.storedBytes), 'stored'),
    card(s.duplicatesBlocked, 'duplicates blocked', 'warn'),
    card(fmtBytes(s.bytesSaved), 'space saved', 'warn'));
}

async function loadGallery() {
  loadStats().catch(() => {});
  try {
    const files = await api(`/api/groups/${state.activeGroupId}/gallery`);
    $('gallery-grid').replaceChildren(...files.map((f) => {
      const thumb = el('div', { className: 'thumb' });
      thumb.append(
        f.mimeType.startsWith('image/') ? el('img', { src: f.url, alt: f.name, loading: 'lazy' })
        : f.mimeType.startsWith('video/') ? el('video', { src: f.url, muted: true, preload: 'metadata' })
        : '📄');
      return el('a', { className: 'gallery-item', href: f.url, target: '_blank', rel: 'noopener', title: f.name }, thumb,
        el('div', { className: 'meta', textContent: f.name || 'file' }),
        el('div', { className: 'meta', textContent: f.sharedBy + ' · ' + fmtDate(f.sharedAt) }));
    }));
    if (!files.length) $('gallery-grid').textContent = 'No media yet';
  } catch (err) { toast(err.message); }
}

/* ===================== G. SOCKET.IO LISTENERS ===================== */
function connectSocket() {
  // No token needed: the browser sends the httpOnly login cookie with the WebSocket handshake,
  // and the server's io.use() checks it.
  state.socket = io();

  state.socket.on('connect_error', (err) => { if (err.message === 'unauthorized') showAuth(); });

  state.socket.on('connect', () => {
    $('conn-banner').classList.add('hidden');
    // Rooms are lost when the socket drops, so join them again...
    state.groups.forEach((g) => state.socket.emit('joinGroup', g.id));
    // ...and after a RE-connect, reload the open chat to fill in anything missed while offline.
    if (state.everConnected && state.activeGroupId) openGroup(state.activeGroupId);
    state.everConnected = true;
  });
  state.socket.on('disconnect', (reason) => {
    if (reason !== 'io client disconnect') $('conn-banner').classList.remove('hidden');
  });

  state.socket.on('newMessage', (msg) => {
    if (msg.groupId === state.activeGroupId) {
      const box = $('messages');
      const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
      box.append(renderMessage(msg));
      if (nearBottom || msg.senderId === state.user.id) scrollToBottom();
      $('typing').textContent = '';
      // media OR duplicate alert both change the gallery/stats numbers
      if (msg.type !== 'text' && !$('gallery').classList.contains('hidden')) loadGallery();
    } else {
      state.unread[msg.groupId] = (state.unread[msg.groupId] || 0) + 1;
      renderGroups();
    }
  });

  // Someone else is typing in the open chat -> show for 2.5 s unless they keep typing
  // AUTO-TRANSLATE: the translation of a message arrives a moment after the message itself
  state.socket.on('messageTranslated', ({ id, translation }) => {
    const msg = state.msgById[id];
    if (!msg) return;
    msg.translation = translation;
    msg.canTranslate = false;
    refreshBubble(msg);
  });

  // EDIT: someone changed a message (translations follow separately via messageTranslated)
  state.socket.on('messageUpdated', (msg) => {
    state.msgById[msg.id] = msg;
    if (msg.groupId === state.activeGroupId) refreshBubble(msg);
  });
  // DELETE FOR EVERYONE
  state.socket.on('messageDeleted', (d) => applyDeleted(d));

  state.socket.on('typing', ({ groupId, username }) => {
    if (groupId !== state.activeGroupId) return;
    $('typing').textContent = username + ' is typing…';
    clearTimeout(state.typingTimer);
    state.typingTimer = setTimeout(() => ($('typing').textContent = ''), 2500);
  });

  // Someone created a group with me / added me to one
  state.socket.on('groupAdded', () => { loadGroups().catch(() => {}); });
}

/* ===================== H. BOOT ===================== */
// The login cookie is httpOnly (invisible to JS), so ask the server "am I logged in?"
api('/api/me', { noAuthRedirect: true })
  .then((data) => startApp(data))
  .catch(showAuth);

/* ===================== I. INSTALL AS AN APP (PWA) ===================== */
// 1) register the service worker (needs https, or localhost) - this is what makes the browser offer "Install"
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}
// 2) Chrome/Edge/Android fire `beforeinstallprompt` when the site is installable: keep it and show our own button.
//    (iPhone Safari has no such event: there the user taps Share > "Add to Home Screen".)
let deferredInstall = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredInstall = e;
  if (document.getElementById('install-btn')) return;
  const b = document.createElement('button');
  b.id = 'install-btn'; b.type = 'button'; b.className = 'install-btn'; b.textContent = 'Install app';
  b.addEventListener('click', async () => {
    b.remove();
    deferredInstall.prompt();
    await deferredInstall.userChoice.catch(() => {});
    deferredInstall = null;
  });
  document.body.appendChild(b);
});
window.addEventListener('appinstalled', () => { const b = document.getElementById('install-btn'); if (b) b.remove(); });
