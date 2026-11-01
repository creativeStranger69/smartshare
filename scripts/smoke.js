/**
 * scripts/smoke.js - end-to-end check against a RUNNING server (needs Node 18+).
 *
 *   1. start the app:   npm start
 *   2. in another terminal:   npm run smoke          (or BASE_URL=https://yourdomain npm run smoke)
 *
 * It registers throw-away users, creates a group, uploads the same file twice and checks the
 * deduplication result, the stats, and that outsiders / logged-out users cannot read files.
 */
const crypto = require('crypto');

const BASE = process.env.BASE_URL || 'http://localhost:3000';
const suffix = crypto.randomBytes(3).toString('hex');
let failed = 0;

// Minimal "browser": remembers the login cookie between requests.
function client() {
  let cookie = '';
  return async (path, { json, body, method } = {}) => {
    const headers = { cookie };
    if (json) headers['content-type'] = 'application/json';
    const res = await fetch(BASE + path, { method: method || (json || body ? 'POST' : 'GET'), headers, body: json ? JSON.stringify(json) : body });
    const set = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
    let data = null;
    try { data = await res.clone().json(); } catch { /* not JSON (file download) */ }
    return { status: res.status, data, res };
  };
}

function check(name, condition, detail = '') {
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}${condition ? '' : '  -> ' + detail}`);
  if (!condition) failed++;
}

(async () => {
  const alice = client(), bob = client(), mallory = client(), anon = client();
  const users = { alice: 'alice_' + suffix, bob: 'bob_' + suffix, mallory: 'mallory_' + suffix };

  for (const [who, c] of [['alice', alice], ['bob', bob], ['mallory', mallory]]) {
    const r = await c('/api/register', { json: { username: users[who], email: `${users[who]}@example.com`, password: 'correct-horse-battery' } });
    check(`register ${who}`, r.status === 201, JSON.stringify(r.data));
  }

  check('/api/me works with the login cookie', (await alice('/api/me')).data?.user?.username === users.alice);
  check('/api/me without cookie -> 401', (await anon('/api/me')).status === 401);

  const inj = await anon('/api/login', { json: { username: { $ne: null }, password: { $ne: null } } });
  check('NoSQL-injection login is rejected', inj.status === 401, 'status ' + inj.status);
  check('wrong password -> 401', (await anon('/api/login', { json: { username: users.alice, password: 'wrong-password' } })).status === 401);

  const g = await alice('/api/groups', { json: { name: 'Smoke Test', memberUsernames: [users.bob] } });
  check('create group', g.status === 201 && g.data.memberCount === 2, JSON.stringify(g.data));
  const gid = g.data.id;

  const bytes = crypto.randomBytes(4096);
  const form = (name) => { const f = new FormData(); f.append('file', new Blob([bytes], { type: 'image/png' }), name); return f; };

  const up1 = await alice(`/api/groups/${gid}/upload`, { body: form('photo.png') });
  check('first upload is stored as NEW', up1.status === 201 && up1.data.duplicate === false, JSON.stringify(up1.data));

  const up2 = await bob(`/api/groups/${gid}/upload`, { body: form('renamed-copy.png') });
  check('same bytes, other user + other name -> DUPLICATE', up2.status === 200 && up2.data.duplicate === true, JSON.stringify(up2.data));
  check('duplicate alert points to the original file', up2.data?.message?.type === 'duplicate' && up2.data.message.file?.originalSenderName === users.alice);

  const gallery = await alice(`/api/groups/${gid}/gallery`);
  check('gallery lists the file once', Array.isArray(gallery.data) && gallery.data.length === 1, JSON.stringify(gallery.data));

  const stats = await alice(`/api/groups/${gid}/stats`);
  check('stats: 1 unique, 1 blocked, 4096 bytes saved',
    stats.data?.uniqueFiles === 1 && stats.data?.duplicatesBlocked === 1 && stats.data?.bytesSaved === 4096, JSON.stringify(stats.data));

  const url = gallery.data[0].url;
  const file = await bob(url);
  check('member can download the file with a safe content-type + nosniff',
    file.status === 200 && file.res.headers.get('content-type') === 'image/png' && file.res.headers.get('x-content-type-options') === 'nosniff');
  check('non-member cannot download it (403)', (await mallory(url)).status === 403);
  check('logged-out user cannot download it (401)', (await anon(url)).status === 401);
  check('non-member cannot read history (403)', (await mallory(`/api/groups/${gid}/messages`)).status === 403);
  check('non-member cannot upload (403)', (await mallory(`/api/groups/${gid}/upload`, { body: form('x.png') })).status === 403);

  const hist = await alice(`/api/groups/${gid}/messages?limit=1`);
  check('history is paged (limit=1 -> hasMore)', hist.data?.messages?.length === 1 && hist.data.hasMore === true, JSON.stringify(hist.data));

  const big = await alice(`/api/groups/${gid}/messages?before=not-an-id`);
  check('bad cursor -> 400, not a crash', big.status === 400);

  // ---- user suggestions, one-to-one chats, add members, edit / delete ----
  const ul = await alice('/api/users');
  const names = (ul.data?.users || []).map((u) => u.username);
  check('/api/users lists other registered users (not me)', names.includes(users.bob) && names.includes(users.mallory) && !names.includes(users.alice), JSON.stringify(names));
  check('/api/users never exposes emails', !JSON.stringify(ul.data).includes('@example.com'));
  const filtered = await alice('/api/users?q=' + encodeURIComponent(users.bob.slice(0, 6)));
  check('/api/users?q= filters', filtered.data?.users?.some((u) => u.username === users.bob) && !filtered.data.users.some((u) => u.username === users.mallory), JSON.stringify(filtered.data));
  check('/api/users needs login', (await anon('/api/users')).status === 401);
  const flagged = await alice(`/api/users?groupId=${gid}`);
  check('members already in the group are flagged', flagged.data?.users?.find((u) => u.username === users.bob)?.inGroup === true);

  const dm = await alice('/api/chats/direct', { json: { username: users.bob } });
  check('start one-to-one chat', dm.status === 201 && dm.data.isDirect === true && dm.data.name === users.bob, JSON.stringify(dm.data));
  const dm2 = await bob('/api/chats/direct', { json: { username: users.alice } });
  check('the other person opens the SAME chat (no duplicate)', dm2.status === 200 && dm2.data.id === dm.data.id && dm2.data.name === users.alice, JSON.stringify(dm2.data));
  check('cannot chat with yourself', (await alice('/api/chats/direct', { json: { username: users.alice } })).status === 400);
  check('outsider cannot read a direct chat', (await mallory(`/api/groups/${dm.data.id}/messages`)).status === 403);
  check('cannot add people to a one-to-one chat', (await alice(`/api/groups/${dm.data.id}/members`, { json: { usernames: [users.mallory] } })).status === 400);
  const addm = await alice(`/api/groups/${gid}/members`, { json: { usernames: [users.mallory] } });
  check('add a member to a group from the picker', addm.status === 200 && addm.data.added?.includes(users.mallory), JSON.stringify(addm.data));
  check('the new member can now read the group', (await mallory(`/api/groups/${gid}/messages`)).status === 200);

  // edit / delete: the file upload above is the last media message in the group
  const hist2 = await alice(`/api/groups/${gid}/messages?limit=100`);
  const fileMsg = hist2.data.messages.find((m) => m.type === 'media');
  check('bob cannot delete alice\'s file message', (await bob(`/api/groups/${gid}/messages/${fileMsg.id}`, { method: 'DELETE' })).status === 403);
  const del = await alice(`/api/groups/${gid}/messages/${fileMsg.id}`, { method: 'DELETE' });
  check('alice deletes her file message (alert is removed too)', del.status === 200 && del.data.fileRemoved === true && del.data.ids.length === 2, JSON.stringify(del.data));
  const gal2 = await alice(`/api/groups/${gid}/gallery`);
  check('file left the gallery', Array.isArray(gal2.data) && gal2.data.length === 0, JSON.stringify(gal2.data));
  const reup = await bob(`/api/groups/${gid}/upload`, { body: form('again.png') });
  check('the same file can be shared again after deletion (new, not duplicate)', reup.status === 201 && reup.data.duplicate === false, JSON.stringify(reup.data));
  check('deleted message cannot be deleted twice', (await alice(`/api/groups/${gid}/messages/${fileMsg.id}`, { method: 'DELETE' })).status === 404);

  const langs = await anon('/api/languages');
  check('/api/languages is public and lists languages', langs.status === 200 && langs.data.languages.some((l) => l.code === 'ur'));
  const me = await alice('/api/me');
  check('/api/me includes reading-language settings', me.data?.settings?.language === 'en' && me.data.settings.autoTranslate === true, JSON.stringify(me.data?.settings));
  const setLang = await alice('/api/me/settings', { json: { language: 'hi' }, method: 'PATCH' });
  check('change reading language to Hindi', setLang.status === 200 && setLang.data.settings.language === 'hi', JSON.stringify(setLang.data));
  check('unsupported language is rejected', (await alice('/api/me/settings', { json: { language: 'xx' }, method: 'PATCH' })).status === 400);
  check('settings need login', (await anon('/api/me/settings', { json: { language: 'hi' }, method: 'PATCH' })).status === 401);
  await alice('/api/me/settings', { json: { language: 'en' }, method: 'PATCH' });

  const health = await anon('/healthz');
  check('/healthz ok', health.status === 200 && health.data?.db === true);

  console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll smoke checks passed');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('Smoke test crashed (is the server running at ' + BASE + '?)\n', e.message); process.exit(1); });
