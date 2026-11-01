const test = require('node:test');
const assert = require('node:assert/strict');
const { assessUrl, assessLinks, safeBrowsingLookup, registeredDomain } = require('../lib/linkRisk');

const lvl = (u) => assessUrl(u).level;
const sc = (u) => assessUrl(u).score;

test('ordinary and well-known links are safe', () => {
  for (const u of ['https://example.com/blog/post-1', 'https://www.youtube.com/watch?v=abc123', 'https://en.wikipedia.org/wiki/Foo_(bar)',
    'https://github.com/nodejs/node', 'https://www.incometax.gov.in/iec/foportal', 'https://docs.google.com/document/d/123/edit']) {
    assert.equal(lvl(u), 'safe', u + ' -> ' + sc(u));
  }
});

test('classic phishing patterns are dangerous', () => {
  const bad = [
    'http://sbi-kyc-update.top/login',
    'https://paypal-secure-login.xyz/verify-account',
    'http://192.168.4.7/bank/login.php',
    'https://google.com@evil-site.ru/login',
    'https://secure.hdfcbank.com.account-verify.work/otp',
    'http://free-gift-claim-prize.click/winner',
    'https://xn--pypal-4ve.com/signin',
  ];
  for (const u of bad) assert.equal(lvl(u), 'dangerous', u + ' -> ' + sc(u) + ' ' + assessUrl(u).reasons.join(' | '));
});

test('shortened or odd links are at least suspicious', () => {
  for (const u of ['https://bit.ly/3xYz', 'https://file.example.xyz/download.zip', 'https://example.com/get/app.apk']) {
    assert.notEqual(lvl(u), 'safe', u + ' -> ' + sc(u));
  }
});

test('a single weak signal alone (odd port) adds risk but does not cry wolf', () => {
  const r = assessUrl('https://example.com:8081/a');
  assert.ok(r.score > 0 && r.level === 'safe');
  assert.ok(r.reasons.some((x) => /port/i.test(x)));
});

test('brand impersonation is caught, but the real brand domain is not flagged', () => {
  assert.ok(assessUrl('https://amazon-offers.in/deal').reasons.some((r) => /pretending to be amazon/.test(r)));
  assert.ok(!assessUrl('https://www.amazon.in/dp/B000').reasons.some((r) => /pretending/.test(r)));
  assert.ok(!assessUrl('https://netbanking.hdfcbank.com/login').reasons.some((r) => /pretending/.test(r)));
  assert.ok(assessUrl('https://sbi-kyc.com/x').reasons.some((r) => /pretending to be sbi/.test(r)));
  assert.ok(!assessUrl('https://possible.com/x').reasons.some((r) => /pretending/.test(r)));          // "sbi" inside a word is fine
  assert.ok(!assessUrl('https://pineapple-recipes.com/x').reasons.some((r) => /pretending/.test(r)));  // "apple" inside a word is fine
});

test('a "trusted" domain cannot hide a decoy: user@host trick is still dangerous', () => {
  assert.equal(lvl('https://github.com@evil.xyz/login'), 'dangerous');
});

test('score is always 0-100 and every result explains itself', () => {
  for (const u of ['https://a.com', 'http://1.2.3.4:99/login/verify/otp/kyc.exe?url=http://x.com', 'not a url', 'https://xn--a.b-c-d-e.top']) {
    const r = assessUrl(u);
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(r.reasons.length >= 1);
    assert.ok(['safe', 'suspicious', 'dangerous'].includes(r.level));
  }
});

test('registeredDomain handles two-part suffixes and IPs', () => {
  assert.equal(registeredDomain('login.secure.paypal.co.uk'), 'paypal.co.uk');
  assert.equal(registeredDomain('a.b.example.com'), 'example.com');
  assert.equal(registeredDomain('1.2.3.4'), '1.2.3.4');
  assert.equal(registeredDomain('www.incometax.gov.in'), 'incometax.gov.in');
});

test('Safe Browsing: a listed URL becomes 100% dangerous (mocked API)', async () => {
  let sent;
  const fetchImpl = async (url, init) => {
    sent = { url, body: JSON.parse(init.body) };
    return { ok: true, json: async () => ({ matches: [{ threatType: 'SOCIAL_ENGINEERING', threat: { url: 'https://looks-fine-but-listed.com/a' } }] }) };
  };
  const r = await assessLinks([{ url: 'https://looks-fine-but-listed.com/a' }, { url: 'https://example.org/ok' }], { safeBrowsingKey: 'KEY', fetchImpl });
  assert.equal(r[0].score, 100); assert.equal(r[0].level, 'dangerous'); assert.equal(r[0].listed, true);
  assert.match(r[0].reasons[0], /Safe Browsing.*phishing/);
  assert.equal(r[1].level, 'safe'); assert.equal(r[1].listed, false);
  assert.ok(sent.url.includes('safebrowsing.googleapis.com/v4/threatMatches:find?key=KEY'));
  assert.equal(sent.body.threatInfo.threatEntries.length, 2);
});

test('Safe Browsing: when the service fails we silently fall back to heuristics', async () => {
  const boom = async () => { throw new Error('network down'); };
  const notOk = async () => ({ ok: false, status: 403, json: async () => ({}) });
  for (const fetchImpl of [boom, notOk]) {
    const r = await assessLinks([{ url: 'http://sbi-kyc-update.top/login' }], { safeBrowsingKey: 'KEY', fetchImpl });
    assert.equal(r[0].level, 'dangerous');                       // heuristics still work
    assert.equal(r[0].listed, false);
  }
  assert.equal(await safeBrowsingLookup(['https://x-unique-1.com'], 'K', boom), null);
});

test('no API key => no network call is made', async () => {
  let called = false;
  await assessLinks([{ url: 'https://example.com' }], { fetchImpl: async () => { called = true; } });
  assert.equal(called, false);
});

test('look-alike letters are punished, genuine international domains are not', () => {
  assert.equal(lvl('https://pаypal.com/login'), 'dangerous');          // Cyrillic "а"
  assert.equal(lvl('https://münchen.de/karte'), 'safe');
  assert.equal(lvl('https://例え.jp/'), 'safe');
});
