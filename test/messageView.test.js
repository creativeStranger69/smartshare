const test = require('node:test');
const assert = require('node:assert/strict');
const { linkParts, textSegments, buildTranslation, translationFor } = require('../lib/messageView');

const dangerous = { score: 88, level: 'dangerous', reasons: ['Looks like it is pretending to be sbi'] };
const msg = {
  senderId: 'u2',
  text: 'देखो http://sbi-kyc-update.top/login अभी',
  links: [{ url: 'http://sbi-kyc-update.top/login', key: 'https://sbi-kyc-update.top/login', dupOf: 'm1', risk: dangerous }],
};
const origOf = { m1: { messageId: 'm1', senderName: 'bob', timestamp: '2026-10-28T09:00:00Z' } };

test('linkParts: link parts carry host, risk verdict and "already shared" info', () => {
  const parts = linkParts(msg, origOf);
  assert.deepEqual(parts.map((p) => p.type), ['text', 'link', 'text']);
  const link = parts[1];
  assert.equal(link.host, 'sbi-kyc-update.top');
  assert.deepEqual(link.risk, dangerous);
  assert.equal(link.dup.senderName, 'bob');
});

test('linkParts: null when there are no links; risk null for messages stored before the feature existed', () => {
  assert.equal(linkParts({ text: 'hello', links: [] }), null);
  assert.equal(linkParts({ text: 'hello' }), null);
  const old = linkParts({ text: 'see https://example.com/a', links: [{ url: 'https://example.com/a', key: 'https://example.com/a' }] });
  assert.equal(old[1].risk, null);
  assert.equal(old[1].dup, null);
});

test('textSegments: only text parts are translated, links never', () => {
  assert.deepEqual(textSegments('plain', null), ['plain']);
  assert.deepEqual(textSegments(msg.text, linkParts(msg, origOf)), ['देखो ', ' अभी']);
});

test('buildTranslation: translated text goes back around the untouched link', () => {
  const parts = linkParts(msg, origOf);
  const t = buildTranslation(parts, ['Look ', ' now'], 'en');
  assert.equal(t.lang, 'en');
  assert.deepEqual(t.parts.map((p) => p.value), ['Look ', 'http://sbi-kyc-update.top/login', ' now']);
  assert.deepEqual(t.parts[1].risk, dangerous);                       // link keeps its safety verdict
  assert.deepEqual(buildTranslation(null, ['Hello'], 'en'), { lang: 'en', text: 'Hello' });
});

test('translationFor: only for readers who want it, never for the sender, only when the cache matches', () => {
  const viewer = { id: 'u1', language: 'en', autoTranslate: true };
  const m = { senderId: 'u2', text: 'آپ کیسے ہیں', translations: { en: ['How are you'] } };
  assert.deepEqual(translationFor(m, null, viewer), { lang: 'en', text: 'How are you' });
  assert.equal(translationFor(m, null, { ...viewer, autoTranslate: false }), null);
  assert.equal(translationFor(m, null, { ...viewer, language: 'hi' }), null);          // not cached for Hindi
  assert.equal(translationFor(m, null, { ...viewer, id: 'u2' }), null);                // sender reads the original
  assert.equal(translationFor(m, null, null), null);
  assert.equal(translationFor({ ...m, translations: { en: ['a', 'b'] } }, null, viewer), null);   // stale/mismatched cache is ignored
  assert.deepEqual(translationFor({ ...m, translations: new Map([['en', ['Hi']]]) }, null, viewer), { lang: 'en', text: 'Hi' });   // Mongoose Map
});
