const test = require('node:test');
const assert = require('node:assert/strict');
const { detectLanguage, hasLetters } = require('../lib/langdetect');
const { createTranslator, chunkText } = require('../lib/translate');
const { isSupported, LANGUAGES } = require('../lib/languages');

/* ------------------------------- language detection ------------------------------- */
test('detects the language from the alphabet', () => {
  const cases = {
    'آپ کیسے ہیں؟ میں ٹھیک ہوں': 'ur', 'आप कैसे हैं?': 'hi', 'তুমি কেমন আছো': 'bn', 'நீங்கள் எப்படி இருக்கிறீர்கள்': 'ta',
    'మీరు ఎలా ఉన్నారు': 'te', 'كيف حالك اليوم': 'ar', 'شما چطور هستید؟ گفتگو': 'fa', 'Привет, как дела?': 'ru',
    '你好，你好吗': 'zh', 'こんにちは、元気ですか': 'ja', '안녕하세요': 'ko', 'Hello, how are you?': 'en',
  };
  for (const [text, lang] of Object.entries(cases)) assert.equal(detectLanguage(text).lang, lang, text);
});

test('no letters => null (numbers, emoji, punctuation are never sent to a translator)', () => {
  for (const t of ['', '   ', '12345', '👍🔥', '?!...', 12, null, undefined]) assert.equal(detectLanguage(t), null);
  assert.equal(hasLetters('ok 👍'), true);
});

test('mixed text uses the dominant alphabet', () => {
  assert.equal(detectLanguage('मीटिंग at 5pm कल').lang, 'hi');
  assert.equal(detectLanguage('see you in the मीटिंग').lang, 'en');
});

test('language list is sane', () => {
  assert.ok(isSupported('ur') && isSupported('hi') && !isSupported('xx') && !isSupported({}) && !isSupported('__proto__'));
  assert.equal(new Set(LANGUAGES.map((l) => l.code)).size, LANGUAGES.length);
});

/* ------------------------------- chunking ------------------------------- */
test('chunkText: pieces fit the byte limit and nothing is lost', () => {
  const text = 'یہ ایک جملہ ہے۔ '.repeat(80);
  const parts = chunkText(text, 450);
  assert.ok(parts.length > 1);
  assert.ok(parts.every((p) => Buffer.byteLength(p) <= 450));
  assert.equal(parts.join(''), text);
  assert.deepEqual(chunkText('short'), ['short']);
  const noSpaces = 'x'.repeat(1200);
  assert.equal(chunkText(noSpaces, 450).join(''), noSpaces);
});

/* ------------------------------- providers (mocked HTTP) ------------------------------- */
const jsonResponse = (body, ok = true, status = 200) => ({ ok, status, json: async () => body });

test('MyMemory: builds the right request and reads responseData.translatedText', async () => {
  const calls = [];
  const fetchImpl = async (url) => { calls.push(new URL(url)); return jsonResponse({ responseStatus: 200, responseData: { translatedText: 'आप कैसे हैं' } }); };
  const t = createTranslator({ provider: 'mymemory', myMemoryEmail: 'me@example.com', fetchImpl });
  assert.equal(t.enabled, true);
  const out = await t.translateSegments(['آپ کیسے ہیں'], 'hi');
  assert.deepEqual(out, ['आप कैसे हैं']);
  assert.equal(calls[0].searchParams.get('langpair'), 'ur|hi');       // source detected from the alphabet
  assert.equal(calls[0].searchParams.get('q'), 'آپ کیسے ہیں');
  assert.equal(calls[0].searchParams.get('de'), 'me@example.com');
});

test('MyMemory: Chinese uses zh-CN', async () => {
  let pair;
  const fetchImpl = async (url) => { pair = new URL(url).searchParams.get('langpair'); return jsonResponse({ responseStatus: 200, responseData: { translatedText: 'hello' } }); };
  await createTranslator({ provider: 'mymemory', fetchImpl }).translateSegments(['你好'], 'en');
  assert.equal(pair, 'zh-CN|en');
});

test('MyMemory: quota warning text is NEVER shown as a translation', async () => {
  const warn = async () => jsonResponse({ responseStatus: 200, responseData: { translatedText: 'MYMEMORY WARNING: YOU USED ALL AVAILABLE FREE TRANSLATIONS FOR TODAY' } });
  const status429 = async () => jsonResponse({ responseStatus: 429, responseData: { translatedText: 'x' }, responseDetails: 'quota' });
  for (const fetchImpl of [warn, status429]) {
    await assert.rejects(createTranslator({ provider: 'mymemory', fetchImpl }).translateSegments(['नमस्ते दोस्त'], 'en'));
  }
});

test('LibreTranslate: POST /translate with source=auto', async () => {
  let sent;
  const fetchImpl = async (url, init) => { sent = { url, body: JSON.parse(init.body), method: init.method }; return jsonResponse({ translatedText: 'Hello friend' }); };
  const t = createTranslator({ provider: 'libretranslate', libreUrl: 'http://localhost:5000/', libreKey: 'K', fetchImpl });
  assert.deepEqual(await t.translateSegments(['नमस्ते दोस्त'], 'en'), ['Hello friend']);
  assert.equal(sent.url, 'http://localhost:5000/translate');
  assert.deepEqual(sent.body, { q: 'नमस्ते दोस्त', source: 'auto', target: 'en', format: 'text', api_key: 'K' });
});

test('Google v2: one batched request for all segments', async () => {
  let sent, count = 0;
  const fetchImpl = async (url, init) => { count++; sent = { url, body: JSON.parse(init.body) }; return jsonResponse({ data: { translations: [{ translatedText: 'one' }, { translatedText: 'two' }] } }); };
  const t = createTranslator({ provider: 'google', googleKey: 'KEY', fetchImpl });
  assert.deepEqual(await t.translateSegments(['नमस्ते', 'धन्यवाद'], 'en'), ['one', 'two']);
  assert.equal(count, 1);
  assert.ok(sent.url.includes('translation.googleapis.com/language/translate/v2?key=KEY'));
  assert.deepEqual(sent.body, { q: ['नमस्ते', 'धन्यवाद'], target: 'en', format: 'text' });
});

/* ------------------------------- behaviour of the translator layer ------------------------------- */
test('segments that need no translation never hit the network', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return jsonResponse({ translatedText: 'x' }); };
  const t = createTranslator({ provider: 'libretranslate', libreUrl: 'http://x', fetchImpl });
  const input = ['  ', '12345', '👍', 'Already English', ' '];
  assert.deepEqual(await t.translateSegments(input, 'en'), input);     // no letters, or already the target language
  assert.equal(calls, 0);
});

test('leading/trailing spaces around a segment are preserved (links stay separated from text)', async () => {
  const fetchImpl = async () => jsonResponse({ translatedText: 'Look at this' });
  const t = createTranslator({ provider: 'libretranslate', libreUrl: 'http://x', fetchImpl });
  assert.deepEqual(await t.translateSegments(['  ये देखो '], 'en'), ['  Look at this ']);
});

test('results are cached: the same text is translated once', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return jsonResponse({ translatedText: 'Hello' }); };
  const t = createTranslator({ provider: 'libretranslate', libreUrl: 'http://x', fetchImpl });
  await t.translateSegments(['नमस्ते'], 'en');
  await t.translateSegments(['नमस्ते'], 'en');
  assert.equal(calls, 1);
});

test('circuit breaker: after 5 failures the service is left alone for 60 s, then retried', async () => {
  let calls = 0, clock = 1_000_000;
  const fetchImpl = async () => { calls++; throw new Error('down'); };
  const t = createTranslator({ provider: 'libretranslate', libreUrl: 'http://x', fetchImpl, now: () => clock });
  for (let i = 0; i < 5; i++) await assert.rejects(t.translateSegments(['नमस्ते' + i], 'en'));
  assert.equal(calls, 5);
  await assert.rejects(t.translateSegments(['नमस्ते-new'], 'en'), /paused/);
  assert.equal(calls, 5);                                             // not called while paused
  clock += 61_000;
  await assert.rejects(t.translateSegments(['नमस्ते-again'], 'en'), /down/);
  assert.equal(calls, 6);                                             // retried after the pause
});

test('unconfigured / misconfigured providers are simply disabled', async () => {
  for (const cfg of [{}, { provider: 'none' }, { provider: 'google' }, { provider: 'libretranslate' }, { provider: 'bogus' }]) {
    const t = createTranslator(cfg);
    assert.equal(t.enabled, false);
    await assert.rejects(t.translateSegments(['नमस्ते'], 'en'));
  }
});
