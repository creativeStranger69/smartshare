/**
 * lib/translate.js - AUTOMATIC TRANSLATION (one pluggable layer, three possible services)
 * ------------------------------------------------------------------
 * HOW IT FITS INTO THE CHAT (see server.js):
 *   1. Bob (Urdu) sends a message.  -> saved + delivered to everyone IMMEDIATELY (never waits for a translator)
 *   2. The server looks at which languages the other online members chose (Hindi, English, ...).
 *   3. For each of those languages it calls translateSegments() ONCE and caches the result in the DB.
 *   4. Each reader receives a "messageTranslated" event in THEIR language. Sender sees the original.
 *
 * SERVICES (choose with TRANSLATE_PROVIDER in .env):
 *   mymemory       free, no key. Small daily limit (5,000 chars/day per IP; 50,000 with MYMEMORY_EMAIL). Good for demos.
 *   libretranslate open-source; run your own (docker) = chat text never leaves your server. Set LIBRETRANSLATE_URL.
 *   google         Google Cloud Translation v2. Best quality, needs GOOGLE_TRANSLATE_KEY (paid after free tier).
 *   none           feature off.
 *
 * PRIVACY: the text of messages is sent to the chosen service. Use libretranslate (self-hosted) if that matters.
 *
 * ROBUSTNESS: timeouts, a circuit breaker (after 5 failures in a row we stop calling the service for
 * 60 s so a quota-exhausted free tier does not slow every message down), an in-memory cache, and
 * translation is NEVER on the delivery path - if it fails the reader simply sees the original.
 */
const { detectLanguage } = require('./langdetect');

class TranslateError extends Error {}

const MYMEMORY_CODES = { zh: 'zh-CN' };                       // MyMemory wants "zh-CN"
const mm = (code) => MYMEMORY_CODES[code] || code;

/**
 * Split long text into pieces of at most `maxBytes` UTF-8 bytes, preferring sentence ends, then spaces.
 * (MyMemory accepts only 500 bytes per request; Urdu/Hindi letters are 2-3 bytes each.)
 */
function chunkText(text, maxBytes = 450) {
  const out = [];
  let rest = text;
  while (Buffer.byteLength(rest) > maxBytes) {
    // find the largest prefix that fits
    let cut = rest.length;
    while (Buffer.byteLength(rest.slice(0, cut)) > maxBytes) cut = Math.floor(cut * 0.9);
    const head = rest.slice(0, cut);
    let at = Math.max(head.lastIndexOf('. '), head.lastIndexOf('! '), head.lastIndexOf('? '), head.lastIndexOf('۔'), head.lastIndexOf('।'), head.lastIndexOf('\n'));
    if (at < cut * 0.3) at = head.lastIndexOf(' ');
    const end = at > 0 ? at + 1 : cut;
    out.push(rest.slice(0, end));
    rest = rest.slice(end);
  }
  if (rest) out.push(rest);
  return out;
}

/* ---------------------------------- providers: (texts[], target) -> Promise<string[]> ---------------------------------- */

function mymemoryProvider({ email, fetchImpl, timeoutMs }) {
  async function one(text, source, target) {
    const params = new URLSearchParams({ q: text, langpair: `${mm(source)}|${mm(target)}` });
    if (email) params.set('de', email);
    const res = await fetchImpl(`https://api.mymemory.translated.net/get?${params}`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new TranslateError(`MyMemory HTTP ${res.status}`);
    const body = await res.json();
    const out = body && body.responseData && body.responseData.translatedText;
    // On quota exhaustion MyMemory answers with a WARNING sentence in place of the translation: never show that to users
    if (Number(body.responseStatus) !== 200 || typeof out !== 'string' || /^(MYMEMORY WARNING|PLEASE SELECT TWO DISTINCT|INVALID)/i.test(out)) {
      throw new TranslateError('MyMemory refused: ' + String(body.responseDetails || out || 'unknown').slice(0, 120));
    }
    return out;
  }
  return async (texts, target) => Promise.all(texts.map(async (t) => {
    const src = (detectLanguage(t) || {}).lang || 'en';
    const pieces = chunkText(t);
    return (await Promise.all(pieces.map((p) => one(p, src, target)))).join('');
  }));
}

function libreProvider({ url, apiKey, fetchImpl, timeoutMs }) {
  const endpoint = url.replace(/\/+$/, '') + '/translate';
  return async (texts, target) => Promise.all(texts.map(async (q) => {
    const res = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({ q, source: 'auto', target, format: 'text', ...(apiKey ? { api_key: apiKey } : {}) }),
    });
    if (!res.ok) throw new TranslateError(`LibreTranslate HTTP ${res.status}`);
    const body = await res.json();
    if (typeof body.translatedText !== 'string') throw new TranslateError('LibreTranslate: unexpected response');
    return body.translatedText;
  }));
}

function googleProvider({ apiKey, fetchImpl, timeoutMs }) {
  return async (texts, target) => {
    const res = await fetchImpl(`https://translation.googleapis.com/language/translate/v2?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
      body: JSON.stringify({ q: texts, target, format: 'text' }),         // source omitted = auto-detect
    });
    if (!res.ok) throw new TranslateError(`Google Translate HTTP ${res.status}`);
    const body = await res.json();
    const list = body && body.data && body.data.translations;
    if (!Array.isArray(list) || list.length !== texts.length) throw new TranslateError('Google Translate: unexpected response');
    return list.map((t) => t.translatedText);
  };
}

/* ---------------------------------- the translator ---------------------------------- */

/**
 * @param {{provider?:string, libreUrl?:string, libreKey?:string, googleKey?:string, myMemoryEmail?:string,
 *          fetchImpl?:Function, timeoutMs?:number, now?:()=>number}} opts
 */
function createTranslator(opts = {}) {
  const { provider = 'none', fetchImpl = globalThis.fetch, timeoutMs = 4000, now = Date.now } = opts;
  let call = null;
  if (provider === 'mymemory') call = mymemoryProvider({ email: opts.myMemoryEmail, fetchImpl, timeoutMs });
  else if (provider === 'libretranslate' && opts.libreUrl) call = libreProvider({ url: opts.libreUrl, apiKey: opts.libreKey, fetchImpl, timeoutMs });
  else if (provider === 'google' && opts.googleKey) call = googleProvider({ apiKey: opts.googleKey, fetchImpl, timeoutMs });

  const cache = new Map();                                  // "target|text" -> translation (LRU, 1000 entries)
  let failures = 0;
  let pausedUntil = 0;

  async function translateSegments(segments, target) {
    if (!call) throw new TranslateError('Translation is not configured');
    const result = segments.slice();                        // default: unchanged
    const todo = [];                                        // [index, text-without-outer-whitespace, leading, trailing]
    segments.forEach((seg, i) => {
      const core = seg.trim();
      const detected = detectLanguage(core);
      if (!detected || detected.lang === target) return;    // no letters, or already in the reader's language
      const key = `${target}|${core}`;
      if (cache.has(key)) { result[i] = seg.match(/^\s*/)[0] + cache.get(key) + seg.match(/\s*$/)[0]; return; }
      todo.push([i, core, seg.match(/^\s*/)[0], seg.match(/\s*$/)[0]]);
    });
    if (!todo.length) return result;

    if (now() < pausedUntil) throw new TranslateError('Translation service temporarily paused after repeated failures');
    try {
      const translated = await call(todo.map((t) => t[1]), target);
      failures = 0;
      todo.forEach(([i, core, lead, trail], k) => {
        const text = String(translated[k]);
        if (cache.size >= 1000) cache.delete(cache.keys().next().value);
        cache.set(`${target}|${core}`, text);
        result[i] = lead + text + trail;
      });
    } catch (err) {
      if (++failures >= 5) { pausedUntil = now() + 60_000; failures = 0; }
      throw err;
    }
    return result;
  }

  return { enabled: call !== null, provider: call ? provider : 'none', translateSegments };
}

module.exports = { createTranslator, chunkText, TranslateError };
