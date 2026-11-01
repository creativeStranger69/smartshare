/**
 * lib/links.js - LINK DETECTION
 * ------------------------------------------------------------------
 * 1. findLinks(text)  -> finds http/https URLs inside a chat message
 * 2. normalize(url)   -> turns different spellings of the SAME page into ONE key, so
 *                        duplicate links can be detected exactly like duplicate files:
 *
 *      https://www.Example.com/post/            ┐
 *      http://example.com/post?utm_source=wa     ├──>  key "https://example.com/post"
 *      https://example.com/post#comments        ┘
 *
 * 3. toParts(text, links) -> splits the message into [text][link][text]... pieces so the
 *    browser can render real <a> tags WITHOUT ever using innerHTML (XSS-safe).
 *
 * SECURITY: only http: and https: are accepted, so "javascript:..." or "data:..." can never
 * become a clickable link. No server-side fetching of the URL happens (that would open an SSRF hole).
 */
const MAX_LINKS = 5;                      // a message "counts" at most this many links
const MAX_URL_LENGTH = 2000;
const URL_RE = /https?:\/\/[^\s<>"'`]+/gi;
// Query parameters that only track WHERE you clicked from; they do not change the page
const TRACKING_PARAM = /^(utm_[a-z0-9_]+|fbclid|gclid|igshid|mc_cid|mc_eid|ref_src)$/i;

const count = (s, ch) => s.split(ch).length - 1;

/** "see https://x.com/a)." -> drop the sentence punctuation, but keep ")" in ".../Foo_(bar)" */
function trimTrailing(s) {
  for (;;) {
    const last = s[s.length - 1];
    if (!last) return s;
    if ('.,;:!?\'"'.includes(last)) { s = s.slice(0, -1); continue; }
    const open = { ')': '(', ']': '[', '}': '{' }[last];
    if (open && count(s, open) < count(s, last)) { s = s.slice(0, -1); continue; }
    return s;
  }
}

/** The comparison key: same page => same key. */
function normalize(u) {
  const url = new URL(u.href);
  url.hash = '';                                                   // #section does not change the page
  [...url.searchParams.keys()].filter((k) => TRACKING_PARAM.test(k)).forEach((k) => url.searchParams.delete(k));
  url.searchParams.sort();                                         // ?a=1&b=2 == ?b=2&a=1
  const host = url.host.replace(/^www\./, '');                     // URL() already lower-cases the host
  const pathname = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '');   // trailing slash is irrelevant
  return `https://${host}${pathname}${url.search}`;                // http and https treated as the same page
}

/** @returns {{start:number,end:number,url:string,key:string}[]} */
function findLinks(text) {
  const out = [];
  if (typeof text !== 'string') return out;
  URL_RE.lastIndex = 0;
  let m;
  while (out.length < MAX_LINKS && (m = URL_RE.exec(text)) !== null) {
    const raw = trimTrailing(m[0]);
    if (raw.length > MAX_URL_LENGTH) continue;
    let u;
    try { u = new URL(raw); } catch { continue; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (!u.hostname.includes('.') && u.hostname !== 'localhost') continue;   // "http://abc" is not a real link
    out.push({ start: m.index, end: m.index + raw.length, url: u.href, key: normalize(u) });
  }
  return out;
}

/** Split text into [{type:'text',value}, {type:'link',value,url,key}, ...]. Returns null when there are no links. */
function toParts(text, links = findLinks(text)) {
  if (!links.length) return null;
  const parts = [];
  let pos = 0;
  for (const l of links) {
    if (l.start > pos) parts.push({ type: 'text', value: text.slice(pos, l.start) });
    parts.push({ type: 'link', value: text.slice(l.start, l.end), url: l.url, key: l.key });
    pos = l.end;
  }
  if (pos < text.length) parts.push({ type: 'text', value: text.slice(pos) });
  return parts;
}

module.exports = { findLinks, normalize, toParts, MAX_LINKS };
