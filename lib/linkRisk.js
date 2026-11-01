/**
 * lib/linkRisk.js - FRAUD / PHISHING LINK CHECK
 * ------------------------------------------------------------------
 * Gives every link a RISK SCORE from 0 to 100 and a verdict:
 *      0-24  "safe"        (no warning signs found)
 *     25-59  "suspicious"
 *     60-100 "dangerous"
 *
 * TWO LAYERS
 *  1. Heuristics (works offline, instant). Each warning sign adds points, e.g.
 *        "paypal-secure-login.xyz"   brand name in a domain that is NOT paypal.com   +50
 *                                    words scammers love (secure, login ...)         +16
 *                                    cheap/abused ending (.xyz)                      +15
 *        "http://192.168.4.7/pay"    raw IP address instead of a name                +35
 *        "https://google.com@evil.ru" everything before "@" is a decoy               +40
 *  2. Google Safe Browsing (optional, needs a free API key): a REAL blacklist of known
 *     malware/phishing sites. A match = 100% risk.
 *
 * HONEST LIMITS (say this in the viva): heuristics cannot PROVE a site is safe. "Safe" only means
 * "no warning signs found". A brand-new phishing page on a clean-looking domain can score low.
 * That is why every link - even a safe-looking one - still asks permission before opening.
 *
 * SECURITY: we never visit or fetch the link ourselves (that would let attackers make OUR server
 * request internal addresses = SSRF). We only analyse the text of the URL.
 */

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
  'shorturl.at', 'tiny.cc', 'rb.gy', 't.ly', 'bl.ink', 's.id', 'lnkd.in', 'v.gd', 'shorte.st', 'adf.ly', 'clck.ru']);

const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'work', 'loan', 'country',
  'kim', 'men', 'date', 'download', 'racing', 'review', 'stream', 'party', 'gdn', 'monster', 'cyou', 'icu', 'buzz', 'rest', 'support', 'cam']);

// words that appear in scam links far more often than in normal ones
const SCAM_WORDS = ['login', 'signin', 'verify', 'verification', 'secure', 'security', 'account', 'update', 'confirm', 'wallet',
  'bank', 'otp', 'kyc', 'claim', 'prize', 'winner', 'reward', 'gift', 'free', 'bonus', 'airdrop', 'upi', 'refund', 'password',
  'suspended', 'unlock', 'recover', 'invoice', 'payment', 'lottery', 'crypto', 'giveaway', 'cashback'];

// brand -> the ONLY registered domains that really belong to it
const BRANDS = {
  paypal: ['paypal.com'], google: ['google.com', 'google.co.in', 'goo.gl', 'googleapis.com', 'gstatic.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
  apple: ['apple.com', 'icloud.com'], amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amzn.to', 'amzn.in', 'amazonaws.com'],
  facebook: ['facebook.com', 'fb.com', 'fb.me'], instagram: ['instagram.com'], whatsapp: ['whatsapp.com', 'wa.me'],
  netflix: ['netflix.com'], flipkart: ['flipkart.com', 'fkrt.it'], paytm: ['paytm.com', 'paytm.in'], phonepe: ['phonepe.com'],
  icici: ['icicibank.com', 'icicidirect.com'], hdfc: ['hdfcbank.com', 'hdfc.com'], hdfcbank: ['hdfcbank.com'], icicibank: ['icicibank.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbicard.com'], irctc: ['irctc.co.in'],
};

// well-known sites: their risk is capped low (but never to zero - pages on them can still be abused)
const TRUSTED = new Set(['google.com', 'youtube.com', 'wikipedia.org', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'amazon.in', 'linkedin.com', 'whatsapp.com', 'instagram.com', 'facebook.com', 'twitter.com', 'x.com', 'reddit.com',
  'stackoverflow.com', 'mozilla.org', 'openai.com', 'anthropic.com', 'claude.ai', 'npmjs.com', 'nodejs.org', 'mongodb.com',
  'flipkart.com', 'paytm.com', 'irctc.co.in', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com']);
const TRUSTED_SUFFIXES = ['gov.in', 'nic.in', 'edu.in', 'ac.in'];

const TWO_PART_SUFFIXES = new Set(['co.in', 'co.uk', 'com.au', 'org.in', 'net.in', 'gov.in', 'nic.in', 'edu.in', 'ac.in', 'co.jp',
  'com.br', 'com.pk', 'com.bd', 'co.za', 'com.sg', 'co.nz']);
const BAD_EXECUTABLES = ['apk', 'exe', 'scr', 'msi', 'bat', 'cmd', 'jar', 'vbs', 'ps1', 'dmg', 'pkg', 'iso', 'com'];
const ARCHIVES = ['zip', 'rar', '7z'];

const { domainToUnicode } = require('node:url');

// Letters from other alphabets that look like Latin ones ("pаypal" with a Cyrillic "а").
const CONFUSABLES = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
  'һ': 'h', 'ո': 'n', 'ս': 'u', 'ɑ': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'ӏ': 'l', 'ℓ': 'l', 'ａ': 'a' };
/** unicode host with look-alike letters replaced by the Latin letter they imitate */
const skeleton = (host) => [...domainToUnicode(host)].map((c) => CONFUSABLES[c] || c).join('');

const isIPv4 = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h);
const isIP = (h) => isIPv4(h) || h.startsWith('[');

/** "login.secure.paypal.co.uk" -> "paypal.co.uk" */
function registeredDomain(hostname) {
  if (isIP(hostname)) return hostname;
  const labels = hostname.split('.');
  if (labels.length >= 3 && TWO_PART_SUFFIXES.has(labels.slice(-2).join('.'))) return labels.slice(-3).join('.');
  return labels.slice(-2).join('.');
}

const level = (score) => (score >= 60 ? 'dangerous' : score >= 25 ? 'suspicious' : 'safe');

/**
 * Heuristic assessment of ONE url string.
 * @returns {{score:number, level:'safe'|'suspicious'|'dangerous', reasons:string[]}}
 */
function assessUrl(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return { score: 50, level: 'suspicious', reasons: ['Not a valid web address'] }; }

  let score = 0;
  const reasons = [];
  const add = (points, reason) => { score += points; reasons.push(reason); };

  const host = u.hostname.toLowerCase();
  const reg = registeredDomain(host);
  const tld = host.split('.').pop();
  const path = decodeSafe(u.pathname + u.search).toLowerCase();

  // --- structure tricks -------------------------------------------------------------------
  if (u.username || u.password) add(40, 'Contains "@" - the real website is AFTER the @, what comes before is a decoy');
  if (u.username && /\./.test(decodeSafe(u.username))) add(25, `The decoy before the @ ("${decodeSafe(u.username).slice(0, 40)}") looks like a website address, to fool you`);
  if (isIP(host)) add(35, 'Uses a raw IP address instead of a website name');
  if (host.split('.').some((l) => l.startsWith('xn--'))) {
    // International domains are normal (münchen.de). Only letters that LOOK like English ones are a red flag.
    if (skeleton(host) !== domainToUnicode(host)) add(30, 'Uses letters from another alphabet that look like English letters - may imitate a real site');
    else add(10, 'Contains international (non-English) characters');
  }
  if (SHORTENERS.has(reg)) add(25, 'Shortened link - the real destination is hidden');
  if (!isIP(host) && SUSPICIOUS_TLDS.has(tld)) add(15, `".${tld}" is a cheap ending that scammers often use`);
  if (u.protocol === 'http:') add(10, 'Not encrypted (http, not https)');
  if (u.port) add(10, `Unusual port number (${u.port})`);
  if (!isIP(host) && host.split('.').length - reg.split('.').length >= 3) add(10, 'Too many sub-domains (often used to hide the real domain)');
  if ((host.replace(/xn--/g, '').match(/-/g) || []).length >= 3) add(10, 'Many hyphens in the domain name');
  if (host.length > 40) add(5, 'Very long domain name');
  if (u.href.length > 150) add(5, 'Very long link');
  if ((u.href.match(/%[0-9a-f]{2}/gi) || []).length > 5) add(10, 'Heavily encoded characters');
  if ([...u.searchParams.entries()].some(([k, val]) => /^(url|redirect|redir|next|goto|target|dest|continue|return)/i.test(k) && /^https?:\/\//i.test(val))) {
    add(15, 'Redirects you to another website');
  }

  // --- file downloads ---------------------------------------------------------------------
  const ext = (u.pathname.split('.').pop() || '').toLowerCase();
  if (BAD_EXECUTABLES.includes(ext) && u.pathname.includes('.')) add(30, `Downloads a program file (.${ext})`);
  else if (ARCHIVES.includes(ext) && u.pathname.includes('.')) add(10, `Downloads an archive (.${ext})`);

  // --- scam wording -----------------------------------------------------------------------
  const found = SCAM_WORDS.filter((w) => host.includes(w) || path.includes(w));
  if (found.length) add(Math.min(found.length * 8, 32), `Words often used in scams: ${found.slice(0, 4).join(', ')}`);

  // --- pretending to be a famous brand ------------------------------------------------------
  // The host is also checked in "skeleton" form, so "pаypal.com" (Cyrillic а) is read as "paypal.com".
  const tokens = [...new Set([...host.split(/[.\-]/), ...skeleton(host).split(/[.\-]/)])];
  for (const [brand, legit] of Object.entries(BRANDS)) {
    const mentions = tokens.some((t) => t === brand || (brand.length >= 6 && t.includes(brand)));
    if (mentions && !legit.includes(reg)) { add(50, `Looks like it is pretending to be ${brand} (but the domain is ${reg})`); break; }
  }

  // --- well-known sites get a low ceiling ------------------------------------------------------
  const trusted = TRUSTED.has(reg) || TRUSTED_SUFFIXES.some((s) => reg.endsWith('.' + s));
  if (trusted && !u.username && !host.includes('xn--')) {
    score = Math.min(score, 15);
    reasons.unshift('Well-known website (this does not guarantee a specific page is safe)');
  }

  score = Math.max(0, Math.min(100, score));
  if (!reasons.length) reasons.push('No warning signs found');
  return { score, level: level(score), reasons };
}

function decodeSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }

/* ---------------------------------------------------------------------------------------------
 * Layer 2: Google Safe Browsing (Lookup API v4). Optional.
 * Request/response format: https://developers.google.com/safe-browsing/v4/lookup-api
 * --------------------------------------------------------------------------------------------- */
const sbCache = new Map();                       // url -> { at, threats }   (5 minute cache, max 500 entries)
const SB_TTL = 5 * 60 * 1000;

/** @returns {Promise<Map<string,string[]>|null>} url -> threat types, or null if the service was unreachable */
async function safeBrowsingLookup(urls, apiKey, fetchImpl = fetch) {
  const result = new Map();
  const todo = [];
  for (const url of urls) {
    const hit = sbCache.get(url);
    if (hit && Date.now() - hit.at < SB_TTL) result.set(url, hit.threats); else todo.push(url);
  }
  if (!todo.length) return result;
  try {
    const res = await fetchImpl(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: AbortSignal.timeout(2500),
      body: JSON.stringify({
        client: { clientId: 'smartshare', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: todo.map((url) => ({ url })),
        },
      }),
    });
    if (!res.ok) return null;
    const body = await res.json();                // {} when nothing matched, {matches:[...]} otherwise
    const byUrl = new Map(todo.map((u) => [u, []]));
    for (const m of body.matches || []) if (m.threat && byUrl.has(m.threat.url)) byUrl.get(m.threat.url).push(m.threatType);
    for (const [url, threats] of byUrl) {
      if (sbCache.size >= 500) sbCache.delete(sbCache.keys().next().value);
      sbCache.set(url, { at: Date.now(), threats });
      result.set(url, threats);
    }
    return result;
  } catch {
    return null;                                  // timeout / network error: fall back to heuristics only
  }
}

const THREAT_NAMES = { MALWARE: 'malware', SOCIAL_ENGINEERING: 'phishing / scam', UNWANTED_SOFTWARE: 'unwanted software', POTENTIALLY_HARMFUL_APPLICATION: 'harmful app' };

/**
 * Assess several links at once.
 * @param {{url:string}[]} links
 * @param {{safeBrowsingKey?:string, fetchImpl?:Function}} opts
 * @returns {Promise<{score:number, level:string, reasons:string[], listed:boolean}[]>}
 */
async function assessLinks(links, opts = {}) {
  const out = links.map((l) => ({ ...assessUrl(l.url), listed: false }));
  if (opts.safeBrowsingKey && links.length) {
    const found = await safeBrowsingLookup(links.map((l) => l.url), opts.safeBrowsingKey, opts.fetchImpl);
    if (found) {
      out.forEach((r, i) => {
        const threats = found.get(links[i].url) || [];
        if (threats.length) {
          r.score = 100; r.level = 'dangerous'; r.listed = true;
          r.reasons.unshift(`Listed by Google Safe Browsing as ${threats.map((t) => THREAT_NAMES[t] || t).join(', ')}`);
        }
      });
    }
  }
  return out;
}

module.exports = { assessUrl, assessLinks, safeBrowsingLookup, registeredDomain, level };
