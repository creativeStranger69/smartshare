/**
 * lib/messageView.js - pure helpers that turn a stored message into what the browser needs.
 * (Kept free of database/Express code so they can be unit-tested.)
 */
const { findLinks, toParts } = require('./links');

/**
 * FRAUD-LINK CHECK + LINK DETECTION (display side).
 * Splits the text into [text][link]... parts. Every link part also carries
 *   host - the real domain (shown in the permission dialog)
 *   risk - {score, level, reasons} computed when the message was saved (lib/linkRisk.js)
 *   dup  - who shared the same link first, if it was shared before in this group
 * @param m        stored message ({text, links:[{key, dupOf, risk}]})
 * @param origOf   map: message id -> {messageId, senderName, timestamp} for the "already shared" note
 */
function linkParts(m, origOf = {}) {
  if (!m.links || !m.links.length) return null;
  const parts = toParts(m.text, findLinks(m.text));
  if (!parts) return null;
  const byKey = Object.fromEntries(m.links.map((l) => [l.key, l]));
  return parts.map((p) => {
    if (p.type !== 'link') return p;
    const l = byKey[p.key] || {};
    let host = '';
    try { host = new URL(p.url).hostname; } catch { /* keep empty */ }
    return {
      ...p,
      host,
      dup: l.dupOf ? origOf[String(l.dupOf)] || null : null,
      risk: l.risk && l.risk.level ? { score: l.risk.score, level: l.risk.level, reasons: l.risk.reasons || [] } : null,
    };
  });
}

/**
 * AUTO-TRANSLATE: a message is translated in "segments" = its text parts. Links are never sent to the
 * translator, so they stay clickable and keep their safety badge. The DB cache stores one string per segment.
 */
const textSegments = (text, parts) => (parts ? parts.filter((p) => p.type === 'text').map((p) => p.value) : [text]);

/** Put translated segments back into the message structure the browser renders. */
function buildTranslation(parts, segs, lang) {
  if (!parts) return { lang, text: segs[0] };
  let i = 0;
  return { lang, parts: parts.map((p) => (p.type === 'text' ? { ...p, value: segs[i++] } : p)) };
}

/** The cached translation of message `m` for `viewer` ({id, language, autoTranslate}), or null. */
function translationFor(m, parts, viewer) {
  if (!viewer || !viewer.autoTranslate || String(m.senderId) === viewer.id || !m.text) return null;
  const cached = m.translations instanceof Map ? m.translations.get(viewer.language) : m.translations && m.translations[viewer.language];
  return Array.isArray(cached) && cached.length === textSegments(m.text, parts).length ? buildTranslation(parts, cached, viewer.language) : null;
}

module.exports = { linkParts, textSegments, buildTranslation, translationFor };
