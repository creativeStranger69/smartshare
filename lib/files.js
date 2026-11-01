/**
 * lib/files.js - decides HOW a stored file may be served back to a browser.
 *
 * SECURITY (viva point): users upload arbitrary files. If we served an uploaded .html or .svg
 * with its own content-type from our domain, its JavaScript would run on OUR origin (stored XSS)
 * and could act as the logged-in user. So the content-type is NOT taken from the uploader.
 * It is derived from the file extension via an allow-list; everything else is forced to
 * "download as attachment" with a neutral type.
 */
const path = require('path');

const SAFE_TYPES = {
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.wav': 'audio/wav',
  '.pdf': 'application/pdf',
};

/** @returns {{type: string, inline: boolean}} */
function servingInfo(filePath = '') {
  const type = SAFE_TYPES[path.extname(filePath).toLowerCase()];
  return type ? { type, inline: true } : { type: 'application/octet-stream', inline: false };
}

/** RFC 5987 encoding so non-ASCII names work in the Content-Disposition header */
function contentDisposition(inline, name = 'file') {
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encoded}`;
}

module.exports = { servingInfo, contentDisposition };
