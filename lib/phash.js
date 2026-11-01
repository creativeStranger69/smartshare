/**
 * lib/phash.js - SIMILAR-IMAGE DETECTION ("perceptual hash")
 * ------------------------------------------------------------------
 * SHA-256 only catches files with IDENTICAL bytes. But a photo that was forwarded through
 * WhatsApp, re-saved as JPEG or resized has DIFFERENT bytes while looking the same.
 * A perceptual hash is a fingerprint of how the image LOOKS, so similar-looking images get
 * similar fingerprints.
 *
 * ALGORITHM ("difference hash", dHash) - easy to explain in a viva:
 *   1. Shrink the image to 17 x 17 pixels and make it grey  (throws away size, colour, compression noise)
 *   2. For every pixel ask: "is the pixel on my RIGHT brighter than me?"   -> 16 x 17 = 272 yes/no bits
 *      and:                 "is the pixel BELOW me brighter than me?"      -> 17 x 16 = 272 yes/no bits
 *   3. Those 544 bits are the fingerprint (stored as 136 hex characters).
 *   4. Distance between two images = number of bits that differ (Hamming distance).
 *      similarity = 1 - differingBits / 544
 *
 *   same photo, recompressed/resized  -> ~0-5% of bits differ  (similarity ~95-100%)
 *   two unrelated photos              -> ~40-50% differ         (similarity ~50-60%)
 *
 * LIMITS (be honest in the viva): cropped, rotated or mirrored copies are NOT matched.
 * This is a "looks the same" check, not face/object recognition.
 *
 * `sharp` (image library) is optional: if it is not installed the feature switches itself off
 * and the rest of the app keeps working.
 */
let sharp = null;
try { sharp = require('sharp'); } catch { /* feature disabled */ }

const GRID = 17;                                   // 17x17 grey pixels
const BITS = (GRID - 1) * GRID * 2;                // 544
// >= 90% of bits equal => "looks similar". Measured: recompressed/resized/brightened copies of a real
// photo scored 94-99%; unrelated pictures scored 43-73%. 90% sits in the middle of that gap.
const SIMILAR_MIN = 0.90;
const FLAT_RANGE = 8;                              // almost one colour (blank image) -> not comparable

// number of 1-bits in every possible byte value
const POP = Uint8Array.from({ length: 256 }, (_, n) => { let c = 0; for (; n; n >>= 1) c += n & 1; return c; });

const isAvailable = () => sharp !== null;

// Only files that look like pictures are fingerprinted (decided by name here; sharp then verifies the bytes)
const IMAGE_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.tif', '.tiff', '.avif']);
const isImageName = (name = '') => IMAGE_EXT.has(String(name).toLowerCase().replace(/^.*(?=\.)/, ''));

/** @returns {Promise<string|null>} 136-char hex fingerprint, or null (not an image / unreadable / blank / sharp missing) */
async function dHash(buffer) {
  if (!sharp) return null;
  try {
    const { data, info } = await sharp(buffer, { limitInputPixels: 50_000_000, failOn: 'none' })   // limit = decompression-bomb guard
      .rotate()                                    // honour the camera's EXIF orientation
      .flatten({ background: '#ffffff' })          // transparent PNGs: composite on white
      .greyscale()
      .resize(GRID, GRID, { fit: 'fill' })
      .raw()
      .toBuffer({ resolveWithObject: true });

    const ch = info.channels;
    const px = (x, y) => data[(y * GRID + x) * ch];
    let min = 255, max = 0;
    for (let y = 0; y < GRID; y++) for (let x = 0; x < GRID; x++) { const p = px(x, y); if (p < min) min = p; if (p > max) max = p; }
    if (max - min < FLAT_RANGE) return null;

    const bits = new Uint8Array(BITS / 8);
    let i = 0;
    const set = (cond) => { if (cond) bits[i >> 3] |= 1 << (i & 7); i++; };
    for (let y = 0; y < GRID; y++) for (let x = 0; x < GRID - 1; x++) set(px(x, y) < px(x + 1, y));   // right neighbour brighter?
    for (let y = 0; y < GRID - 1; y++) for (let x = 0; x < GRID; x++) set(px(x, y) < px(x, y + 1));   // lower neighbour brighter?
    return Buffer.from(bits).toString('hex');
  } catch {
    return null;
  }
}

/** number of differing bits between two hex fingerprints */
function hamming(hexA, hexB) {
  const a = Buffer.from(hexA, 'hex'), b = Buffer.from(hexB, 'hex');
  let d = 0;
  for (let i = 0; i < a.length; i++) d += POP[a[i] ^ b[i]];
  return d;
}

const similarity = (hexA, hexB) => 1 - hamming(hexA, hexB) / BITS;

/**
 * Best match among candidates [{ id, phash }]. Linear scan: fine for thousands of images per group
 * (each comparison is 68 byte XORs). Larger systems would use a BK-tree or multi-index hashing.
 * @returns {{id: string, similarity: number} | null}
 */
function findSimilar(hash, candidates, min = SIMILAR_MIN) {
  let best = null;
  for (const c of candidates) {
    if (!c.phash || c.phash.length !== hash.length) continue;
    const s = similarity(hash, c.phash);
    if (s >= min && (!best || s > best.similarity)) best = { id: c.id, similarity: s };
  }
  return best;
}

module.exports = { dHash, hamming, similarity, findSimilar, isAvailable, isImageName, SIMILAR_MIN, BITS };
