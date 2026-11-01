/**
 * dedup.js  -  THE DEDUPLICATION ENGINE (core of the project)
 * ------------------------------------------------------------------
 * DATA FLOW (read this top-to-bottom in the viva):
 *
 *   Browser ──multipart upload──> multer (RAM buffer) ──> dedupMiddleware
 *                                                            │
 *        1. sha256(buffer)  ->  64-char fingerprint of the file CONTENT
 *        2. FileHash.findOne({ groupId, fileHashString })
 *               │
 *     ┌─────────┴───────────┐
 *   FOUND (duplicate)     NOT FOUND (new file)
 *     │                      │
 *     │ write NOTHING        3. write buffer to uploads/<hash>.<ext>  (atomic: temp file + rename)
 *     │ return the OLD       4. insert FileHash row (the "index entry")
 *     │ FileHash row         5. return the NEW FileHash row
 *     └─────────┬───────────┘
 *               ▼
 *       req.dedup = { duplicate: bool, fileHash }   -> server.js builds the chat message
 *
 * WHY SHA-256?  Same bytes  => same hash (always).
 *               Different bytes => different hash (collision chance ~ 2^-256, i.e. never).
 * The file NAME is irrelevant: "a.jpg" and "holiday_final(2).jpg" with identical
 * bytes are detected as duplicates; a re-saved/compressed copy is NOT (bytes changed).
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const { FileHash } = require('./models');
const { dHash, findSimilar, isImageName } = require('./lib/phash');

const UPLOAD_DIR = config.uploadDir;
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/** Step 1: content fingerprint. */
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/** Keep only a safe extension (prevents "../" tricks in user-supplied filenames). */
function safeExt(originalName = '') {
  return path.extname(originalName).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 10);
}

/**
 * Clean the display name: busboy hands us UTF-8 names decoded as latin1 (so "फोटो.jpg" arrives
 * garbled) - restore it, then strip control characters and path separators.
 */
function cleanName(name = '') {
  let n = String(name);
  if (/^[\u0000-ÿ]*$/.test(n)) n = Buffer.from(n, 'latin1').toString('utf8');
  n = n.replace(/[\u0000-\u001f\u007f\\/]/g, '').trim().slice(0, 200);
  return n || 'file';
}

/**
 * Write the bytes to disk atomically: write a temp file, then rename it into place.
 * rename() is atomic, so a crash can never leave a half-written file under the final name
 * (which would otherwise be served - and cached forever - as a corrupt "duplicate").
 */
async function storeOnDisk(fileName, buffer) {
  const dest = path.join(UPLOAD_DIR, fileName);
  try { await fs.promises.access(dest); return; } catch { /* not there yet: write it */ }
  // random suffix: two simultaneous uploads of the same bytes must not share one temp file
  const tmp = `${dest}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  await fs.promises.writeFile(tmp, buffer);
  await fs.promises.rename(tmp, dest);
}

/**
 * CORE FUNCTION: decides "write the file" vs "link to existing asset".
 *
 * @param {Buffer} buffer        raw file bytes
 * @param {string} groupId       dedup scope = ONE group (same file in another group is allowed)
 * @param {string} senderId      who is uploading
 * @param {string} originalName  name shown in the UI
 * @param {string} mimeType      e.g. image/png (informational only - never trusted for serving)
 * @returns {{duplicate: boolean, fileHash: FileHash, similar: ({id: string, similarity: number}|null)}}
 *          `similar` is only set for a NEW image that LOOKS like an image already in this group.
 */
async function processUpload({ buffer, groupId, senderId, originalName, mimeType }) {
  const hash = sha256(buffer);

  // Step 2: have we seen this exact content in THIS group before?
  const existing = await FileHash.findOne({ groupId, fileHashString: hash });
  if (existing) {
    return { duplicate: true, fileHash: existing, similar: null };   // nothing written to disk
  }

  // Step 2b - SIMILAR-IMAGE CHECK. Different bytes, but does it LOOK like a picture already in this group?
  // (a recompressed / resized / forwarded copy). The picture is still stored - it is a different file -
  // but the chat shows a "looks similar to ..." note. Skipped for non-images and when `sharp` is missing.
  let phash = null;
  let similar = null;
  if (isImageName(originalName)) {
    phash = await dHash(buffer);
    if (phash) {
      const known = await FileHash.find({ groupId, phash: { $exists: true, $ne: null } }, 'phash').limit(5000).lean();
      similar = findSimilar(phash, known.map((r) => ({ id: String(r._id), phash: r.phash })));
    }
  }

  // Step 3: new content -> store it.
  // File is named after its hash (content-addressed storage), so the same bytes
  // uploaded to a DIFFERENT group reuse the same physical file on disk too.
  const fileName = hash + safeExt(originalName);
  await storeOnDisk(fileName, buffer);

  // Step 4: register it in the dedup index.
  try {
    const fileHash = await FileHash.create({
      groupId,
      fileHashString: hash,
      physicalFilePath: 'uploads/' + fileName,
      originalSenderId: senderId,
      originalTimestamp: new Date(),
      originalName: cleanName(originalName),
      mimeType,
      size: buffer.length,
      phash: phash || undefined,
    });
    return { duplicate: false, fileHash, similar };
  } catch (err) {
    // RACE CONDITION: two identical uploads arrived simultaneously, both passed the
    // findOne() check, and the unique index (groupId + hash) rejected the second.
    // That second one is, by definition, a duplicate.
    if (err.code === 11000) {
      const winner = await FileHash.findOne({ groupId, fileHashString: hash });
      return { duplicate: true, fileHash: winner, similar: null };
    }
    throw err;
  }
}

/**
 * Express middleware wrapper. Place AFTER multer (which fills req.file)
 * and AFTER auth (which fills req.user).  Result lands in req.dedup.
 */
async function dedupMiddleware(req, res, next) {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file attached' });
    if (req.file.size === 0) return res.status(400).json({ error: 'The file is empty' });
    req.dedup = await processUpload({
      buffer: req.file.buffer,
      groupId: req.params.groupId,
      senderId: req.user.id,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
    });
    next();
  } catch (err) {
    next(err);
  }
}

module.exports = { sha256, cleanName, processUpload, dedupMiddleware, UPLOAD_DIR };
