/**
 * Tests the deduplication engine with an in-memory fake of the FileHash collection,
 * so they run without MongoDB. The fake enforces the same UNIQUE (groupId + hash) rule
 * as the real index (error code 11000).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// --- test doubles -------------------------------------------------------------
const rows = [];
let seq = 0;
const FileHash = {
  async findOne(q) { return rows.find((r) => r.groupId === q.groupId && r.fileHashString === q.fileHashString) || null; },
  find(q) {                                                     // find(filter, projection).limit().lean()
    const hit = rows.filter((r) => r.groupId === q.groupId && (!q.phash || r.phash));
    const chain = { limit: () => chain, lean: async () => hit };
    return chain;
  },
  async create(d) {
    if (rows.some((r) => r.groupId === d.groupId && r.fileHashString === d.fileHashString)) {
      const e = new Error('E11000 duplicate key'); e.code = 11000; throw e;
    }
    // check + insert happen in ONE synchronous step, like MongoDB's unique index (atomic)...
    const row = { ...d, _id: String(++seq) }; rows.push(row);
    await new Promise((r) => setImmediate(r));                  // ...then yield, so the race test can interleave
    return row;
  },
};
const realLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === './models') return { FileHash };
  if (request === 'dotenv') return { config() {} };
  return realLoad.call(this, request, ...rest);
};

process.env.UPLOAD_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'smartshare-test-'));
const { processUpload, sha256, cleanName, UPLOAD_DIR } = require('../dedup');
const onDisk = () => fs.readdirSync(UPLOAD_DIR);

const base = { groupId: 'G1', senderId: 'U1', mimeType: 'text/plain' };

test('sha256 is deterministic and content-sensitive', () => {
  assert.equal(sha256(Buffer.from('abc')), sha256(Buffer.from('abc')));
  assert.notEqual(sha256(Buffer.from('abc')), sha256(Buffer.from('abd')));
  assert.equal(sha256(Buffer.from('abc')).length, 64);
});

test('new file is stored once and indexed', async () => {
  const r = await processUpload({ ...base, buffer: Buffer.from('hello smartshare'), originalName: 'a.txt' });
  assert.equal(r.duplicate, false);
  assert.equal(r.fileHash.size, 16);
  assert.deepEqual(onDisk(), [sha256(Buffer.from('hello smartshare')) + '.txt']);
});

test('same bytes under another name + another sender = duplicate, nothing new on disk', async () => {
  const before = onDisk().length;
  const first = rows[0];
  const r = await processUpload({ ...base, senderId: 'U2', buffer: Buffer.from('hello smartshare'), originalName: 'renamed.txt' });
  assert.equal(r.duplicate, true);
  assert.equal(r.fileHash._id, first._id);                      // points at the ORIGINAL record
  assert.equal(onDisk().length, before);
});

test('same bytes in a DIFFERENT group is allowed, but disk still holds one physical copy', async () => {
  const r = await processUpload({ ...base, groupId: 'G2', buffer: Buffer.from('hello smartshare'), originalName: 'a.txt' });
  assert.equal(r.duplicate, false);
  assert.equal(onDisk().length, 1);
});

test('different bytes = new file', async () => {
  const r = await processUpload({ ...base, buffer: Buffer.from('something else'), originalName: 'b.txt' });
  assert.equal(r.duplicate, false);
  assert.equal(onDisk().length, 2);
});

test('simultaneous identical uploads: exactly one wins, the other becomes a duplicate (race condition)', async () => {
  const run = () => processUpload({ ...base, groupId: 'G3', buffer: Buffer.from('race'), originalName: 'r.txt' });
  const results = await Promise.all([run(), run(), run()]);
  assert.deepEqual(results.map((r) => r.duplicate).sort(), [false, true, true]);
  assert.equal(rows.filter((r) => r.groupId === 'G3').length, 1);
});

test('no temp files are left behind (atomic write)', () => {
  assert.ok(onDisk().every((f) => !f.endsWith('.tmp')));
});

test('hostile file names cannot escape the upload folder', async () => {
  const r = await processUpload({ ...base, groupId: 'G4', buffer: Buffer.from('evil'), originalName: '../../etc/passwd.txt' });
  assert.ok(r.fileHash.physicalFilePath.startsWith('uploads/'));
  assert.ok(!r.fileHash.physicalFilePath.slice(8).includes('/'));
  assert.ok(!r.fileHash.originalName.includes('/'));
});

test('cleanName strips control characters and restores UTF-8 from latin1', () => {
  assert.equal(cleanName('a\u0000b\nc.txt'), 'abc.txt');
  assert.equal(cleanName(Buffer.from('फोटो.jpg', 'utf8').toString('latin1')), 'फोटो.jpg');
  assert.equal(cleanName(''), 'file');
});

/* ------------------------- similar-image detection through the real upload path ------------------------- */
let sharp = null;
try { sharp = require('sharp'); } catch { /* tests below are skipped */ }

async function photo(seed) {
  let s = seed; const rnd = () => ((s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296);
  const blobs = Array.from({ length: 14 }, () => `<circle cx="${rnd() * 800}" cy="${rnd() * 600}" r="${40 + rnd() * 160}" fill="rgb(${rnd() * 255 | 0},${rnd() * 255 | 0},${rnd() * 255 | 0})" opacity="0.7"/>`).join('');
  return sharp(Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600"><rect width="100%" height="100%" fill="rgb(${rnd() * 255 | 0},90,${rnd() * 255 | 0})"/>${blobs}</svg>`)).jpeg({ quality: 92 }).toBuffer();
}

test('similar image: a recompressed copy is stored but flagged; unrelated / other-group uploads are not', { skip: !sharp }, async () => {
  const original = await photo(5);
  const first = await processUpload({ ...base, groupId: 'G5', buffer: original, originalName: 'trip.jpg' });
  assert.equal(first.duplicate, false);
  assert.equal(first.similar, null);
  assert.equal(first.fileHash.phash.length, 136);

  const forwarded = await sharp(original).resize(400).jpeg({ quality: 40 }).toBuffer();        // different bytes, same look
  const second = await processUpload({ ...base, groupId: 'G5', senderId: 'U2', buffer: forwarded, originalName: 'IMG-2024.jpeg' });
  assert.equal(second.duplicate, false, 'different bytes are NOT an exact duplicate');
  assert.equal(second.similar.id, String(first.fileHash._id));
  assert.ok(second.similar.similarity >= 0.9);

  const other = await processUpload({ ...base, groupId: 'G5', buffer: await photo(9), originalName: 'other.jpg' });
  assert.equal(other.similar, null);

  const elsewhere = await processUpload({ ...base, groupId: 'G6', buffer: forwarded, originalName: 'x.jpg' });
  assert.equal(elsewhere.similar, null, 'similarity is only checked inside the same group');
});

test('non-image files are never fingerprinted', async () => {
  const r = await processUpload({ ...base, groupId: 'G7', buffer: Buffer.from('plain text file'), originalName: 'notes.txt' });
  assert.equal(r.similar, null);
  assert.equal(r.fileHash.phash, undefined);
});

test.after(() => fs.rmSync(UPLOAD_DIR, { recursive: true, force: true }));
