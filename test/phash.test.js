/**
 * Similar-image tests. They build "photos" with sharp, make recompressed/resized/brightened
 * copies, and check the fingerprints. Skipped automatically if sharp is not installed.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const ph = require('../lib/phash');

let sharp = null;
try { sharp = require('sharp'); } catch { /* skip */ }
const skip = !sharp || !ph.isAvailable();

// deterministic pseudo-random numbers so "photo A" is always the same picture
function rng(seed) { let s = seed; return () => ((s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296); }

/** A photo-like picture: soft coloured blobs on a gradient. Different seed = different picture. */
async function makePhoto(seed, w = 800, h = 600) {
  const r = rng(seed);
  const blobs = Array.from({ length: 14 }, () => {
    const c = () => Math.floor(r() * 255);
    return `<circle cx="${r() * w}" cy="${r() * h}" r="${40 + r() * 160}" fill="rgb(${c()},${c()},${c()})" opacity="${0.4 + r() * 0.5}"/>`;
  }).join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
    <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="rgb(${Math.floor(r() * 255)},${Math.floor(r() * 255)},${Math.floor(r() * 255)})"/>
    <stop offset="1" stop-color="rgb(${Math.floor(r() * 255)},${Math.floor(r() * 255)},${Math.floor(r() * 255)})"/></linearGradient></defs>
    <rect width="100%" height="100%" fill="url(#g)"/>${blobs}</svg>`;
  return sharp(Buffer.from(svg)).jpeg({ quality: 92 }).toBuffer();
}

test('same picture after typical forwarding/editing is detected as similar', { skip }, async () => {
  const original = await makePhoto(1);
  const variants = {
    'low-quality jpeg (q30)': await sharp(original).jpeg({ quality: 30 }).toBuffer(),
    'whatsapp-style (1/2 size, q60)': await sharp(original).resize(400).jpeg({ quality: 60 }).toBuffer(),
    'upscaled 2x': await sharp(original).resize(1600).jpeg().toBuffer(),
    'png re-encode': await sharp(original).png().toBuffer(),
    'brightness +15%': await sharp(original).modulate({ brightness: 1.15 }).jpeg().toBuffer(),
    'slight blur': await sharp(original).blur(1.5).jpeg().toBuffer(),
    'greyscale': await sharp(original).greyscale().jpeg().toBuffer(),
  };
  const h0 = await ph.dHash(original);
  assert.equal(h0.length, 136);
  for (const [name, buf] of Object.entries(variants)) {
    const s = ph.similarity(h0, await ph.dHash(buf));
    assert.ok(s >= ph.SIMILAR_MIN, `${name}: similarity ${(s * 100).toFixed(1)}% is below the threshold`);
  }
});

test('different pictures are NOT similar', { skip }, async () => {
  const hashes = [];
  for (let seed = 1; seed <= 12; seed++) hashes.push(await ph.dHash(await makePhoto(seed)));
  let worst = 0;
  for (let i = 0; i < hashes.length; i++) for (let j = i + 1; j < hashes.length; j++) worst = Math.max(worst, ph.similarity(hashes[i], hashes[j]));
  assert.ok(worst < ph.SIMILAR_MIN - 0.05, `two unrelated pictures reached ${(worst * 100).toFixed(1)}% similarity`);
});

test('findSimilar returns the best match above the threshold, or null', { skip }, async () => {
  const a = await makePhoto(1), b = await makePhoto(2);
  const ha = await ph.dHash(a), hb = await ph.dHash(b);
  const copyOfA = await ph.dHash(await sharp(a).resize(300).jpeg({ quality: 50 }).toBuffer());
  const hit = ph.findSimilar(copyOfA, [{ id: 'B', phash: hb }, { id: 'A', phash: ha }]);
  assert.equal(hit.id, 'A');
  assert.ok(hit.similarity >= ph.SIMILAR_MIN);
  assert.equal(ph.findSimilar(copyOfA, [{ id: 'B', phash: hb }]), null);
  assert.equal(ph.findSimilar(copyOfA, []), null);
});

test('blank images, non-images and garbage give null instead of a fingerprint or a crash', { skip }, async () => {
  const blank = await sharp({ create: { width: 200, height: 200, channels: 3, background: '#ffffff' } }).png().toBuffer();
  assert.equal(await ph.dHash(blank), null);
  assert.equal(await ph.dHash(Buffer.from('this is not an image')), null);
  assert.equal(await ph.dHash(Buffer.alloc(0)), null);
});

test('hamming distance basics', () => {
  assert.equal(ph.hamming('00ff', '00ff'), 0);
  assert.equal(ph.hamming('00ff', 'ffff'), 8);
  assert.equal(ph.similarity('00', '00'), 1);
});
