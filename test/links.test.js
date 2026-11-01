const test = require('node:test');
const assert = require('node:assert/strict');
const { findLinks, normalize, toParts } = require('../lib/links');

const urls = (t) => findLinks(t).map((l) => l.url);
const keys = (t) => findLinks(t).map((l) => l.key);

test('finds http/https links in normal sentences', () => {
  assert.deepEqual(urls('check https://example.com/a and http://test.org/x?y=1 now'),
    ['https://example.com/a', 'http://test.org/x?y=1']);
  assert.deepEqual(urls('no links here'), []);
});

test('sentence punctuation is not part of the link, but balanced brackets are', () => {
  assert.deepEqual(urls('see https://example.com/page.'), ['https://example.com/page']);
  assert.deepEqual(urls('(https://example.com/page)'), ['https://example.com/page']);
  assert.deepEqual(urls('https://en.wikipedia.org/wiki/Foo_(bar)'), ['https://en.wikipedia.org/wiki/Foo_(bar)']);
  assert.deepEqual(urls('wow https://example.com/a!!'), ['https://example.com/a']);
});

test('dangerous or fake schemes are never links', () => {
  assert.deepEqual(urls('javascript:alert(1) data:text/html,<script> ftp://example.com file:///etc/passwd'), []);
  assert.deepEqual(urls('http://abc'), []);                      // no dot -> not a real site
  assert.deepEqual(urls('http://localhost:3000/x'), ['http://localhost:3000/x']);
});

test('different spellings of the same page get the same key', () => {
  const same = [
    'https://www.Example.com/post/',
    'http://example.com/post?utm_source=whatsapp&utm_medium=x',
    'https://example.com/post#comments',
    'https://example.com:443/post',
  ];
  const k = same.map((u) => keys(u)[0]);
  assert.ok(k.every((x) => x === 'https://example.com/post'), JSON.stringify(k));
  assert.equal(keys('https://a.com/?b=2&a=1')[0], keys('https://a.com/?a=1&b=2')[0]);
});

test('genuinely different pages get different keys', () => {
  assert.notEqual(keys('https://example.com/post1')[0], keys('https://example.com/post2')[0]);
  assert.notEqual(keys('https://example.com/p?id=1')[0], keys('https://example.com/p?id=2')[0]);
  assert.notEqual(keys('https://example.com/Post')[0], keys('https://example.com/post')[0]);   // paths are case-sensitive
});

test('only the first 5 links in a message are detected', () => {
  const text = Array.from({ length: 9 }, (_, i) => `https://site${i}.com`).join(' ');
  assert.equal(findLinks(text).length, 5);
});

test('toParts splits text so it can be rendered without innerHTML', () => {
  const text = 'hi https://example.com/a bye';
  const parts = toParts(text);
  assert.deepEqual(parts.map((p) => p.type), ['text', 'link', 'text']);
  assert.equal(parts.map((p) => p.value).join(''), text);        // nothing lost or reordered
  assert.equal(parts[1].url, 'https://example.com/a');
  assert.equal(toParts('plain text'), null);
});

test('hostile text stays inert data', () => {
  const parts = toParts('<script>alert(1)</script> https://example.com/<b>x');
  assert.equal(parts.map((p) => p.value).join(''), '<script>alert(1)</script> https://example.com/<b>x');
  assert.ok(findLinks('https://example.com/a"onmouseover="x').every((l) => !l.url.includes('"')));
});

test('normalize works on a URL object', () => {
  assert.equal(normalize(new URL('HTTP://WWW.Example.COM/')), 'https://example.com');
});
