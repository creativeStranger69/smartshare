const test = require('node:test');
const assert = require('node:assert/strict');
const { servingInfo, contentDisposition } = require('../lib/files');

test('safe media types are served inline with a server-chosen content-type', () => {
  assert.deepEqual(servingInfo('uploads/abc.PNG'), { type: 'image/png', inline: true });
  assert.deepEqual(servingInfo('uploads/abc.mp4'), { type: 'video/mp4', inline: true });
  assert.deepEqual(servingInfo('uploads/abc.pdf'), { type: 'application/pdf', inline: true });
});

test('active content (html/svg/js) can never be rendered inline from our origin', () => {
  for (const ext of ['.html', '.htm', '.svg', '.js', '.xml', '.exe', '']) {
    assert.deepEqual(servingInfo('uploads/abc' + ext), { type: 'application/octet-stream', inline: false }, ext);
  }
});

test('content-disposition handles unicode and header-breaking characters', () => {
  const h = contentDisposition(false, 'फोटो (1).jpg');
  assert.match(h, /^attachment; filename\*=UTF-8''/);
  assert.ok(!/[\s"'()]/.test(h.split("''")[1]));
  assert.ok(contentDisposition(true, 'a.png').startsWith('inline;'));
});
