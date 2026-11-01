// Run with:  npm test      (uses Node's built-in test runner - no extra packages)
const test = require('node:test');
const assert = require('node:assert/strict');
const v = require('../lib/validate');

test('username: trims, lower-cases, enforces pattern', () => {
  assert.equal(v.username('  Alice_1 '), 'alice_1');
  assert.throws(() => v.username('ab'), v.ValidationError);
  assert.throws(() => v.username('has space'));
  assert.throws(() => v.username('a'.repeat(21)));
});

test('NoSQL injection: objects/arrays are rejected, never passed on', () => {
  assert.throws(() => v.username({ $ne: null }));
  assert.throws(() => v.email({ $gt: '' }));
  assert.throws(() => v.password({ $ne: 1 }));
  assert.throws(() => v.groupName(['x']));
  assert.equal(v.messageText({ $ne: 1 }), null);
});

test('email', () => {
  assert.equal(v.email(' Bob@Example.COM '), 'bob@example.com');
  assert.throws(() => v.email('not-an-email'));
});

test('password: 8-72 bytes', () => {
  assert.equal(v.password('12345678'), '12345678');
  assert.throws(() => v.password('short'));
  assert.throws(() => v.password('x'.repeat(73)));
});

test('messageText: empty or > 4000 chars -> null', () => {
  assert.equal(v.messageText('  hi  '), 'hi');
  assert.equal(v.messageText('   '), null);
  assert.equal(v.messageText('x'.repeat(4001)), null);
});

test('usernameList: dedupes, drops invalid, caps size', () => {
  assert.deepEqual(v.usernameList(['Bob', 'bob', 'x', 5, { a: 1 }, 'carol_1']), ['bob', 'carol_1']);
  assert.deepEqual(v.usernameList('bob'), []);
  assert.equal(v.usernameList(Array.from({ length: 200 }, (_, i) => 'user' + i)).length, 50);
});

test('isObjectId: only 24 hex characters', () => {
  assert.ok(v.isObjectId('507f1f77bcf86cd799439011'));
  assert.ok(!v.isObjectId('507f1f77bcf86cd79943901'));
  assert.ok(!v.isObjectId({ $ne: 1 }));
  assert.ok(!v.isObjectId('x'.repeat(24)));
});
