const test = require('node:test');
const assert = require('node:assert/strict');
const chats = require('../lib/chats');

test('directKey is the same for (a,b) and (b,a)', () => {
  assert.equal(chats.directKey('a1', 'b2'), chats.directKey('b2', 'a1'));
  assert.notEqual(chats.directKey('a1', 'b2'), chats.directKey('a1', 'c3'));
});

test('userFilter excludes me, trims/lowercases, and escapes regex characters', () => {
  assert.deepEqual(chats.userFilter('me', undefined), { _id: { $ne: 'me' } });
  assert.deepEqual(chats.userFilter('me', '  AL '), { _id: { $ne: 'me' }, username: { $regex: 'al' } });
  assert.equal(chats.userFilter('me', '.*').username.$regex, '\\.\\*');          // cannot inject a pattern
  assert.deepEqual(chats.userFilter('me', { $ne: 1 }), { _id: { $ne: 'me' } });   // non-strings ignored
});

test('editProblem: only the sender, only text, only within 15 minutes', () => {
  const now = Date.now();
  const msg = { senderId: 'u1', timestamp: new Date(now - 60_000), isMedia: false };
  assert.equal(chats.editProblem(msg, 'u1', now), null);
  assert.equal(chats.editProblem(msg, 'u2', now).status, 403);
  assert.equal(chats.editProblem(null, 'u1', now).status, 404);
  assert.equal(chats.editProblem({ ...msg, deleted: true }, 'u1', now).status, 404);
  assert.equal(chats.editProblem({ ...msg, isMedia: true }, 'u1', now).status, 400);
  assert.equal(chats.editProblem({ ...msg, mediaRef: 'x' }, 'u1', now).status, 400);   // duplicate alert
  assert.equal(chats.editProblem({ ...msg, timestamp: new Date(now - 16 * 60_000) }, 'u1', now).status, 400);
});

// tiny in-memory FileHash double
function fakeFileHash(rows) {
  return {
    async findOneAndDelete({ _id, groupId }) {
      const i = rows.findIndex((r) => r._id === _id && r.groupId === groupId);
      return i < 0 ? null : rows.splice(i, 1)[0];
    },
    async countDocuments({ physicalFilePath }) { return rows.filter((r) => r.physicalFilePath === physicalFilePath).length; },
  };
}

test('releaseFile keeps the bytes while another group still uses them (reference counting)', async () => {
  const rows = [
    { _id: 'f1', groupId: 'gA', physicalFilePath: 'uploads/h.png', size: 100 },
    { _id: 'f2', groupId: 'gB', physicalFilePath: 'uploads/h.png', size: 100 },
  ];
  const unlinked = [];
  const r = await chats.releaseFile({ FileHash: fakeFileHash(rows), fileId: 'f1', groupId: 'gA', uploadDir: '/up', unlink: async (p) => unlinked.push(p) });
  assert.deepEqual(r, { removed: true, physicalDeleted: false, bytesFreed: 0 });
  assert.equal(unlinked.length, 0);
  const r2 = await chats.releaseFile({ FileHash: fakeFileHash(rows), fileId: 'f2', groupId: 'gB', uploadDir: '/up', unlink: async (p) => unlinked.push(p) });
  assert.deepEqual(r2, { removed: true, physicalDeleted: true, bytesFreed: 100 });
  assert.deepEqual(unlinked, ['/up/h.png']);
});

test('releaseFile: wrong group removes nothing; missing file on disk is fine; path cannot escape', async () => {
  const rows = [{ _id: 'f1', groupId: 'gA', physicalFilePath: '../../etc/passwd', size: 5 }];
  const none = await chats.releaseFile({ FileHash: fakeFileHash(rows), fileId: 'f1', groupId: 'gZ', uploadDir: '/up', unlink: async () => assert.fail('no') });
  assert.equal(none.removed, false);
  const seen = [];
  const r = await chats.releaseFile({ FileHash: fakeFileHash(rows), fileId: 'f1', groupId: 'gA', uploadDir: '/up',
    unlink: async (p) => { seen.push(p); throw Object.assign(new Error('gone'), { code: 'ENOENT' }); } });
  assert.equal(r.physicalDeleted, true);
  assert.deepEqual(seen, ['/up/passwd']);                                         // basename only
});
