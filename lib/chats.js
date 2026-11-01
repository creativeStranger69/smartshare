/**
 * lib/chats.js - small, database-free helpers for one-to-one chats, user suggestions,
 * message editing and file clean-up. (Kept separate so they can be unit-tested.)
 */
const path = require('path');

const EDIT_WINDOW_MS = 15 * 60 * 1000;     // a message can be edited for 15 minutes after sending

/** The key of a one-to-one chat: the same for (a,b) and (b,a). A unique index on it prevents duplicate chats. */
const directKey = (a, b) => [String(a), String(b)].sort().join(':');

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Mongo filter for the "pick a user" suggestion list: everyone except me, optionally matching what I typed. */
function userFilter(meId, rawQuery) {
  const q = typeof rawQuery === 'string' ? rawQuery.trim().toLowerCase().slice(0, 20) : '';
  const filter = { _id: { $ne: meId } };
  if (q) filter.username = { $regex: escapeRegex(q) };   // escaped: a user can never inject a regex
  return filter;
}

/** Why can't this person edit this message? Returns null when editing is allowed. */
function editProblem(msg, userId, now = Date.now()) {
  if (!msg || msg.deleted) return { status: 404, error: 'Message not found' };
  if (String(msg.senderId) !== String(userId)) return { status: 403, error: 'You can only edit your own messages' };
  if (msg.isMedia || msg.mediaRef) return { status: 400, error: 'Only text messages can be edited' };
  if (now - new Date(msg.timestamp).getTime() > EDIT_WINDOW_MS) return { status: 400, error: 'Messages can only be edited for 15 minutes' };
  return null;
}

/**
 * REFERENCE COUNTING for stored files. Files are named by their hash and shared by every group that has the
 * same file, so one group deleting its copy must NOT remove the bytes while another group still uses them.
 *   1. delete this group's FileHash row (so the file can be shared again and leaves the gallery)
 *   2. count the rows that still point at the same physical file
 *   3. only when that count is 0, delete the bytes from disk
 */
async function releaseFile({ FileHash, fileId, groupId, uploadDir, unlink }) {
  const row = await FileHash.findOneAndDelete({ _id: fileId, groupId });
  if (!row) return { removed: false, physicalDeleted: false, bytesFreed: 0 };
  const stillUsed = await FileHash.countDocuments({ physicalFilePath: row.physicalFilePath });
  if (stillUsed > 0) return { removed: true, physicalDeleted: false, bytesFreed: 0 };
  try {
    await unlink(path.join(uploadDir, path.basename(row.physicalFilePath)));   // basename: never a path from outside
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;                                      // already gone is fine
  }
  return { removed: true, physicalDeleted: true, bytesFreed: row.size || 0 };
}

module.exports = { EDIT_WINDOW_MS, directKey, escapeRegex, userFilter, editProblem, releaseFile };
