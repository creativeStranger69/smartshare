// ---------------------------------------------------------------------------
// models/FileHash.js  -  FILEHASH SCHEMA  (the heart of deduplication)
// Fields: id (auto), groupId, fileHashString (SHA-256), physicalFilePath,
//         originalSenderId, originalTimestamp
//
// One document = "this exact file content was first shared in THIS group by
// THIS user at THIS time, and lives on disk at physicalFilePath".
//
// The COMPOUND UNIQUE INDEX {groupId, fileHashString} is what makes the
// guarantee strong: even if two users upload the same file at the same
// millisecond, MongoDB itself refuses the second insert (error code 11000),
// so a group can never contain the same content twice. The same file CAN
// exist in two different groups (dedup is scoped per group, as required).
// ---------------------------------------------------------------------------
const mongoose = require('mongoose');

const fileHashSchema = new mongoose.Schema({
  groupId:          { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
  fileHashString:   { type: String, required: true },          // 64 hex chars (SHA-256)
  physicalFilePath: { type: String, required: true },          // e.g. "uploads/ab12...ef.jpg"
  originalSenderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  originalTimestamp:{ type: Date, default: Date.now },
});

fileHashSchema.index({ groupId: 1, fileHashString: 1 }, { unique: true });
fileHashSchema.index({ fileHashString: 1 }); // lets us reuse the disk file across groups

module.exports = mongoose.model('FileHash', fileHashSchema);
