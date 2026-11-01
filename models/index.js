/**
 * models/index.js  -  DATABASE LAYER (Mongoose schemas)
 * ------------------------------------------------------------------
 * Four collections, exactly as in the project specification:
 *
 *   User ──< Group.members          (many-to-many: a user is in many groups)
 *   Group ──< Message.groupId       (one group has many messages)
 *   User ──< Message.senderId       (one user sends many messages)
 *   Group ──< FileHash.groupId      (one group has many UNIQUE files)
 *   Message.mediaRef ──> FileHash._id   (a media message points to a file record)
 *
 * NOTE for viva: MongoDB stores the primary key as `_id`. Mongoose adds a
 * virtual getter `id` (the same value as a string), so the spec's `id`
 * field is satisfied without declaring it manually.
 */
const mongoose = require('mongoose');
const { Schema } = mongoose;

// ---------------------------------------------------------------- USER
const userSchema = new Schema({
  // stored lower-case: "Alice" and "alice" must not be two different accounts (impersonation)
  username: { type: String, required: true, unique: true, trim: true, lowercase: true, minlength: 3, maxlength: 20 },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  // Never the plain password - bcrypt hash only (see /api/register in server.js)
  password: { type: String, required: true },
  // AUTO-TRANSLATE: the language this user wants to READ messages in, and whether to translate at all
  language:       { type: String, default: 'en' },
  autoTranslate:  { type: Boolean, default: true },
});

// --------------------------------------------------------------- GROUP
const groupSchema = new Schema({
  name:    { type: String, required: true, trim: true },
  members: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  // ONE-TO-ONE CHAT: a direct chat is simply a Group with exactly two members, so dedup, gallery,
  // translation, link checks... all work unchanged. `directKey` = the two user ids sorted and joined,
  // and its unique index guarantees there is only ever ONE direct chat per pair (even under a race).
  isDirect:  { type: Boolean, default: false },
  directKey: { type: String },
});

groupSchema.index({ directKey: 1 }, { unique: true, partialFilterExpression: { directKey: { $type: 'string' } } });
groupSchema.index({ members: 1 });          // "which groups am I in?" is asked on every page load

// ------------------------------------------------------------- MESSAGE
const messageSchema = new Schema({
  groupId:   { type: Schema.Types.ObjectId, ref: 'Group', required: true, index: true },
  senderId:  { type: Schema.Types.ObjectId, ref: 'User', required: true },
  text:      { type: String, default: '' },
  timestamp: { type: Date, default: Date.now },
  isMedia:   { type: Boolean, default: false },
  // String form of a FileHash._id.
  //  - isMedia === true  -> this bubble IS a (new, unique) file
  //  - isMedia === false && mediaRef set -> this bubble is a DUPLICATE ALERT
  //    that points back at the original file's FileHash record.
  mediaRef:  { type: String },
  // LINK DETECTION: one entry per http(s) link found in `text`.
  //   key   = normalised form of the URL (see lib/links.js) - the comparison value
  //   dupOf = _id of the EARLIEST message in this group that had the same key (null = first time shared)
  links: [{
    _id: false,
    url:   { type: String, required: true },
    key:   { type: String, required: true },
    dupOf: { type: Schema.Types.ObjectId, default: null },
    // FRAUD-LINK CHECK result (see lib/linkRisk.js): 0-100 risk, verdict, and the reasons shown to the user
    risk:  { score: Number, level: String, reasons: [String] },
  }],
  // SIMILAR-IMAGE DETECTION: set on a NEW image that looks like an image already in the group
  similar: { fileId: String, similarity: Number },
  // AUTO-TRANSLATE cache: language code -> translated text pieces (one per text segment of the message)
  translations: { type: Map, of: [String] },
  // DELETE FOR EVERYONE: the row stays as a "message was deleted" tombstone (text, links, file pointer are wiped)
  deleted:  { type: Boolean, default: false },
  // EDIT: set when the sender changed the text (shown as "edited")
  editedAt: { type: Date },
});

// History is read newest-first in pages of 50 ("load older"): this index makes that fast.
messageSchema.index({ groupId: 1, _id: -1 });
messageSchema.index({ groupId: 1, 'links.key': 1 });   // "was this link already shared in this group?"

// ------------------------------------------------------------ FILEHASH
// One row per UNIQUE file per group. This collection IS the dedup index.
const fileHashSchema = new Schema({
  groupId:          { type: Schema.Types.ObjectId, ref: 'Group', required: true },
  fileHashString:   { type: String, required: true },            // SHA-256 hex (64 chars)
  physicalFilePath: { type: String, required: true },            // e.g. "uploads/ab12...ef.jpg"
  originalSenderId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  originalTimestamp:{ type: Date, default: Date.now },
  // Small extras so the UI can render the file nicely (not part of dedup logic)
  originalName:     { type: String },
  mimeType:         { type: String },
  size:             { type: Number, default: 0 },   // bytes; used by the Storage Savings stats
  phash:            { type: String },               // 136-hex "how it looks" fingerprint (images only, see lib/phash.js)
});

// DATABASE-LEVEL GUARANTEE: the same hash can exist only once per group.
// Even if two users upload the same file at the exact same millisecond
// (race condition), MongoDB rejects the 2nd insert with error code 11000.
fileHashSchema.index({ groupId: 1, fileHashString: 1 }, { unique: true });
// REFERENCE COUNTING: before deleting a file from disk we count how many rows (in any group) still use it.
fileHashSchema.index({ physicalFilePath: 1 });

module.exports = {
  User: mongoose.model('User', userSchema),
  Group: mongoose.model('Group', groupSchema),
  Message: mongoose.model('Message', messageSchema),
  FileHash: mongoose.model('FileHash', fileHashSchema),
};
