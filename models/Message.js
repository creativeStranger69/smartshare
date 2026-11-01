// ---------------------------------------------------------------------------
// models/Message.js  -  MESSAGE SCHEMA
// Fields: id (auto), groupId, senderId, text, timestamp, isMedia, mediaRef
//
// HOW THE THREE KINDS OF CHAT BUBBLES ARE STORED (all in this one schema):
//
//   1. Plain text         ->  isMedia:false, mediaRef:undefined
//   2. Media (new file)   ->  isMedia:true,  mediaRef:"<FileHash _id>"
//   3. Dedup system alert ->  isMedia:false, mediaRef:"<FileHash _id of the ORIGINAL>"
//                             (text holds the "System Alert: ..." sentence)
//
// So `mediaRef` is the pointer to the FileHash collection. For a duplicate,
// it points at the file that was shared FIRST - that is the "text pointer".
// The frontend tells (3) apart from (1) by:  !isMedia && mediaRef
// ---------------------------------------------------------------------------
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  groupId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
  senderId:  { type: mongoose.Schema.Types.ObjectId, ref: 'User',  required: true },
  text:      { type: String, default: '', maxlength: 2000 },
  timestamp: { type: Date, default: Date.now },
  isMedia:   { type: Boolean, default: false },
  mediaRef:  { type: String }, // FileHash _id stored as string (see above)
});

// Chat history is always "messages of group X ordered by time".
messageSchema.index({ groupId: 1, timestamp: 1 });

module.exports = mongoose.model('Message', messageSchema);
