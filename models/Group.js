// ---------------------------------------------------------------------------
// models/Group.js  -  GROUP SCHEMA
// Fields: id (auto), name, members (array of User IDs)
// A user can only read/write a group if their ID is inside `members`.
// ---------------------------------------------------------------------------
const mongoose = require('mongoose');

const groupSchema = new mongoose.Schema({
  name:    { type: String, required: true, trim: true, maxlength: 40 },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

// Index so "all groups of user X" is a fast lookup.
groupSchema.index({ members: 1 });

module.exports = mongoose.model('Group', groupSchema);
