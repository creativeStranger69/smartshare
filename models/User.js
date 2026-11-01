// ---------------------------------------------------------------------------
// models/User.js  -  USER SCHEMA
// Fields: id (auto, exposed by Mongoose as a virtual of _id), username, email, password
// NOTE: `password` never stores plain text. server.js stores a bcrypt hash here.
// ---------------------------------------------------------------------------
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 20 },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true }, // bcrypt hash
});

module.exports = mongoose.model('User', userSchema);
