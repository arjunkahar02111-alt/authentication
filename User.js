const mongoose = require("mongoose");

module.exports = mongoose.model("User", new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  refreshToken: String
},{ timestamps:true }));
