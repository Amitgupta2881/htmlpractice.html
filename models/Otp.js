const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    otp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 } // 5 minute baad auto-delete (TTL Index)
});

module.exports = mongoose.model('Otp', otpSchema);