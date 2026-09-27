const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    walletBalance: { type: Number, default: 0.00 },
    inviteCode: { type: String, unique: true },
    referredBy: { type: String, default: null },
    level1Commission: { type: Number, default: 0.00 },
    level2Commission: { type: Number, default: 0.00 },
    ipAddress: { type: String, default: null },
    savedBankDetails: { type: String, default: null },
    status: { type: String, enum: ['active', 'blocked'], default: 'active' },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    lastCheckInDate: { type: String, default: null },
    totalCheckIns: { type: Number, default: 0 },
    totalDeposited: { type: Number, default: 0 },
    totalWagered: { type: Number, default: 0 },
    signupBonusAmount: { type: Number, default: 0 }
});

module.exports = mongoose.model('User', UserSchema);