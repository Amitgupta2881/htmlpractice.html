const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    email: { type: String, required: true },
    type: { type: String, enum: ['Deposit', 'Withdrawal'], required: true },
    amount: { type: Number, required: true },
    utr: { type: String }, 
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Transaction', transactionSchema);