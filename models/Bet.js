const mongoose = require('mongoose');

const BetSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    amount: { type: Number, required: true },
    
    // betOn will store what the user clicked: e.g., 'Red', 'Green', 'Violet', or a number '0'-'9'
    betOn: { type: String, required: true }, 
    period: { type: Number, required: true },
    gameType: { type: String, enum: ['30s', '1m', '3m', '5m'], default: '30s', required: true },
    // Status will update to 'Win' or 'Loss' when the timer ends
    status: { type: String, default: 'Pending' }, 
    
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Bet', BetSchema);