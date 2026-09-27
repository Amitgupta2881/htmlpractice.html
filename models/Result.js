const mongoose = require('mongoose');

const resultSchema = new mongoose.Schema({
    period: { type: Number, required: true },
    gameType: { type: String, enum: ['30s', '1m', '3m', '5m'], default: '30s', required: true },
    number: { type: Number, required: true },
    size: { type: String, required: true },
    colors: { type: [String], required: true },
    date: { type: Date, default: Date.now }
});

resultSchema.index({ period: 1, gameType: 1 }, { unique: true });

module.exports = mongoose.model('Result', resultSchema);