process.env.TZ = 'Asia/Kolkata';
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const mongoSanitize = require('express-mongo-sanitize');
const crypto = require('crypto');

// Models Import
const User = require('./models/User');
const Otp = require('./models/Otp');
const Bet = require('./models/Bet');
const Result = require('./models/Result');
const Transaction = require('./models/Transaction');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const GAME_MODES = {
    '30s': { intervalSec: 30 },
    '1m': { intervalSec: 60 },
    '3m': { intervalSec: 180 },
    '5m': { intervalSec: 300 }
};

app.use(helmet({
    contentSecurityPolicy: false // Allow inline scripts/styles for static files
}));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname)); // Serve frontend files

// Rate Limiter
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100,
    message: "Too many requests, please slow down."
});
app.use('/api/', apiLimiter);

const withdrawLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    handler: (req, res) => {
        res.status(429).json({ message: "Too many withdrawal requests, please try again later." });
    }
});

// 🛡️ JWT Security Middleware
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ message: "Token missing! Access Denied." });
    
    const token = authHeader.split(" ")[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'AmitSuperSecretKey123');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Unauthorized! Token Expired." });
    }
};

// 👑 Admin Security Middleware
const verifyAdmin = async (req, res, next) => {
    try {
        const user = await User.findOne({ email: req.user.email });
        if (user && user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ message: "Access Denied! You are not an Admin." });
        }
    } catch (err) {
        res.status(500).json({ message: "Server error checking admin rights." });
    }
};

// 🔌 MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { family: 4 })
    .then(async () => {
        console.log('✅ Connected to MongoDB successfully!');
        await syncOfflinePeriods();
    })
    .catch((err) => console.log('❌ Database error:', err));

async function syncOfflinePeriods() {
    console.log("🔄 Syncing offline periods...");
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const dateString = `${year}${month}${day}`;
    const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const msSinceMidnight = now.getTime() - midnight;

    for (const [mode, config] of Object.entries(GAME_MODES)) {
        try {
            const intervalMs = config.intervalSec * 1000;
            const periodSequence = Math.floor(msSinceMidnight / intervalMs) + 1;
            const currentLivePeriod = parseInt(`${dateString}${String(periodSequence).padStart(4, '0')}`);

            const lastResult = await Result.findOne({ gameType: mode }).sort({ period: -1 });
            let lastPeriod = lastResult ? lastResult.period : parseInt(`${dateString}0000`);
            
            if (String(lastPeriod).startsWith(dateString) && lastPeriod < currentLivePeriod - 1) {
                console.log(`Missing periods for ${mode} from ${lastPeriod + 1} to ${currentLivePeriod - 1}. Generating...`);
                let newResults = [];
                for (let p = lastPeriod + 1; p < currentLivePeriod; p++) {
                    const outcomesData = [
                        { number: 0, size: 'Small', colors: ['Red', 'Violet'] },
                        { number: 1, size: 'Small', colors: ['Green'] },
                        { number: 2, size: 'Small', colors: ['Red'] },
                        { number: 3, size: 'Small', colors: ['Green'] },
                        { number: 4, size: 'Small', colors: ['Red'] },
                        { number: 5, size: 'Big', colors: ['Green', 'Violet'] },
                        { number: 6, size: 'Big', colors: ['Red'] },
                        { number: 7, size: 'Big', colors: ['Green'] },
                        { number: 8, size: 'Big', colors: ['Red'] },
                        { number: 9, size: 'Big', colors: ['Green'] }
                    ];
                    const randomDraw = outcomesData[Math.floor(Math.random() * outcomesData.length)];
                    newResults.push({
                        period: p,
                        gameType: mode,
                        number: randomDraw.number,
                        size: randomDraw.size,
                        colors: randomDraw.colors
                    });
                }
                if (newResults.length > 0) {
                    await Result.insertMany(newResults);
                    console.log(`✅ Generated ${newResults.length} missing periods for ${mode}.`);
                }
            }
        } catch (err) {
            console.error(`Error syncing offline periods for ${mode}:`, err);
        }
    }
}

// ==========================================
// 👤 AUTHENTICATION ROUTES
// ==========================================
app.post('/signup', async (req, res) => {
    try {
        const { username, email, password, inviteCode } = req.body;
        
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const ipCount = await User.countDocuments({ ipAddress: clientIp });
        if (ipCount >= 10) {
            return res.status(403).json({ message: "IP limit exceeded! Too many accounts created from this IP." });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        let referredBy = null;
        if (inviteCode) {
            const referrer = await User.findOne({ inviteCode });
            if (referrer) referredBy = inviteCode;
        }

        const newInviteCode = crypto.randomBytes(4).toString('hex').toUpperCase();
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const initialBonus = referredBy ? 20 : 0;
        
        const newUser = new User({ 
            username, 
            email, 
            password: hashedPassword, 
            walletBalance: initialBonus,
            signupBonusAmount: initialBonus,
            inviteCode: newInviteCode,
            referredBy,
            ipAddress: clientIp
        });
        await newUser.save();

        res.status(201).json({ message: "Account created successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

        if (user.status === 'blocked') {
            return res.status(403).json({ message: "Your account has been blocked by Admin." });
        }

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET || 'AmitSuperSecretKey123', { expiresIn: '24h' });
        
        res.status(200).json({ 
            message: "Login successful", 
            token, 
            walletBalance: user.walletBalance,
            redirect: true,
            redirectUrl: 'dashboard.html' 
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ==========================================
// 🎁 DAILY CHECK-IN API
// ==========================================
app.post('/api/user/checkin', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const todayDate = `${year}${month}${day}`;

        if (user.lastCheckInDate === todayDate) {
            return res.status(400).json({ message: "Aap aaj ka bonus already le chuke hain!" });
        }

        const bonusAmount = 5; // ₹5 daily bonus
        user.lastCheckInDate = todayDate;
        user.totalCheckIns += 1;
        user.walletBalance += bonusAmount;
        await user.save();

        res.status(200).json({
            message: `Check-in successful! Aapko ₹${bonusAmount} bonus mila.`,
            walletBalance: user.walletBalance
        });
    } catch (err) {
        res.status(500).json({ message: "Server error during checkin." });
    }
});

// ==========================================
// 💸 AGENCY COMMISSION CLAIM API
// ==========================================
app.post('/api/user/claim-commission', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const totalCommission = (user.level1Commission || 0) + (user.level2Commission || 0);
        
        if (totalCommission <= 0) {
            return res.status(400).json({ message: "No commission available to claim!" });
        }

        user.walletBalance += totalCommission;
        user.level1Commission = 0;
        user.level2Commission = 0;
        await user.save();

        res.status(200).json({
            message: `Successfully claimed ₹${totalCommission.toFixed(2)} commission!`,
            walletBalance: user.walletBalance
        });
    } catch (err) {
        res.status(500).json({ message: "Server error during claim." });
    }
});

// ==========================================
// 💳 PAYMENT & TRANSACTION ROUTES (AUTO-APPROVE)
// ==========================================
// 1. User Deposit Request API (FULLY AUTOMATED)
app.post('/api/user/deposit', verifyToken, async (req, res) => {
    try {
        const { amount, utrNumber } = req.body;
        const user = await User.findOne({ email: req.user.email });

        if (!amount || !utrNumber) {
            return res.status(400).json({ message: "Amount aur UTR number dono zaroori hain!" });
        }

        const existingTx = await Transaction.findOne({ utr: utrNumber });
        if (existingTx) {
            return res.status(400).json({ message: "Yeh UTR number pehle hi use ho chuka hai!" });
        }

        const newTx = new Transaction({
            email: user.email,
            type: 'Deposit',
            amount: Number(amount),
            utr: utrNumber,
            status: 'Pending' 
        });
        await newTx.save();

        res.status(200).json({ 
            message: `Deposit request submitted! Awaiting Admin verification.`,
            newBalance: user.walletBalance
        });
    } catch (err) {
        res.status(500).json({ message: "Server error during deposit processing." });
    }
});

// User Withdrawal Request API
app.post('/api/user/withdraw', verifyToken, withdrawLimiter, async (req, res) => {
    try {
        const { amount } = req.body;
        const parsedAmount = Number(amount);
        if (!parsedAmount || isNaN(parsedAmount) || parsedAmount <= 0) {
            return res.status(400).json({ message: "Invalid withdrawal amount!" });
        }

        const user = await User.findOne({ email: req.user.email });
        if (!user || user.status !== 'active') return res.status(400).json({ message: "Account blocked or invalid!" });
        if (!user.savedBankDetails) return res.status(400).json({ message: "Please add your Bank/UPI details first!" });
        if (user.walletBalance < parsedAmount) return res.status(400).json({ message: "Insufficient balance!" });

        if (parsedAmount < 100) {
            return res.status(400).json({ message: "Minimum withdrawal amount is ₹100!" });
        }

        const requiredWager = (user.totalDeposited || 0) + (user.signupBonusAmount || 0); // Require signup bonus + deposits to be played
        if ((user.totalWagered || 0) < requiredWager) {
            return res.status(403).json({ message: `Wagering requirement not met! Play games for ₹${requiredWager - (user.totalWagered || 0)} more to unlock withdrawals.` });
        }

        user.walletBalance -= parsedAmount;
        await user.save();

        const newTx = new Transaction({
            email: user.email,
            type: 'Withdrawal',
            amount: parsedAmount,
            utr: user.savedBankDetails, // Use saved bank details
            status: 'Pending'
        });
        await newTx.save();

        res.status(200).json({ 
            message: `Withdrawal request for ₹${parsedAmount} submitted. Awaiting Admin approval.`,
            newBalance: user.walletBalance
        });
    } catch (err) {
        res.status(500).json({ message: "Server error during withdrawal." });
    }
});

// Add Bank/UPI Details
app.post('/api/user/add-bank', verifyToken, async (req, res) => {
    try {
        const { bankDetails } = req.body;
        if (!bankDetails || bankDetails.trim() === '') {
            return res.status(400).json({ message: "Invalid bank details!" });
        }
        await User.findOneAndUpdate(
            { email: req.user.email },
            { savedBankDetails: bankDetails }
        );
        res.status(200).json({ message: "Bank details saved successfully!" });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

// User Transactions History API
app.get('/api/user/transactions', verifyToken, async (req, res) => {
    try {
        const transactions = await Transaction.find({ email: req.user.email }).sort({ date: -1 });
        res.status(200).json(transactions);
    } catch (err) {
        res.status(500).json({ message: "Error fetching transactions." });
    }
});

// 2. Admin: Saari Requests Dekhne Ka Route (History ke liye)
app.get('/api/admin/requests', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const requests = await Transaction.find().sort({ date: -1 });
        res.status(200).json(requests);
    } catch (err) {
        res.status(500).json({ message: "Error fetching transactions." });
    }
});

// Admin Stats
app.get('/api/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const pendingWithdrawals = await Transaction.find({ type: 'Withdrawal', status: 'Pending' });
        const pendingDeposits = await Transaction.find({ type: 'Deposit', status: 'Pending' });
        res.status(200).json({
            treasuryBalance: global.adminTreasury || 0,
            totalUsers,
            pendingWithdrawals,
            pendingDeposits
        });
    } catch (err) {
        res.status(500).json({ message: "Error fetching stats." });
    }
});

// Admin Users List & Update
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password').sort({ _id: -1 });
        res.status(200).json(users);
    } catch (err) {
        res.status(500).json({ message: "Error fetching users." });
    }
});

app.post('/api/admin/user/update', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { email, action, amount } = req.body; 
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found." });

        if (action === 'block') user.status = 'blocked';
        else if (action === 'unblock') user.status = 'active';
        else if (action === 'add_balance') {
            const val = Number(amount);
            if (val > 0) user.walletBalance += val;
        } else if (action === 'deduct_balance') {
            const val = Number(amount);
            if (val > 0 && user.walletBalance >= val) user.walletBalance -= val;
        }

        await user.save();
        res.status(200).json({ message: "User updated successfully." });
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

// Admin Deposit Approve/Reject
app.post('/api/admin/deposit/action', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { transactionId, action } = req.body;
        const tx = await Transaction.findById(transactionId);
        
        if (!tx || tx.type !== 'Deposit' || tx.status !== 'Pending') {
            return res.status(400).json({ message: "Invalid or already processed transaction." });
        }

        if (action === 'approve') {
            tx.status = 'Approved';
            await tx.save();
            await User.findOneAndUpdate(
                { email: tx.email },
                { $inc: { walletBalance: tx.amount, totalDeposited: tx.amount } }
            );
            return res.status(200).json({ message: "Deposit approved! Money added to user's wallet." });
        } else if (action === 'reject') {
            tx.status = 'Rejected';
            await tx.save();
            return res.status(200).json({ message: "Deposit rejected." });
        }
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

// Admin Withdrawal Approve/Reject
app.post('/api/admin/withdraw/action', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { transactionId, action } = req.body;
        const tx = await Transaction.findById(transactionId);
        
        if (!tx || tx.type !== 'Withdrawal' || tx.status !== 'Pending') {
            return res.status(400).json({ message: "Invalid or already processed transaction." });
        }

        if (action === 'approve') {
            tx.status = 'Approved';
            await tx.save();
            return res.status(200).json({ message: "Withdrawal approved successfully." });
        } else if (action === 'reject') {
            tx.status = 'Rejected';
            await tx.save();
            await User.findOneAndUpdate(
                { email: tx.email },
                { $inc: { walletBalance: tx.amount } }
            );
            return res.status(200).json({ message: "Withdrawal rejected and amount refunded." });
        }
    } catch (err) {
        res.status(500).json({ message: "Server error." });
    }
});

// ==========================================
// 🎮 GAME & WALLET ROUTES
// ==========================================
app.get('/api/user/:email', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.params.email });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.status(200).json({ 
            username: user.username, 
            walletBalance: user.walletBalance, 
            inviteCode: user.inviteCode,
            level1Commission: user.level1Commission,
            level2Commission: user.level2Commission,
            savedBankDetails: user.savedBankDetails
        });
    } catch (err) {
        res.status(500).json({ message: "Error fetching user data" });
    }
});

app.get('/api/current-game', (req, res) => {
    res.status(200).json(gameStates);
});

app.get('/api/game-history', async (req, res) => {
    try {
        const { gameType = '30s', page = 1, limit = 10 } = req.query;
        const history = await Result.find({ gameType })
                                    .sort({ period: -1 })
                                    .skip((page - 1) * limit)
                                    .limit(Number(limit));
        const total = await Result.countDocuments({ gameType });
        res.status(200).json({ data: history, totalPages: Math.ceil(total / limit), currentPage: Number(page) });
    } catch (err) {
        res.status(500).json({ message: "Error fetching history" });
    }
});

app.get('/api/bet-history/:email', async (req, res) => {
    try {
        const { gameType = '30s', page = 1, limit = 10 } = req.query;
        const bets = await Bet.find({ userEmail: req.params.email, gameType })
                              .sort({ createdAt: -1 })
                              .skip((page - 1) * limit)
                              .limit(Number(limit));
        const total = await Bet.countDocuments({ userEmail: req.params.email, gameType });
        res.status(200).json({ data: bets, totalPages: Math.ceil(total / limit), currentPage: Number(page) });
    } catch (err) {
        res.status(500).json({ message: "Error fetching bets" });
    }
});

app.post('/api/place-bet', verifyToken, async (req, res) => {
    try {
        const { amount, betOn, gameType = '30s' } = req.body;
        const userEmail = req.user.email;

        if (typeof amount !== 'number' || amount <= 0 || !Number.isInteger(amount)) {
            return res.status(400).json({ message: "Invalid bet amount! Must be a positive integer." });
        }

        if (gameStates[gameType] && gameStates[gameType].timeLeft <= 5) {
            return res.status(400).json({ message: "Time is up! Bet closed for this round." });
        }

        const user = await User.findOneAndUpdate(
            { email: userEmail, walletBalance: { $gte: amount }, status: 'active' },
            { $inc: { walletBalance: -amount, totalWagered: amount } },
            { new: true }
        );

        if (!user) return res.status(400).json({ message: "Insufficient balance or account blocked!" });

        const currentPeriod = gameStates[gameType].period;
        const newBet = new Bet({ userEmail, amount, betOn, period: currentPeriod, gameType, status: 'Pending' });
        await newBet.save();

        if (user.referredBy) {
            const level1Ref = await User.findOne({ inviteCode: user.referredBy });
            if (level1Ref) {
                const l1Com = amount * 0.01;
                await User.findOneAndUpdate(
                    { email: level1Ref.email },
                    { $inc: { walletBalance: l1Com, level1Commission: l1Com } }
                );

                if (level1Ref.referredBy) {
                    const level2Ref = await User.findOne({ inviteCode: level1Ref.referredBy });
                    if (level2Ref) {
                        const l2Com = amount * 0.005;
                        await User.findOneAndUpdate(
                            { email: level2Ref.email },
                            { $inc: { walletBalance: l2Com, level2Commission: l2Com } }
                        );
                    }
                }
            }
        }

        res.status(200).json({ message: `Successfully placed ₹${amount} on ${betOn}!`, newBalance: user.walletBalance });
    } catch (err) {
        res.status(500).json({ message: "Betting failed", error: err.message });
    }
});

// 📊 Admin Treasury API Route
app.get('/api/admin/treasury', verifyToken, verifyAdmin, (req, res) => {
    res.status(200).json({ 
        treasuryBalance: global.adminTreasury || 0 
    });
});

// 🎮 Admin Manual Rigging API
app.post('/api/admin/game/force-result', verifyToken, verifyAdmin, (req, res) => {
    const { gameType, outcome } = req.body; // outcome can be 'Green', 'Red', 'Violet', 'Big', 'Small', or specific number '0'-'9', or 'None'
    if (!gameStates[gameType]) return res.status(400).json({ message: "Invalid game type" });
    
    if (outcome === 'None') {
        global.forcedResults[gameType] = null;
    } else {
        global.forcedResults[gameType] = outcome;
    }
    
    res.status(200).json({ message: `Forced result for ${gameType} set to ${outcome}` });
});

app.get('/api/admin/game/forced-results', verifyToken, verifyAdmin, (req, res) => {
    res.status(200).json(global.forcedResults);
});

// ==========================================
// ⏱️ MULTI-TIMER MASTER GAME ENGINE (Time-Synced + 50/50 RTP + Tax)
// ==========================================

let gameStates = {
    '30s': { period: 0, timeLeft: 30 },
    '1m': { period: 0, timeLeft: 60 },
    '3m': { period: 0, timeLeft: 180 },
    '5m': { period: 0, timeLeft: 300 }
};

global.forcedResults = {
    '30s': null,
    '1m': null,
    '3m': null,
    '5m': null
};

if (typeof global.adminTreasury === 'undefined') global.adminTreasury = 0;

setInterval(async () => {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const dateString = `${year}${month}${day}`;

    const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const msSinceMidnight = now.getTime() - midnight;

    let updates = {};

    for (const [mode, config] of Object.entries(GAME_MODES)) {
        const intervalMs = config.intervalSec * 1000;
        const periodSequence = Math.floor(msSinceMidnight / intervalMs) + 1;
        const livePeriod = parseInt(`${dateString}${String(periodSequence).padStart(4, '0')}`);
        const currentSeconds = Math.floor((msSinceMidnight % intervalMs) / 1000);
        const liveTimeLeft = config.intervalSec - currentSeconds;

        if (gameStates[mode].period !== 0 && livePeriod !== gameStates[mode].period) {
            console.log(`\n--- Ending Period: ${gameStates[mode].period} for ${mode} ---`);
            processRound(mode, gameStates[mode].period);
        }

        gameStates[mode].period = livePeriod;
        gameStates[mode].timeLeft = liveTimeLeft;
        
        updates[mode] = { period: livePeriod, time: liveTimeLeft };
    }

    io.emit('timerUpdate', updates);
}, 1000);

async function processRound(gameType, period) {
    const PLATFORM_FEE = 0.02; 
    const ADMIN_RISK_LIMIT = 1000;

    try {
        const pendingBets = await Bet.find({ period: period, gameType: gameType, status: 'Pending' });
        let totalBetAmount = 0;
        let totalTaxCollected = 0;

        pendingBets.forEach(bet => {
            totalBetAmount += bet.amount;
            totalTaxCollected += (bet.amount * PLATFORM_FEE);
        });

        if (totalBetAmount > 0) {
            global.adminTreasury += totalTaxCollected;
        }

        let outcomesData = [];
        let minPayout = Infinity;

        for (let num = 0; num <= 9; num++) {
            let currentPayout = 0;
            const size = num >= 5 ? "Big" : "Small";
            let colors = [];
            if ([1, 3, 7, 9].includes(num)) colors = ["Green"];
            else if ([2, 4, 6, 8].includes(num)) colors = ["Red"];
            else if (num === 0) colors = ["Red", "Violet"];
            else if (num === 5) colors = ["Green", "Violet"];

            for (let bet of pendingBets) {
                const effectiveBet = bet.amount - (bet.amount * PLATFORM_FEE);
                let multiplier = 0;
                if (bet.betOn === size) multiplier = 2;
                else if (colors.includes(bet.betOn)) multiplier = bet.betOn === 'Violet' ? 4.5 : 2;
                else if (bet.betOn === num.toString()) multiplier = 9;
                
                if (multiplier > 0) currentPayout += (effectiveBet * multiplier);
            }
            outcomesData.push({ number: num, size, colors, payout: currentPayout });
            if (currentPayout < minPayout) minPayout = currentPayout;
        }

        let finalDraw;
        
        // 👑 ADMIN RIGGING OVERRIDE
        if (global.forcedResults[gameType]) {
            const forced = global.forcedResults[gameType];
            let possibleOutcomes = outcomesData.filter(out => 
                out.size === forced || 
                out.colors.includes(forced) || 
                out.number.toString() === forced
            );
            if (possibleOutcomes.length > 0) {
                finalDraw = possibleOutcomes[Math.floor(Math.random() * possibleOutcomes.length)];
                global.forcedResults[gameType] = null; // Reset after use for safety, or keep it? Let's reset so it's only one-shot per click.
            }
        }

        if (!finalDraw) {
            if (totalBetAmount > 0) {
                if (minPayout > (global.adminTreasury + ADMIN_RISK_LIMIT)) {
                    const safeOutcomes = outcomesData.filter(out => out.payout === minPayout);
                    finalDraw = safeOutcomes[Math.floor(Math.random() * safeOutcomes.length)];
                } else {
                    let winnableOutcomes = outcomesData.filter(out => out.payout > 0 && out.payout <= (global.adminTreasury + totalBetAmount));
                    
                    if (winnableOutcomes.length > 0) {
                        const rng = Math.random() * 100;
                        let winChance = totalBetAmount <= 500 ? 75 : 50; 
                        
                        if (rng <= winChance) {
                            finalDraw = winnableOutcomes[Math.floor(Math.random() * winnableOutcomes.length)];
                        } else {
                            let zeroPayoutOutcomes = outcomesData.filter(out => out.payout === 0);
                            finalDraw = zeroPayoutOutcomes.length > 0 ? zeroPayoutOutcomes[Math.floor(Math.random() * zeroPayoutOutcomes.length)] : outcomesData.filter(out => out.payout === minPayout)[0];
                        }
                    } else {
                        finalDraw = outcomesData.filter(out => out.payout === minPayout)[0];
                    }
                }
            } else {
                finalDraw = outcomesData[Math.floor(Math.random() * outcomesData.length)];
            }
        }

        if (totalBetAmount > 0) {
            const bettingProfitLoss = totalBetAmount - totalTaxCollected - finalDraw.payout;
            global.adminTreasury += bettingProfitLoss;
        }
        await Result.create({ period: period, gameType: gameType, number: finalDraw.number, size: finalDraw.size, colors: finalDraw.colors });

        for (let bet of pendingBets) {
            const effectiveBet = bet.amount - (bet.amount * PLATFORM_FEE);
            let isWinner = false, multiplier = 0;

            if (bet.betOn === finalDraw.size) { isWinner = true; multiplier = 2; }
            else if (finalDraw.colors.includes(bet.betOn)) { isWinner = true; multiplier = bet.betOn === 'Violet' ? 4.5 : 2; }
            else if (bet.betOn === finalDraw.number.toString()) { isWinner = true; multiplier = 9; }

            if (isWinner) {
                bet.status = 'Win';
                const winAmount = effectiveBet * multiplier;
                await User.findOneAndUpdate({ email: bet.userEmail }, { $inc: { walletBalance: winAmount } });
            } else {
                bet.status = 'Loss';
            }
            await bet.save();
        }

        // Rolling History: Keep only last 500 periods (50 pages) to prevent infinite growth & UI stuck
        const cutoffPeriod = period - 500;
        if (cutoffPeriod > 0) {
            await Result.deleteMany({ gameType: gameType, period: { $lte: cutoffPeriod } }).catch(e => console.log("Cleanup error:", e));
            await Bet.deleteMany({ gameType: gameType, period: { $lte: cutoffPeriod } }).catch(e => console.log("Cleanup error:", e));
        }

        io.emit('roundComplete', { gameType });
    } catch (error) {
        console.error(`Round processing error for ${gameType}:`, error);
    }
}

io.on('connection', (socket) => {
    socket.emit('timerUpdate', gameStates);
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server & Socket running on port ${PORT}`));