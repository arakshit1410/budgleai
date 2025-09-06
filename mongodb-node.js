// src/index.js - Main server file
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const mongoose = require('mongoose');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const transactionRoutes = require('./routes/transactions');
const goalRoutes = require('./routes/goals');
const aiRoutes = require('./routes/ai');
const blockchainRoutes = require('./routes/blockchain');
const userRoutes = require('./routes/users');
const alertRoutes = require('./routes/alerts');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://mongo:27017/budgle', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/goals', goalRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/blockchain', blockchainRoutes);
app.use('/api/users', userRoutes);
app.use('/api/alerts', alertRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'BUDGLE Backend is running',
    timestamp: new Date().toISOString(),
    database: db.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: 'Something went wrong!', 
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal Server Error' 
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 BUDGLE Backend running on port ${PORT}`);
  console.log(`💰 AI + Blockchain Finance API Ready`);
});

// ===== src/models/User.js =====
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  mobile: {
    type: String,
    required: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  balance: {
    type: Number,
    default: 0
  },
  totalIncome: {
    type: Number,
    default: 0
  },
  totalExpenses: {
    type: Number,
    default: 0
  },
  karmaTokens: {
    type: Number,
    default: 0
  },
  blockchainAddress: {
    type: String,
    unique: true
  },
  aiPreferences: {
    autoCategorize: { type: Boolean, default: true },
    fraudDetection: { type: Boolean, default: true },
    smartAlerts: { type: Boolean, default: true }
  },
  settings: {
    notifications: { type: Boolean, default: true },
    currency: { type: String, default: 'INR' }
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);

// ===== src/models/Transaction.js =====
const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['food', 'transport', 'shopping', 'entertainment', 'health', 'utilities', 'education', 'income', 'other']
  },
  type: {
    type: String,
    required: true,
    enum: ['income', 'expense']
  },
  date: {
    type: Date,
    required: true
  },
  note: {
    type: String,
    trim: true
  },
  blockchainHash: {
    type: String,
    required: true
  },
  aiCategorized: {
    type: Boolean,
    default: false
  },
  aiConfidence: {
    type: Number,
    min: 0,
    max: 1
  },
  fraudCheck: {
    passed: { type: Boolean, default: true },
    score: { type: Number, default: 0 },
    reason: { type: String }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Transaction', transactionSchema);

// ===== src/models/Goal.js =====
const mongoose = require('mongoose');

const goalSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true
  },
  targetAmount: {
    type: Number,
    required: true
  },
  currentAmount: {
    type: Number,
    default: 0
  },
  frequency: {
    type: String,
    enum: ['daily', 'weekly', 'monthly', 'yearly'],
    default: 'monthly'
  },
  targetDate: {
    type: Date
  },
  status: {
    type: String,
    enum: ['active', 'completed', 'paused'],
    default: 'active'
  },
  icon: {
    type: String,
    default: '🎯'
  },
  blockchainHash: {
    type: String
  },
  aiOptimized: {
    suggestedAmount: { type: Number },
    optimizedDate: { type: Date },
    confidence: { type: Number }
  }
}, {
  timestamps: true
});

// Calculate progress percentage
goalSchema.virtual('progress').get(function() {
  return Math.round((this.currentAmount / this.targetAmount) * 100);
});

goalSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('Goal', goalSchema);

// ===== src/models/Alert.js =====
const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['normal', 'warning', 'danger', 'info'],
    required: true
  },
  category: {
    type: String,
    enum: ['fraud', 'spending', 'goal', 'system', 'ai', 'blockchain'],
    required: true
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  read: {
    type: Boolean,
    default: false
  },
  actionable: {
    type: Boolean,
    default: false
  },
  metadata: {
    transactionId: { type: mongoose.Schema.Types.ObjectId },
    amount: { type: Number },
    blockchainHash: { type: String }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Alert', alertSchema);

// ===== src/routes/auth.js =====
const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { generateBlockchainAddress } = require('../utils/blockchain');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { fullName, email, mobile, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Generate blockchain address
    const blockchainAddress = generateBlockchainAddress(email);

    // Create user
    const user = new User({
      fullName,
      email,
      mobile,
      password,
      blockchainAddress,
      karmaTokens: 100 // Welcome bonus
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'budgle-secret-key',
      { expiresIn: '30d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        mobile: user.mobile,
        blockchainAddress: user.blockchainAddress,
        karmaTokens: user.karmaTokens
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed', error: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'budgle-secret-key',
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        mobile: user.mobile,
        balance: user.balance,
        totalIncome: user.totalIncome,
        totalExpenses: user.totalExpenses,
        karmaTokens: user.karmaTokens,
        blockchainAddress: user.blockchainAddress
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

module.exports = router;

// ===== src/routes/transactions.js =====
const express = require('express');
const Transaction = require('../models/Transaction');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');
const { categorizeTransaction, detectFraud } = require('../utils/ai');
const { generateTransactionHash } = require('../utils/blockchain');

const router = express.Router();

// Get all transactions
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, category } = req.query;
    
    const query = { userId: req.user.userId };
    if (type) query.type = type;
    if (category) query.category = category;

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Transaction.countDocuments(query);

    res.json({
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch transactions', error: error.message });
  }
});

// Create transaction
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { title, amount, category, type, date, note } = req.body;

    // AI categorization
    const aiResult = categorizeTransaction(title, note);
    
    // Fraud detection
    const fraudCheck = detectFraud(title, amount, note);
    
    if (fraudCheck.isFraud) {
      return res.status(400).json({
        message: 'Transaction blocked for security',
        reason: fraudCheck.reason,
        confidence: fraudCheck.confidence
      });
    }

    // Generate blockchain hash
    const blockchainHash = generateTransactionHash({
      userId: req.user.userId,
      title,
      amount,
      category: aiResult.category,
      date
    });

    // Create transaction
    const transaction = new Transaction({
      userId: req.user.userId,
      title,
      amount: type === 'expense' ? -Math.abs(amount) : Math.abs(amount),
      category: aiResult.category,
      type,
      date: date || new Date(),
      note,
      blockchainHash,
      aiCategorized: aiResult.confidence > 0.7,
      aiConfidence: aiResult.confidence,
      fraudCheck: {
        passed: !fraudCheck.isFraud,
        score: fraudCheck.confidence,
        reason: fraudCheck.reason
      }
    });

    await transaction.save();

    // Update user balance
    const user = await User.findById(req.user.userId);
    if (type === 'expense') {
      user.totalExpenses += Math.abs(amount);
      user.balance -= Math.abs(amount);
    } else {
      user.totalIncome += Math.abs(amount);
      user.balance += Math.abs(amount);
    }
    
    // Award karma tokens
    const tokensEarned = Math.floor(Math.abs(amount) / 100);
    user.karmaTokens += tokensEarned;
    
    await user.save();

    res.status(201).json({
      message: 'Transaction created successfully',
      transaction,
      aiResult: {
        category: aiResult.category,
        confidence: aiResult.confidence,
        reasoning: aiResult.reasoning
      },
      tokensEarned,
      blockchainHash
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to create transaction', error: error.message });
  }
});

// Get transaction analytics
router.get('/analytics', authenticateToken, async (req, res) => {
  try {
    const { period = 'monthly' } = req.query;
    
    let dateFilter = {};
    const now = new Date();
    
    switch (period) {
      case 'weekly':
        dateFilter = { $gte: new Date(now - 7 * 24 * 60 * 60 * 1000) };
        break;
      case 'monthly':
        dateFilter = { $gte: new Date(now.getFullYear(), now.getMonth(), 1) };
        break;
      case 'yearly':
        dateFilter = { $gte: new Date(now.getFullYear(), 0, 1) };
        break;
    }

    const analytics = await Transaction.aggregate([
      {
        $match: {
          userId: req.user.userId,
          createdAt: dateFilter
        }
      },
      {
        $group: {
          _id: { type: '$type', category: '$category' },
          total: { $sum: { $abs: '$amount' } },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.type',
          categories: {
            $push: {
              category: '$_id.category',
              amount: '$total',
              count: '$count'
            }
          },
          totalAmount: { $sum: '$total' }
        }
      }
    ]);

    res.json({ analytics, period });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch analytics', error: error.message });
  }
});

module.exports = router;

// ===== src/routes/goals.js =====
const express = require('express');
const Goal = require('../models/Goal');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');
const { optimizeGoal } = require('../utils/ai');
const { generateGoalHash } = require('../utils/blockchain');

const router = express.Router();

// Get all goals
router.get('/', authenticateToken, async (req, res) => {
  try {
    const goals = await Goal.find({ userId: req.user.userId }).sort({ createdAt: -1 });
    res.json(goals);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch goals', error: error.message });
  }
});

// Create goal
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { name, targetAmount, frequency, targetDate, icon } = req.body;

    // AI goal optimization
    const optimization = optimizeGoal(targetAmount, frequency, req.user.userId);
    
    // Generate blockchain hash
    const blockchainHash = generateGoalHash({
      userId: req.user.userId,
      name,
      targetAmount,
      frequency
    });

    const goal = new Goal({
      userId: req.user.userId,
      name,
      targetAmount,
      frequency,
      targetDate,
      icon: icon || '🎯',
      blockchainHash,
      aiOptimized: optimization
    });

    await goal.save();

    // Award karma tokens for goal creation
    const user = await User.findById(req.user.userId);
    user.karmaTokens += 50;
    await user.save();

    res.status(201).json({
      message: 'Goal created successfully',
      goal,
      aiOptimization: optimization,
      tokensEarned: 50
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to create goal', error: error.message });
  }
});

// Update goal progress
router.put('/:goalId/progress', authenticateToken, async (req, res) => {
  try {
    const { amount } = req.body;
    
    const goal = await Goal.findOne({ _id: req.params.goalId, userId: req.user.userId });
    if (!goal) {
      return res.status(404).json({ message: 'Goal not found' });
    }

    goal.currentAmount += amount;
    
    // Check if goal is completed
    if (goal.currentAmount >= goal.targetAmount) {
      goal.status = 'completed';
      
      // Award completion bonus
      const user = await User.findById(req.user.userId);
      user.karmaTokens += 200;
      await user.save();
    }

    await goal.save();

    res.json({
      message: 'Goal progress updated',
      goal,
      tokensEarned: goal.status === 'completed' ? 200 : 0
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update goal', error: error.message });
  }
});

module.exports = router;

// ===== src/routes/ai.js =====
const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { 
  generateFinancialInsights, 
  detectSpendingPatterns,
  generateSavingsSuggestions 
} = require('../utils/ai');
const Transaction = require('../models/Transaction');
const User = require('../models/User');

const router = express.Router();

// Get AI financial insights
router.get('/insights', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(100);
    
    const user = await User.findById(req.user.userId);
    
    const insights = generateFinancialInsights(transactions, user);
    
    res.json(insights);
  } catch (error) {
    res.status(500).json({ message: 'Failed to generate insights', error: error.message });
  }
});

// Get spending patterns
router.get('/patterns', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ 
      userId: req.user.userId,
      type: 'expense'
    }).sort({ createdAt: -1 });
    
    const patterns = detectSpendingPatterns(transactions);
    
    res.json(patterns);
  } catch (error) {
    res.status(500).json({ message: 'Failed to detect patterns', error: error.message });
  }
});

// Get AI suggestions
router.get('/suggestions', authenticateToken, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user.userId })
      .sort({ createdAt: -1 });
    
    const user = await User.findById(req.user.userId);
    
    const suggestions = generateSavingsSuggestions(transactions, user);
    
    res.json(suggestions);
  } catch (error) {
    res.status(500).json({ message: 'Failed to generate suggestions', error: error.message });
  }
});

// Chat with AI assistant
router.post('/chat', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    
    // Get user context
    const user = await User.findById(req.user.userId);
    const recentTransactions = await Transaction.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(10);
    
    // Simple AI response generation (in production, use actual AI service)
    const response = generateAIResponse(message, user, recentTransactions);
    
    res.json({
      message: response.text,
      confidence: response.confidence,
      suggestions: response.suggestions
    });
  } catch (error) {
    res.status(500).json({ message: 'AI chat failed', error: error.message });
  }
});

function generateAIResponse(message, user, transactions) {
  const msg = message.toLowerCase();
  
  if (msg.includes('balance')) {
    return {
      text: `Your current balance is ₹${user.balance.toLocaleString()}. You have ₹${user.totalIncome.toLocaleString()} in income and ₹${user.totalExpenses.toLocaleString()} in expenses.`,
      confidence: 0.95,
      suggestions: ['View detailed breakdown', 'Set savings goal']
    };
  }
  
  if (msg.includes('spend') || msg.includes('expense')) {
    const topCategory = transactions.filter(t => t.type === 'expense')[0]?.category || 'general';
    return {
      text: `Your top spending category is ${topCategory}. You've spent ₹${user.totalExpenses.toLocaleString()} this month. Consider reducing expenses by 10% to save more.`,
      confidence: 0.87,
      suggestions: ['View spending breakdown', 'Set expense limits']
    };
  }
  
  return {
    text: "I'm your AI finance assistant! I can help with spending analysis, goal planning, fraud detection, and financial insights. What would you like to know?",
    confidence: 0.9,
    suggestions: ['Check my balance', 'Analyze spending', 'Set new goal']
  };
}

module.exports = router;

// ===== src/utils/blockchain.js =====
const crypto = require('crypto');

function generateBlockchainAddress(email) {
  return '0x' + crypto.createHash('sha256')
    .update(email + Date.now().toString())
    .digest('hex')
    .substring(0, 40);
}

function generateTransactionHash(transactionData) {
  return '0x' + crypto.createHash('sha256')
    .update(JSON.stringify(transactionData) + Date.now().toString())
    .digest('hex')
    .substring(0, 16);
}

function generateGoalHash(goalData) {
  return '0x' + crypto.createHash('sha256')
    .update(JSON.stringify(goalData) + Date.now().toString())
    .digest('hex')
    .substring(0, 16);
}

function verifyHash(data, hash) {
  const computedHash = generateTransactionHash(data);
  return computedHash === hash;
}

module.exports = {
  generateBlockchainAddress,
  generateTransactionHash,
  generateGoalHash,
  verifyHash
};

// ===== src/utils/ai.js =====
const crypto = require('crypto');

function categorizeTransaction(title, note = '') {
  const text = (title + ' ' + note).toLowerCase();
  
  const categories = {
    food: ['food', 'restaurant', 'zomato', 'swiggy', 'grocery', 'cafe', 'dining', 'meal'],
    transport: ['uber', 'ola', 'taxi', 'metro', 'bus', 'fuel', 'cab', 'transport'],
    shopping: ['amazon', 'flipkart', 'mall', 'shop', 'store', 'purchase', 'buy'],
    entertainment: ['netflix', 'movie', 'game', 'music', 'show', 'concert', 'entertainment'],
    health: ['hospital', 'doctor', 'medicine', 'gym', 'pharmacy', 'health'],
    utilities: ['electricity', 'water', 'gas', 'internet', 'phone', 'bill', 'utility'],
    education: ['school', 'college', 'book', 'course', 'tuition', 'education']
  };
  
  for (const [category, keywords] of Object.entries(categories)) {
    const matchedKeywords = keywords.filter(keyword => text.includes(keyword));
    if (matchedKeywords.length > 0) {
      return {
        category,
        confidence: Math.min(0.7 + (matchedKeywords.length * 0.1), 0.95),
        reasoning: `Matched keywords: ${matchedKeywords.join(', ')}`
      };
    }
  }
  
  return {
    category: 'other',
    confidence: 0.5,
    reasoning: 'No specific keywords detected'
  };
}

function detectFraud(title, amount, note = '') {
  const text = (title + ' ' + note).toLowerCase();
  
  const fraudKeywords = [
    'congratulations', 'won', 'lottery', 'prize', 'urgent', 'click',
    'verify account', 'suspended', 'winner', 'claim now'
  ];
  
  let fraudScore = 0;
  const detectedKeywords = [];
  
  fraudKeywords.forEach(keyword => {
    if (text.includes(keyword)) {
      fraudScore += 0.2;
      detectedKeywords.push(keyword);
    }
  });
  
  // Check for unusually large amounts
  if (amount > 50000) {
    fraudScore += 0.3;
    detectedKeywords.push('large amount');
  }
  
  // Check for suspicious patterns
  if (text.includes('http') || text.includes('bit.ly')) {
    fraudScore += 0.4;
    detectedKeywords.push('suspicious link');
  }
  
  return {
    isFraud: fraudScore > 0.5,
    confidence: Math.min(fraudScore, 1),
    reason: detectedKeywords.length > 0 ? 
      `Detected: ${detectedKeywords.join(', ')}` : 
      'Transaction appears normal'
  };
}

function generateFinancialInsights(transactions, user) {
  const insights = {
    totalTransactions: transactions.length,
    savingsRate: user.totalIncome > 0 ? 
      Math.round((user.balance / user.totalIncome) * 100) : 0,
    topSpendingCategory: getTopCategory(transactions.filter(t => t.type === 'expense')),
    monthlyAverage: calculateMonthlyAverage(transactions),
    trends: calculateTrends(transactions),
    recommendations: generateRecommendations(transactions, user)
  };
  
  return insights;
}

function getTopCategory(expenses) {
  const categoryTotals = {};
  expenses.forEach(expense => {
    categoryTotals[expense.category] = (categoryTotals[expense.category] || 0) + Math.abs(expense.amount);
  });
  
  return Object.keys(categoryTotals).reduce((a, b) => 
    categoryTotals[a] > categoryTotals[b] ? a : b, 'other');
}

function calculateMonthlyAverage(transactions) {
  if (transactions.length === 0) return 0;
  
  const expenses = transactions.filter(t => t.type === 'expense');
  const totalExpenses = expenses.reduce((sum, t) => sum + Math.abs(t.amount), 0);
  
  return Math.round(totalExpenses / Math.max(1, getMonthsCount(transactions)));
}

function getMonthsCount(transactions) {
  if (transactions.length === 0) return 1;
  
  const oldest = new Date(Math.min(...transactions.map(t => new Date(t.date))));
  const newest = new Date(Math.max(...transactions.map(t => new Date(t.date))));
  
  return Math.max(1, Math.ceil((newest - oldest) / (30 * 24 * 60 * 60 * 1000)));
}

function calculateTrends(transactions) {
  // Simplified trend calculation
  const currentMonth = transactions.filter(t => {
    const date = new Date(t.date);
    const now = new Date();
    return date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
  });
  
  const lastMonth = transactions.filter(t => {
    const date = new Date(t.date);
    const now = new Date();
    const lastMonthDate = new Date(now.getFullYear(), now.getMonth() - 1);
    return date.getMonth() === lastMonthDate.getMonth() && date.getFullYear() === lastMonthDate.getFullYear();
  });
  
  const currentExpenses = currentMonth.filter(t => t.type === 'expense').reduce((sum, t) => sum + Math.abs(t.amount), 0);
  const lastExpenses = lastMonth.filter(t => t.type === 'expense').reduce((sum, t) => sum + Math.abs(t.amount), 0);
  
  return {
    expenseChange: lastExpenses > 0 ? Math.round(((currentExpenses - lastExpenses) / lastExpenses) * 100) : 0,
    direction: currentExpenses > lastExpenses ? 'increasing' : 'decreasing'
  };
}

function generateRecommendations(transactions, user) {
  const recommendations = [];
  
  // Savings recommendation
  if (user.balance < user.totalIncome * 0.2) {
    recommendations.push({
      type: 'savings',
      priority: 'high',
      message: 'Increase your savings rate to at least 20% of income',
      action: 'Set up automatic savings'
    });
  }
  
  // Spending recommendation
  const topCategory = getTopCategory(transactions.filter(t => t.type === 'expense'));
  if (topCategory === 'food') {
    recommendations.push({
      type: 'spending',
      priority: 'medium', 
      message: 'Food expenses are your top category. Consider meal planning',
      action: 'Track food spending for one week'
    });
  }
  
  return recommendations;
}

function optimizeGoal(targetAmount, frequency, userId) {
  // AI goal optimization logic
  const monthlyOptimal = Math.round(targetAmount * 0.1); // 10% per month suggestion
  const confidence = 0.85;
  
  return {
    suggestedAmount: monthlyOptimal,
    optimizedDate: new Date(Date.now() + (10 * 30 * 24 * 60 * 60 * 1000)), // 10 months
    confidence: confidence,
    reasoning: `Based on average savings patterns, ₹${monthlyOptimal}/month is optimal`
  };
}

function detectSpendingPatterns(transactions) {
  const patterns = {
    weekdaySpending: {},
    categoryTrends: {},
    timeOfDay: {},
    anomalies: []
  };
  
  transactions.forEach(transaction => {
    const date = new Date(transaction.date);
    const weekday = date.toLocaleDateString('en', { weekday: 'long' });
    const hour = date.getHours();
    
    // Weekday patterns
    patterns.weekdaySpending[weekday] = (patterns.weekdaySpending[weekday] || 0) + Math.abs(transaction.amount);
    
    // Time patterns
    const timeSlot = hour < 12 ? 'morning' : hour < 18 ? 'afternoon' : 'evening';
    patterns.timeOfDay[timeSlot] = (patterns.timeOfDay[timeSlot] || 0) + Math.abs(transaction.amount);
    
    // Category trends
    patterns.categoryTrends[transaction.category] = (patterns.categoryTrends[transaction.category] || 0) + Math.abs(transaction.amount);
  });
  
  return patterns;
}

function generateSavingsSuggestions(transactions, user) {
  const suggestions = [];
  
  // Analyze spending categories
  const categories = {};
  transactions.filter(t => t.type === 'expense').forEach(t => {
    categories[t.category] = (categories[t.category] || 0) + Math.abs(t.amount);
  });
  
  // Find top spending categories
  const sortedCategories = Object.entries(categories).sort(([,a], [,b]) => b - a);
  
  if (sortedCategories.length > 0) {
    const [topCategory, amount] = sortedCategories[0];
    suggestions.push({
      category: topCategory,
      currentSpending: amount,
      suggestedReduction: Math.round(amount * 0.1), // 10% reduction
      potentialSavings: Math.round(amount * 0.1 * 12), // Annual savings
      tips: getCategoryTips(topCategory)
    });
  }
  
  return suggestions;
}

function getCategoryTips(category) {
  const tips = {
    food: ['Cook at home 3 times a week', 'Use grocery coupons', 'Plan weekly meals'],
    transport: ['Use public transport', 'Carpool when possible', 'Walk for short distances'],
    shopping: ['Make shopping lists', 'Compare prices online', 'Wait 24h before buying'],
    entertainment: ['Use streaming services efficiently', 'Look for free events', 'Set entertainment budget'],
    default: ['Track expenses daily', 'Set category budgets', 'Review spending weekly']
  };
  
  return tips[category] || tips.default;
}

module.exports = {
  categorizeTransaction,
  detectFraud,
  generateFinancialInsights,
  detectSpendingPatterns,
  generateSavingsSuggestions,
  optimizeGoal
};

// ===== src/middleware/auth.js =====
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'budgle-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

module.exports = { authenticateToken };

// ===== src/routes/blockchain.js =====
const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { generateTransactionHash, verifyHash } = require('../utils/blockchain');
const Transaction = require('../models/Transaction');

const router = express.Router();

// Verify transaction on blockchain
router.post('/verify', authenticateToken, async (req, res) => {
  try {
    const { transactionId } = req.body;
    
    const transaction = await Transaction.findById(transactionId);
    if (!transaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }
    
    const isValid = verifyHash({
      userId: transaction.userId,
      title: transaction.title,
      amount: transaction.amount,
      category: transaction.category,
      date: transaction.date
    }, transaction.blockchainHash);
    
    res.json({
      valid: isValid,
      hash: transaction.blockchainHash,
      timestamp: transaction.createdAt
    });
  } catch (error) {
    res.status(500).json({ message: 'Verification failed', error: error.message });
  }
});

// Get blockchain status
router.get('/status', authenticateToken, async (req, res) => {
  try {
    const totalTransactions = await Transaction.countDocuments({ userId: req.user.userId });
    const verifiedTransactions = await Transaction.countDocuments({ 
      userId: req.user.userId,
      blockchainHash: { $exists: true }
    });
    
    res.json({
      totalTransactions,
      verifiedTransactions,
      integrity: Math.round((verifiedTransactions / Math.max(1, totalTransactions)) * 100),
      networkStatus: 'online'
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to get blockchain status', error: error.message });
  }
});

module.exports = router;

// ===== src/routes/users.js =====
const express = require('express');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch profile', error: error.message });
  }
});

// Update user profile
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName, mobile, aiPreferences, settings } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (fullName) user.fullName = fullName;
    if (mobile) user.mobile = mobile;
    if (aiPreferences) user.aiPreferences = { ...user.aiPreferences, ...aiPreferences };
    if (settings) user.settings = { ...user.settings, ...settings };
    
    await user.save();
    
    res.json({
      message: 'Profile updated successfully',
      user: await User.findById(req.user.userId).select('-password')
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update profile', error: error.message });
  }
});

// Redeem karma tokens
router.post('/redeem', authenticateToken, async (req, res) => {
  try {
    const { tokens, rewardType } = req.body;
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    if (user.karmaTokens < tokens) {
      return res.status(400).json({ message: 'Insufficient karma tokens' });
    }
    
    user.karmaTokens -= tokens;
    await user.save();
    
    // Generate reward (mock)
    const rewards = {
      'amazon_500': 'Amazon ₹500 voucher code: AMZ-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
      'zomato_200': 'Zomato ₹200 off code: ZOM-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
      'charity_100': 'Donated ₹' + (tokens * 0.5) + ' to charity. Impact verified on blockchain.'
    };
    
    res.json({
      message: 'Tokens redeemed successfully',
      reward: rewards[rewardType] || 'Generic reward redeemed',
      remainingTokens: user.karmaTokens
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to redeem tokens', error: error.message });
  }
});

module.exports = router;

// ===== src/routes/alerts.js =====
const express = require('express');
const Alert = require('../models/Alert');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Get all alerts
router.get('/', authenticateToken, async (req, res) => {
  try {
    const alerts = await Alert.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch alerts', error: error.message });
  }
});

// Create alert
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { type, category, title, message, metadata } = req.body;
    
    const alert = new Alert({
      userId: req.user.userId,
      type,
      category,
      title,
      message,
      metadata
    });
    
    await alert.save();
    
    res.status(201).json({
      message: 'Alert created successfully',
      alert
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to create alert', error: error.message });
  }
});

// Mark alert as read
router.put('/:alertId/read', authenticateToken, async (req, res) => {
  try {
    const alert = await Alert.findOneAndUpdate(
      { _id: req.params.alertId, userId: req.user.userId },
      { read: true },
      { new: true }
    );
    
    if (!alert) {
      return res.status(404).json({ message: 'Alert not found' });
    }
    
    res.json({
      message: 'Alert marked as read',
      alert
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update alert', error: error.message });
  }
});

module.exports = router;

// ===== src/seed.js - Database Seeder =====
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const Transaction = require('./models/Transaction');
const Goal = require('./models/Goal');
const Alert = require('./models/Alert');
const { generateBlockchainAddress, generateTransactionHash } = require('./utils/blockchain');

require('dotenv').config();

async function seedDatabase() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/budgle');
    console.log('Connected to MongoDB');

    // Clear existing data
    await User.deleteMany({});
    await Transaction.deleteMany({});
    await Goal.deleteMany({});
    await Alert.deleteMany({});
    console.log('Cleared existing data');

    // Create demo user
    const hashedPassword = await bcrypt.hash('password123', 12);
    const user = await User.create({
      fullName: 'Jane Doe',
      email: 'jane@example.com',
      mobile: '+91 98765 43210',
      password: hashedPassword,
      balance: 26500,
      totalIncome: 45000,
      totalExpenses: 18500,
      karmaTokens: 1250,
      blockchainAddress: generateBlockchainAddress('jane@example.com')
    });

    // Create sample transactions
    const transactions = [
      {
        userId: user._id,
        title: 'Groceries at FreshMart',
        amount: -1350,
        category: 'food',
        type: 'expense',
        date: new Date('2024-05-15'),
        blockchainHash: generateTransactionHash({title: 'Groceries at FreshMart', amount: 1350})
      },
      {
        userId: user._id,
        title: 'New Shirt at FashionHub',
        amount: -900,
        category: 'shopping',
        type: 'expense',
        date: new Date('2024-05-14'),
        blockchainHash: generateTransactionHash({title: 'New Shirt at FashionHub', amount: 900})
      },
      {
        userId: user._id,
        title: 'Project Payment - Acme Corp',
        amount: 15000,
        category: 'income',
        type: 'income',
        date: new Date('2024-05-13'),
        blockchainHash: generateTransactionHash({title: 'Project Payment - Acme Corp', amount: 15000})
      },
      {
        userId: user._id,
        title: 'Cab ride to Airport',
        amount: -450,
        category: 'transport',
        type: 'expense',
        date: new Date('2024-05-12'),
        blockchainHash: generateTransactionHash({title: 'Cab ride to Airport', amount: 450})
      },
      {
        userId: user._id,
        title: 'Electricity Bill',
        amount: -1200,
        category: 'utilities',
        type: 'expense',
        date: new Date('2024-05-11'),
        blockchainHash: generateTransactionHash({title: 'Electricity Bill', amount: 1200})
      }
    ];

    await Transaction.insertMany(transactions);

    // Create sample goals
    const goals = [
      {
        userId: user._id,
        name: 'Dream Vacation Fund',
        targetAmount: 150000,
        currentAmount: 35000,
        frequency: 'monthly',
        status: 'active'
      },
      {
        userId: user._id,
        name: 'New Gadget',
        targetAmount: 50000,
        currentAmount: 40000,
        frequency: 'weekly',
        status: 'active'
      },
      {
        userId: user._id,
        name: 'Emergency Savings',
        targetAmount: 250000,
        currentAmount: 200000,
        frequency: 'yearly',
        status: 'active'
      }
    ];

    await Goal.insertMany(goals);

    // Create sample alerts
    const alerts = [
      {
        userId: user._id,
        type: 'normal',
        category: 'system',
        title: 'Electricity Bill Due',
        message: 'Your Electricity bill of ₹1,200 is due on May 15. Tap here to avoid late fees.'
      },
      {
        userId: user._id,
        type: 'warning',
        category: 'spending',
        title: 'Shopping Alert',
        message: 'Your spending on shopping has exceeded by 20% this week. Review your spending habits.'
      },
      {
        userId: user._id,
        type: 'danger',
        category: 'fraud',
        title: '🚨 Fraud Detected',
        message: 'Suspicious SMS blocked: "Congratulations! You won ₹50,000..." - AI prevented potential scam'
      }
    ];

    await Alert.insertMany(alerts);

    console.log('✅ Database seeded successfully!');
    console.log('Demo user created:');
    console.log('Email: jane@example.com');
    console.log('Password: password123');
    console.log('Blockchain Address:', user.blockchainAddress);

  } catch (error) {
    console.error('❌ Seeding failed:', error);
  } finally {
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB');
  }
}

// Run seeder if called directly
if (require.main === module) {
  seedDatabase();
}

module.exports = seedDatabase;

// ===== .env.example =====
/*
NODE_ENV=development
PORT=4000
MONGO_URI=mongodb://mongo:27017/budgle
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
*/

// ===== Dockerfile =====
/*
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src/ ./src/

EXPOSE 4000

CMD ["npm", "start"]
*/
