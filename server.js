const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;

// ===== MONGODB =====
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB connected');
    await createDefaultAdmin();
  })
  .catch(err => console.error('❌ MongoDB error:', err.message));

// ===== MODELS =====
const Admin = mongoose.model('Admin', new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}));

const Report = mongoose.model('Report', new mongoose.Schema({
  case_id: { type: String, unique: true, required: true },
  name: String,
  mobile: String,
  email: String,
  case_title: String,
  case_details: String,
  created_at: { type: Date, default: Date.now }
}));

// ===== DEFAULT ADMIN =====
async function createDefaultAdmin() {
  const exists = await Admin.findOne({ username: 'admin' });
  if (!exists) {
    const hash = await bcrypt.hash('admin123', 10);
    await Admin.create({ username: 'admin', password: hash });
    console.log('✅ Admin created: admin / admin123');
  }
}

// ===== MIDDLEWARE =====
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'mkglobal_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// ===== STATIC FILES =====
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ===== UTIL =====
function generateCaseId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let id = 'MK-';
  for (let i = 0; i < 6; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// ===== REPORT API =====
app.post('/report', async (req, res) => {
  try {
    const data = req.body;

    const newReport = new Report({
      case_id: generateCaseId(),
      name: data.name,
      mobile: data.mobile,
      email: data.email,
      case_title: data.case_title,
      case_details: data.case_details
    });

    await newReport.save();

    res.json({ success: true, message: 'Case submitted successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ADMIN LOGIN =====
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  const admin = await Admin.findOne({ username });
  if (!admin) return res.status(401).json({ error: 'Invalid user' });

  const match = await bcrypt.compare(password, admin.password);
  if (!match) return res.status(401).json({ error: 'Wrong password' });

  req.session.adminId = admin._id;
  res.json({ success: true });
});

// ===== AUTH MIDDLEWARE =====
function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// ===== GET REPORTS =====
app.get('/admin/reports', requireAuth, async (req, res) => {
  const reports = await Report.find().sort({ created_at: -1 });
  res.json(reports);
});

// ===== SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 MK Global Nexus running on port ${PORT}`);
});