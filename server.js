const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// ====== MONGODB ======
// MONGODB_URI में अपना password डालो
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mkadmin:dsssb1234@cluster0.w7s9b7z.mongodb.net/mkglobalnexus?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB connected');
    await createDefaultAdmin();
  })
  .catch(err => console.error('❌ MongoDB error:', err.message));

// ====== MODELS ======
const Admin = mongoose.model('Admin', new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}));

const Report = mongoose.model('Report', new mongoose.Schema({
  case_id: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  mobile: { type: String, required: true },
  email: { type: String, required: true },
  case_title: { type: String, required: true },
  details: { type: String, required: true },
  status: { type: String, enum: ['Pending','Investigating','Closed'], default: 'Pending' },
  notes: { type: String, default: '' },
  ip_address: { type: String, default: '' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}));

async function createDefaultAdmin() {
  const exists = await Admin.findOne({ username: 'admin' });
  if (!exists) {
    const hash = await bcrypt.hash('admin123', 10);
    await Admin.create({ username: 'admin', password: hash });
    console.log('✅ Admin created: admin / admin123');
  }
}

// ====== MIDDLEWARE ======
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'mkglobalnexus_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

function generateCaseId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let id = 'MKNX-';
  for (let i = 0; i < 6; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}

// ====== ROUTES ======

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', platform: 'MK Global Nexus', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

app.post('/api/submit', async (req, res) => {
  try {
    const { name, mobile, email, case_title, details } = req.body;
    if (!name || !mobile || !email || !case_title || !details) {
      return res.status(400).json({ error: 'All fields required' });
    }
    const case_id = generateCaseId();
    await Report.create({ case_id, name, mobile, email, case_title, details, ip_address: req.ip || '' });
    res.json({ success: true, case_id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin || !await bcrypt.compare(password, admin.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.adminId = admin._id;
    req.session.adminUsername = admin.username;
    res.json({ success: true, username: admin.username });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/admin/me', requireAuth, (req, res) => {
  res.json({ username: req.session.adminUsername });
});

app.get('/api/admin/reports', requireAuth, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = {};
    if (status && status !== 'all') query.status = status;
    if (search) query.$or = [
      { name: { $regex: search, $options: 'i' } },
      { case_title: { $regex: search, $options: 'i' } },
      { case_id: { $regex: search, $options: 'i' } }
    ];
    const reports = await Report.find(query).sort({ created_at: -1 });
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/stats', requireAuth, async (req, res) => {
  try {
    const total = await Report.countDocuments();
    const pending = await Report.countDocuments({ status: 'Pending' });
    const investigating = await Report.countDocuments({ status: 'Investigating' });
    const closed = await Report.countDocuments({ status: 'Closed' });
    res.json({ total, pending, investigating, closed });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/admin/reports/:case_id', requireAuth, async (req, res) => {
  try {
    const { status, notes } = req.body;
    const report = await Report.findOneAndUpdate(
      { case_id: req.params.case_id },
      { status, notes, updated_at: new Date() },
      { new: true }
    );
    if (!report) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, report });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/reports/:case_id', requireAuth, async (req, res) => {
  try {
    const result = await Report.findOneAndDelete({ case_id: req.params.case_id });
    if (!result) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`🚀 MK Global Nexus running on port ${PORT}`));
