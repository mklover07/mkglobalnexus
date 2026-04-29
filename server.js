const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// ====== MONGODB ======
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not set!');
  process.exit(1);
}

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB connected successfully!');
    await createDefaultAdmin();
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
  });

// ====== MODELS ======
const adminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const reportSchema = new mongoose.Schema({
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
});

const Admin = mongoose.model('Admin', adminSchema);
const Report = mongoose.model('Report', reportSchema);

// ====== DEFAULT ADMIN ======
async function createDefaultAdmin() {
  try {
    const exists = await Admin.findOne({ username: 'admin' });
    if (!exists) {
      const hash = await bcrypt.hash('admin123', 10);
      await Admin.create({ username: 'admin', password: hash });
      console.log('✅ Admin created: admin / admin123');
    } else {
      console.log('✅ Admin already exists');
    }
  } catch (err) {
    console.error('Admin error:', err.message);
  }
}

// ====== MIDDLEWARE ======
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'mkglobalnexus_secret_key_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ====== AUTH CHECK ======
function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// ====== CASE ID ======
function generateCaseId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let id = 'MKNX-';
  for (let i = 0; i < 6; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}

// ====== ROUTES ======

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    platform: 'MK Global Nexus',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    time: new Date()
  });
});

// Submit fraud report
app.post('/api/submit', async (req, res) => {
  try {
    const { name, mobile, email, case_title, details } = req.body;

    if (!name || !mobile || !email || !case_title || !details) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const case_id = generateCaseId();

    await Report.create({
      case_id,
      name: name.trim(),
      mobile: mobile.trim(),
      email: email.trim().toLowerCase(),
      case_title: case_title.trim(),
      details: details.trim(),
      ip_address: req.ip || ''
    });

    console.log(`✅ New report: ${case_id} from ${name}`);
    res.json({ success: true, case_id, message: 'Report submitted successfully' });

  } catch (err) {
    console.error('Submit error:', err.message);
    res.status(500).json({ error: 'Failed to submit report. Please try again.' });
  }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields required' });

    const admin = await Admin.findOne({ username: username.trim() });
    if (!admin) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, admin.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    req.session.adminId = admin._id.toString();
    req.session.adminUsername = admin.username;
    res.json({ success: true, username: admin.username });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin logout
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Check auth status
app.get('/api/admin/me', requireAuth, (req, res) => {
  res.json({ username: req.session.adminUsername });
});

// Get all reports
app.get('/api/admin/reports', requireAuth, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = {};

    if (status && status !== 'all') query.status = status;
    if (search && search.trim()) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { case_title: { $regex: search, $options: 'i' } },
        { case_id: { $regex: search, $options: 'i' } },
        { mobile: { $regex: search, $options: 'i' } }
      ];
    }

    const reports = await Report.find(query).sort({ created_at: -1 }).lean();
    res.json(reports);

  } catch (err) {
    console.error('Reports error:', err.message);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Get stats
app.get('/api/admin/stats', requireAuth, async (req, res) => {
  try {
    const [total, pending, investigating, closed] = await Promise.all([
      Report.countDocuments(),
      Report.countDocuments({ status: 'Pending' }),
      Report.countDocuments({ status: 'Investigating' }),
      Report.countDocuments({ status: 'Closed' })
    ]);
    res.json({ total, pending, investigating, closed });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Update report status
app.put('/api/admin/reports/:case_id', requireAuth, async (req, res) => {
  try {
    const { status, notes } = req.body;
    const allowed = ['Pending', 'Investigating', 'Closed'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const report = await Report.findOneAndUpdate(
      { case_id: req.params.case_id },
      { status, notes: notes || '', updated_at: new Date() },
      { new: true }
    );
    if (!report) return res.status(404).json({ error: 'Case not found' });
    res.json({ success: true, report });

  } catch (err) {
    res.status(500).json({ error: 'Failed to update' });
  }
});

// Delete report
app.delete('/api/admin/reports/:case_id', requireAuth, async (req, res) => {
  try {
    const result = await Report.findOneAndDelete({ case_id: req.params.case_id });
    if (!result) return res.status(404).json({ error: 'Case not found' });
    res.json({ success: true, message: 'Case deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

// ====== START SERVER ======
app.listen(PORT, () => {
  console.log(`🚀 MK Global Nexus Server running on port ${PORT}`);
});
