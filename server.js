const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ====== DATABASE ======
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ====== MIDDLEWARE ======
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'mkglobalnexus_secret_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ====== DB SETUP ======
async function setupDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        case_id VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        mobile VARCHAR(20) NOT NULL,
        email VARCHAR(150) NOT NULL,
        case_title VARCHAR(255) NOT NULL,
        details TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'Pending',
        notes TEXT DEFAULT '',
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Create default admin if not exists
    const adminExists = await pool.query('SELECT id FROM admins WHERE username = $1', ['admin']);
    if (adminExists.rows.length === 0) {
      const hash = await bcrypt.hash('admin123', 10);
      await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['admin', hash]);
      console.log('✅ Default admin created: admin / admin123');
    }

    console.log('✅ Database ready');
  } catch (err) {
    console.error('❌ DB Setup error:', err.message);
  }
}

// ====== AUTH MIDDLEWARE ======
function requireAuth(req, res, next) {
  if (req.session && req.session.adminId) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// ====== GENERATE CASE ID ======
function generateCaseId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = 'MKNX-';
  for (let i = 0; i < 6; i++) result += chars[Math.floor(Math.random() * chars.length)];
  return result;
}

// ====== API ROUTES ======

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', platform: 'MK Global Nexus', time: new Date() });
});

// Submit fraud report
app.post('/api/submit', async (req, res) => {
  try {
    const { name, mobile, email, case_title, details } = req.body;

    // Validate
    if (!name || !mobile || !email || !case_title || !details) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (details.length < 20) {
      return res.status(400).json({ error: 'Case details must be at least 20 characters' });
    }

    const case_id = generateCaseId();
    const ip = req.ip || req.connection.remoteAddress;

    await pool.query(
      `INSERT INTO reports (case_id, name, mobile, email, case_title, details, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [case_id, name.trim(), mobile.trim(), email.trim(), case_title.trim(), details.trim(), ip]
    );

    res.json({ success: true, case_id, message: 'Report submitted successfully' });
  } catch (err) {
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Failed to submit report' });
  }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'All fields required' });

    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const admin = result.rows[0];
    const valid = await bcrypt.compare(password, admin.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    req.session.adminId = admin.id;
    req.session.adminUsername = admin.username;
    res.json({ success: true, username: admin.username });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin logout
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Check auth status
app.get('/api/admin/me', requireAuth, (req, res) => {
  res.json({ username: req.session.adminUsername });
});

// Get all reports
app.get('/api/admin/reports', requireAuth, async (req, res) => {
  try {
    const { status, search } = req.query;
    let query = 'SELECT * FROM reports';
    const params = [];

    if (status && status !== 'all') {
      query += ' WHERE status = $1';
      params.push(status);
    }
    if (search) {
      const searchParam = `%${search}%`;
      if (params.length > 0) {
        query += ` AND (name ILIKE $${params.length + 1} OR case_title ILIKE $${params.length + 1} OR case_id ILIKE $${params.length + 1})`;
      } else {
        query += ' WHERE (name ILIKE $1 OR case_title ILIKE $1 OR case_id ILIKE $1)';
      }
      params.push(searchParam);
    }

    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Get stats
app.get('/api/admin/stats', requireAuth, async (req, res) => {
  try {
    const total = await pool.query('SELECT COUNT(*) FROM reports');
    const pending = await pool.query("SELECT COUNT(*) FROM reports WHERE status = 'Pending'");
    const investigating = await pool.query("SELECT COUNT(*) FROM reports WHERE status = 'Investigating'");
    const closed = await pool.query("SELECT COUNT(*) FROM reports WHERE status = 'Closed'");
    res.json({
      total: parseInt(total.rows[0].count),
      pending: parseInt(pending.rows[0].count),
      investigating: parseInt(investigating.rows[0].count),
      closed: parseInt(closed.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Update report status
app.put('/api/admin/reports/:case_id', requireAuth, async (req, res) => {
  try {
    const { case_id } = req.params;
    const { status, notes } = req.body;
    const allowed = ['Pending', 'Investigating', 'Closed'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const result = await pool.query(
      'UPDATE reports SET status = $1, notes = $2, updated_at = NOW() WHERE case_id = $3 RETURNING *',
      [status, notes || '', case_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Case not found' });
    res.json({ success: true, report: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update report' });
  }
});

// Delete report
app.delete('/api/admin/reports/:case_id', requireAuth, async (req, res) => {
  try {
    const { case_id } = req.params;
    const result = await pool.query('DELETE FROM reports WHERE case_id = $1 RETURNING id', [case_id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Case not found' });
    res.json({ success: true, message: 'Case deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

// ====== START ======
setupDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 MK Global Nexus Server running on port ${PORT}`);
  });
});
