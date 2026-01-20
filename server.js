const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'pomodoro-secret-key-change-in-production';
const TEACHER_PASSWORD = 'SBiscool1!';

let db;

// Initialize database
async function initDatabase() {
  const SQL = await initSqlJs();
  
  // Try to load existing database
  const dbPath = path.join(__dirname, 'pomodoro.db');
  if (fs.existsSync(dbPath)) {
    const buffer = fs.readFileSync(dbPath);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'student',
      agreed_to_terms INTEGER DEFAULT 0,
      agreed_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS screenshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      image_data TEXT,
      url TEXT,
      title TEXT,
      captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  
  saveDatabase();
  console.log('Database initialized');
}

// Save database to file
function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(path.join(__dirname, 'pomodoro.db'), buffer);
}

// Helper functions for sql.js
function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDatabase();
  return { lastInsertRowid: db.exec("SELECT last_insert_rowid()")[0]?.values[0]?.[0] };
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static('uploads'));

// Configure multer for screenshot uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(__dirname, 'uploads', req.userId.toString());
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `screenshot_${timestamp}.png`);
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    req.isTeacher = decoded.isTeacher || false;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Teacher-only middleware
function teacherOnly(req, res, next) {
  if (req.userRole !== 'teacher' && !req.isTeacher) {
    return res.status(403).json({ error: 'Teachers only' });
  }
  next();
}

// ============ AUTH ROUTES ============

// Register new student
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const existing = dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = dbRun(
      'INSERT INTO users (name, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)',
      [name, email, hashedPassword, 'student', new Date().toISOString()]
    );
    
    res.json({ success: true, userId: result.lastInsertRowid });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Student Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    // Store session
    dbRun('INSERT INTO sessions (user_id, token, created_at) VALUES (?, ?, ?)', 
      [user.id, token, new Date().toISOString()]);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        agreedToTerms: user.agreed_to_terms === 1
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Teacher Login (password only)
app.post('/api/teacher-login', (req, res) => {
  try {
    const { password } = req.body;
    
    if (password !== TEACHER_PASSWORD) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    
    const token = jwt.sign(
      { role: 'teacher', isTeacher: true },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      user: {
        name: 'Teacher',
        role: 'teacher'
      }
    });
  } catch (error) {
    console.error('Teacher login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/me', authMiddleware, (req, res) => {
  if (req.isTeacher) {
    return res.json({ name: 'Teacher', role: 'teacher', agreedToTerms: true });
  }
  
  const user = dbGet('SELECT id, name, email, role, agreed_to_terms, agreed_at FROM users WHERE id = ?', [req.userId]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({
    ...user,
    agreedToTerms: user.agreed_to_terms === 1
  });
});

// Accept terms/agreement
app.post('/api/accept-terms', authMiddleware, (req, res) => {
  dbRun('UPDATE users SET agreed_to_terms = 1, agreed_at = ? WHERE id = ?',
    [new Date().toISOString(), req.userId]
  );
  res.json({ success: true });
});

// ============ SCREENSHOT ROUTES ============

// Upload screenshot (from extension)
app.post('/api/screenshots', authMiddleware, upload.single('screenshot'), (req, res) => {
  try {
    const { url, title } = req.body;
    const filename = req.file.filename;
    
    dbRun(
      'INSERT INTO screenshots (user_id, filename, url, title, captured_at) VALUES (?, ?, ?, ?, ?)',
      [req.userId, filename, url || '', title || '', new Date().toISOString()]
    );
    
    res.json({ success: true, filename });
  } catch (error) {
    console.error('Screenshot upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get student's own screenshots
app.get('/api/my-screenshots', authMiddleware, (req, res) => {
  const screenshots = dbAll(`
    SELECT id, filename, url, title, captured_at 
    FROM screenshots 
    WHERE user_id = ? 
    ORDER BY captured_at DESC
    LIMIT 100
  `, [req.userId]);
  
  res.json(screenshots.map(s => ({
    ...s,
    imageUrl: `/uploads/${req.userId}/${s.filename}`
  })));
});

// ============ TEACHER/ADMIN ROUTES ============

// Get all students
app.get('/api/admin/students', authMiddleware, teacherOnly, (req, res) => {
  const students = dbAll(`
    SELECT id, name, email, agreed_to_terms, agreed_at, created_at
    FROM users
    WHERE role = 'student'
    ORDER BY name
  `);
  
  // Get screenshot counts separately
  const result = students.map(student => {
    const countResult = dbGet('SELECT COUNT(*) as count FROM screenshots WHERE user_id = ?', [student.id]);
    const lastResult = dbGet('SELECT captured_at FROM screenshots WHERE user_id = ? ORDER BY captured_at DESC LIMIT 1', [student.id]);
    
    return {
      ...student,
      screenshot_count: countResult?.count || 0,
      last_screenshot: lastResult?.captured_at || null
    };
  });
  
  res.json(result);
});

// Get specific student's screenshots
app.get('/api/admin/students/:studentId/screenshots', authMiddleware, teacherOnly, (req, res) => {
  const { studentId } = req.params;
  
  const screenshots = dbAll(`
    SELECT id, filename, url, title, captured_at 
    FROM screenshots 
    WHERE user_id = ?
    ORDER BY captured_at DESC 
    LIMIT 200
  `, [studentId]);
  
  res.json(screenshots.map(s => ({
    ...s,
    imageUrl: `/uploads/${studentId}/${s.filename}`
  })));
});

// Get student details
app.get('/api/admin/students/:studentId', authMiddleware, teacherOnly, (req, res) => {
  const { studentId } = req.params;
  
  const student = dbGet(`
    SELECT id, name, email, agreed_to_terms, agreed_at, created_at
    FROM users WHERE id = ? AND role = 'student'
  `, [studentId]);
  
  if (!student) {
    return res.status(404).json({ error: 'Student not found' });
  }
  
  res.json(student);
});

// ============ SERVE FRONTEND ============

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
async function start() {
  await initDatabase();
  app.listen(PORT, () => {
    console.log(`🍅 Pomodoro Monitoring Server running on http://localhost:${PORT}`);
    console.log(`   Teacher password: ${TEACHER_PASSWORD}`);
  });
}

start();
