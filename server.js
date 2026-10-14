const express = require('express');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, 'noor.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_type TEXT NOT NULL CHECK(item_type IN ('quran','hadith','adhkar')),
    item_id TEXT NOT NULL,
    title TEXT NOT NULL,
    text TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, item_type, item_id)
  );
`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.urlencoded({ extended: false, limit: '30kb' }));
app.use(session({
  name: 'noor.sid',
  secret: process.env.SESSION_SECRET || 'change-this-secret-before-deployment',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'يجب تسجيل الدخول أولًا.' });
  next();
}
function validEmail(email) { return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }

app.get('/api/health', (req, res) => res.json({ status: 'ok', service: 'Noor API' }));
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, email, created_at FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user: user || null });
});
app.post('/api/auth/register', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = req.body.password;
  if (!validEmail(email)) return res.status(400).json({ error: 'أدخل بريدًا إلكترونيًا صحيحًا.' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون من ٨ أحرف على الأقل.' });
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);
    req.session.userId = Number(result.lastInsertRowid);
    res.status(201).json({ user: { id: Number(result.lastInsertRowid), email } });
  } catch (error) {
    if (String(error.code).includes('SQLITE_CONSTRAINT_UNIQUE')) return res.status(409).json({ error: 'هذا البريد مسجل بالفعل.' });
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب.' });
  }
});
app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = req.body.password;
  if (!validEmail(email) || typeof password !== 'string') return res.status(400).json({ error: 'تحقق من البريد الإلكتروني وكلمة المرور.' });
  const user = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة.' });
  req.session.userId = user.id;
  res.json({ user: { id: user.id, email: user.email } });
});
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('noor.sid', { httpOnly: true, sameSite: 'lax' });
    res.json({ success: true });
  });
});
app.get('/api/favorites', requireUser, (req, res) => {
  const rows = db.prepare('SELECT id, item_type AS type, item_id AS itemId, title, text, source, created_at AS createdAt FROM favorites WHERE user_id = ? ORDER BY id DESC').all(req.session.userId);
  res.json({ favorites: rows });
});
app.post('/api/favorites', requireUser, (req, res) => {
  const { type, itemId, title, text, source } = req.body || {};
  if (!['quran', 'hadith', 'adhkar'].includes(type) || ![itemId, title, text, source].every(value => typeof value === 'string' && value.trim() && value.length <= 5000)) {
    return res.status(400).json({ error: 'بيانات العنصر غير مكتملة أو غير صحيحة.' });
  }
  try {
    db.prepare('INSERT INTO favorites (user_id, item_type, item_id, title, text, source) VALUES (?, ?, ?, ?, ?, ?)').run(req.session.userId, type, itemId, title, text, source);
    res.status(201).json({ success: true });
  } catch (error) {
    if (String(error.code).includes('SQLITE_CONSTRAINT_UNIQUE')) return res.status(409).json({ error: 'العنصر موجود بالفعل في المفضلة.' });
    res.status(500).json({ error: 'تعذر حفظ العنصر.' });
  }
});
app.delete('/api/favorites/:id', requireUser, (req, res) => {
  const result = db.prepare('DELETE FROM favorites WHERE id = ? AND user_id = ?').run(Number(req.params.id), req.session.userId);
  if (!result.changes) return res.status(404).json({ error: 'العنصر غير موجود.' });
  res.json({ success: true });
});
app.get('/api/library/status', (req, res) => res.json({ status: 'starter', note: 'مكتبة المحتوى الكاملة غير مضافة بعد. يجب استيراد نصوص موثقة من مصادر موثوقة ومراجعتها قبل النشر.' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Noor is running at http://localhost:${PORT}`));
