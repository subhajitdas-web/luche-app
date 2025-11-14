const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'luche-secret-2025';

// === STATIC USER ===
const USER = {
  email: 'subhajitdas@gmail.com',
  passwordHash: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' // bcrypt hash of "admin123"
};

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// === API ROUTES ===

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  if (email.toLowerCase() !== USER.email) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, USER.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ email: USER.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email || email.toLowerCase().trim() !== USER.email) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Your original password generation logic
  let hash = 0;
  const e = email.toLowerCase().trim();
  for (let i = 0; i < e.length; i++) {
    hash = e.charCodeAt(i) + ((hash << 5) - hash);
  }
  hash = Math.abs(hash);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let pwd = '';
  for (let i = 0; i < 8; i++) {
    pwd += chars.charAt(hash % chars.length);
    hash = (hash * 31) % 2147483647;
  }
  const newPassword = pwd.match(/.{1,4}/g).join('');

  // Update hash
  USER.passwordHash = await bcrypt.hash(newPassword, 10);
  res.json({ newPassword });
});

// Verify Token
app.get('/api/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    jwt.verify(token, JWT_SECRET);
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// === ROUTES FOR HTML PAGES ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'signin.html'));
});

app.get('/reset-password.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'reset-password.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'dashboard.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'signin.html'));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Open: http://localhost:${PORT}`);
});