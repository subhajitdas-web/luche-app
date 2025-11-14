const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'luche-secret-2025';
const USERS_FILE = path.join(__dirname, 'users.txt');

let users = new Map(); // email → passwordHash

// Load users from file
async function loadUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf-8');
    for (const line of data.trim().split('\n')) {
      if (!line.trim()) continue;
      const [email, hash] = line.split(':');
      if (email && hash) users.set(email.toLowerCase(), hash);
    }
    console.log(`Loaded ${users.size} user(s)`);
  } catch (err) {
    console.log('users.txt not found → starting fresh');
  }
}

// Save user to file
async function saveUser(email, hash) {
  const line = `${email}:${hash}\n`;
  await fs.appendFile(USERS_FILE, line);
  users.set(email.toLowerCase(), hash);
}

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API: Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const normalized = email.toLowerCase().trim();
  const hash = users.get(normalized);

  if (!hash) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, hash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ email: normalized }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// API: Register (called on first login with new email)
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  const normalized = email.toLowerCase().trim();
  if (users.has(normalized)) return res.status(400).json({ error: 'User exists' });

  const hash = await bcrypt.hash(password, 10);
  await saveUser(normalized, hash);
  const token = jwt.sign({ email: normalized }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// API: Reset Password (optional – updates existing user)
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const normalized = email.toLowerCase().trim();
  if (!users.has(normalized)) return res.status(404).json({ error: 'User not found' });

  // Generate same password as your HTML logic
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    hash = normalized.charCodeAt(i) + ((hash << 5) - hash);
  }
  hash = Math.abs(hash);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let pwd = '';
  for (let i = 0; i < 8; i++) {
    pwd += chars.charAt(hash % chars.length);
    hash = (hash * 31) % 2147483647;
  }
  const newPass = pwd.match(/.{1,4}/g).join('');

  const newHash = await bcrypt.hash(newPass, 10);
  users.set(normalized, newHash);

  // Update file
  const allLines = Array.from(users.entries()).map(([e, h]) => `${e}:${h}`).join('\n') + '\n';
  await fs.writeFile(USERS_FILE, allLines);

  res.json({ newPassword: newPass });
});

// API: Verify Token
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

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'signin.html')));
app.get('/reset-password.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'reset-password.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'dashboard.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'subha-developer', 'signin.html')));

// Start
loadUsers().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
});