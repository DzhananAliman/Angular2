
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';
import fs from 'fs';

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret_dev_key_change_me';
const DB_FILE = './db.json';

const app = express();
app.use(cors());
app.use(express.json());

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const seed = { users: [], posts: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(seed, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

function canModifyPost(userId, post) {
  return post.authorId === userId;
}

app.get('/', (req, res) => res.json({ ok: true, service: 'minimal-blog-backend' }));

// Auth
app.post('/auth/register', async (req, res) => {
  const { email, password, username } = req.body || {};
  if (!email || !password || !username) {
    return res.status(400).json({ message: 'email, password, username required' });
  }
  const db = loadDB();
  if (db.users.find(u => u.email === email)) {
    return res.status(409).json({ message: 'Email already registered' });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: nanoid(), email, username, passwordHash, createdAt: Date.now() };
  db.users.push(user);
  saveDB(db);
  const token = jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: { id: user.id, email, username } });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'email and password required' });
  const db = loadDB();
  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email, username: user.username } });
});

app.get('/auth/profile', authMiddleware, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const myPosts = db.posts.filter(p => p.authorId === user.id);
  res.json({ id: user.id, email: user.email, username: user.username, myPosts });
});

// Posts CRUD
app.get('/posts', (req, res) => {
  const db = loadDB();
  // newest first
  const posts = [...db.posts].sort((a, b) => b.createdAt - a.createdAt);
  res.json(posts);
});

app.get('/posts/:id', (req, res) => {
  const db = loadDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Post not found' });
  res.json(post);
});

app.post('/posts', authMiddleware, (req, res) => {
  const { title, content } = req.body || {};
  if (!title || !content) return res.status(400).json({ message: 'title and content required' });
  const db = loadDB();
  const post = {
    id: nanoid(),
    title,
    content,
    authorId: req.user.id,
    authorName: req.user.username,
    createdAt: Date.now(),
    likes: [],
    comments: []
  };
  db.posts.push(post);
  saveDB(db);
  res.status(201).json(post);
});

app.put('/posts/:id', authMiddleware, (req, res) => {
  const db = loadDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Post not found' });
  if (!canModifyPost(req.user.id, post)) return res.status(403).json({ message: 'Forbidden' });
  const { title, content } = req.body || {};
  if (title) post.title = title;
  if (content) post.content = content;
  saveDB(db);
  res.json(post);
});

app.delete('/posts/:id', authMiddleware, (req, res) => {
  const db = loadDB();
  const idx = db.posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: 'Post not found' });
  if (!canModifyPost(req.user.id, db.posts[idx])) return res.status(403).json({ message: 'Forbidden' });
  const removed = db.posts.splice(idx, 1)[0];
  saveDB(db);
  res.json(removed);
});

app.post('/posts/:id/like', authMiddleware, (req, res) => {
  const db = loadDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Post not found' });
  const liked = post.likes.includes(req.user.id);
  if (liked) {
    post.likes = post.likes.filter(u => u !== req.user.id);
  } else {
    post.likes.push(req.user.id);
  }
  saveDB(db);
  res.json({ likes: post.likes.length, liked: !liked });
});

app.post('/posts/:id/comments', authMiddleware, (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ message: 'text required' });
  const db = loadDB();
  const post = db.posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ message: 'Post not found' });
  const comment = { id: nanoid(), userId: req.user.id, username: req.user.username, text, createdAt: Date.now() };
  post.comments.push(comment);
  saveDB(db);
  res.status(201).json(comment);
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
