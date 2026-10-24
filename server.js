const express = require('express'), http = require('http'), path = require('path');
const { Server } = require('socket.io'), mongoose = require('mongoose');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser'), cookie = require('cookie');
const helmet = require('helmet'), rateLimit = require('express-rate-limit');

const { MONGODB_URI, JWT_SECRET } = process.env;
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || '').toLowerCase();
if (!MONGODB_URI || !JWT_SECRET || JWT_SECRET.length < 16) { console.error('Set MONGODB_URI and JWT_SECRET (16+ characters).'); process.exit(1); }
const PROD = process.env.NODE_ENV === 'production';
const OId = mongoose.Schema.Types.ObjectId;
const isId = v => typeof v === 'string' && /^[a-f0-9]{24}$/.test(v);
const S = o => new mongoose.Schema(o, { timestamps: true });
const esc = t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim().slice(0, max);
const bad = (s, m, c = 400) => s.status(c).json({ error: m });

/* ---------- models ---------- */
const User = mongoose.model('User', S({
  username: { type: String, unique: true, required: true, match: /^[a-z0-9_]{3,20}$/ },
  displayName: { type: String, required: true, maxlength: 40 },
  email: { type: String, lowercase: true, trim: true, maxlength: 120, unique: true, sparse: true },
  mobile: { type: String, maxlength: 20, default: '' }, bio: { type: String, maxlength: 200, default: '' },
  passwordHash: { type: String, required: true }, role: { type: String, default: 'user' },
  suspended: { type: Boolean, default: false }, tv: { type: Number, default: 0 },
  blocked: [{ type: OId, ref: 'User' }], isPublic: { type: Boolean, default: true }, lastSeen: { type: Date, default: Date.now }
}));
const msgS = S({ convId: { type: String, required: true }, from: { type: OId, required: true }, to: { type: OId, required: true },
  text: { type: String, required: true, maxlength: 2000 }, clientId: { type: String, required: true, maxlength: 64 }, status: { type: Number, default: 0 } });
msgS.index({ from: 1, clientId: 1 }, { unique: true }); msgS.index({ convId: 1, createdAt: -1 }); msgS.index({ to: 1, status: 1 });
const Msg = mongoose.model('Message', msgS);
const Post = mongoose.model('Post', S({ author: { type: OId, ref: 'User', index: true }, text: { type: String, required: true, maxlength: 1000 }, likes: [{ type: OId }] }));
const Comment = mongoose.model('Comment', S({ post: { type: OId, index: true }, author: { type: OId, ref: 'User' }, parent: { type: OId, default: null }, text: { type: String, required: true, maxlength: 500 } }));
const Notif = mongoose.model('Notification', S({ user: { type: OId, index: true }, type: String, from: { type: OId, ref: 'User' }, post: OId, text: String, read: { type: Boolean, default: false } }));
const Report = mongoose.model('Report', S({ by: { type: OId, ref: 'User' }, kind: String, ref: OId, reason: { type: String, maxlength: 300 }, snapshot: { type: String, maxlength: 2000 }, status: { type: String, default: 'open' } }));
const Contact = mongoose.model('Contact', S({ name: String, email: String, subject: String, message: String }));
const Audit = mongoose.model('Audit', S({ admin: { type: OId, ref: 'User' }, action: String, target: String }));

const online = new Map();
const pub = u => ({ id: String(u._id), username: u.username, displayName: u.displayName, bio: u.bio, lastSeen: u.lastSeen, online: online.has(String(u._id)) });
const outMsg = m => ({ id: String(m._id), from: String(m.from), to: String(m.to), text: m.text, clientId: m.clientId, status: m.status, createdAt: m.createdAt });
const convOf = (a, b) => [String(a), String(b)].sort().join(':');

/* ---------- app ---------- */
const app = express(), server = http.createServer(app);
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"], connectSrc: ["'self'", 'ws:', 'wss:'], imgSrc: ["'self'", 'data:'] } } }));
app.use(express.json({ limit: '20kb' })); app.use(cookieParser());
const RL = (ms, n, m) => rateLimit({ windowMs: ms, limit: n, standardHeaders: true, legacyHeaders: false, message: { error: m || 'Too many requests. Try again later.' } });
app.use('/api', RL(60000, 400));
const authLimit = RL(15 * 60000, 25, 'Too many attempts. Try again later.'), writeLimit = RL(10 * 60000, 40), contactLimit = RL(3600e3, 5);
const h = f => (q, s, n) => Promise.resolve(f(q, s, n)).catch(e => { if (e && e.code === 11000) return bad(s, 'Already exists', 409); console.error(e.message); bad(s, 'Server error', 500); });

const sign = (u, rem) => jwt.sign({ id: String(u._id), v: u.tv }, JWT_SECRET, { expiresIn: rem ? '30d' : '1d' });
const setCk = (s, u, rem) => s.cookie('tk', sign(u, rem), Object.assign({ httpOnly: true, secure: PROD, sameSite: 'lax' }, rem ? { maxAge: 30 * 864e5 } : {}));
async function userFrom(tk) { try { const p = jwt.verify(tk, JWT_SECRET), u = await User.findById(p.id); return u && u.tv === p.v && !u.suspended ? u : null; } catch { return null; } }
const maybe = h(async (q, s, n) => { q.user = await userFrom(q.cookies.tk); n(); });
const auth = h(async (q, s, n) => { q.user = await userFrom(q.cookies.tk); q.user ? n() : bad(s, 'Please log in first', 401); });
const admin = (q, s, n) => q.user.role === 'admin' ? n() : bad(s, 'Admins only', 403);
const audit = (q, action, target) => Audit.create({ admin: q.user._id, action, target: String(target || '') }).catch(() => {});
async function excl(q) {
  const ids = new Set();
  if (q.user) { q.user.blocked.forEach(x => ids.add(String(x))); (await User.find({ blocked: q.user._id }).distinct('_id')).forEach(x => ids.add(String(x))); }
  else (await User.find({ isPublic: false }).distinct('_id')).forEach(x => ids.add(String(x)));
  return [...ids];
}
async function notify(user, type, from, post, text) {
  if (String(user) === String(from)) return;
  const n = await Notif.create({ user, type, from, post, text });
  io.to('u:' + user).emit('notification', { id: String(n._id), type, text });
}
const mePriv = u => ({ ...pub(u), email: u.email || '', mobile: u.mobile, isPublic: u.isPublic, role: u.role });

/* ---------- auth + account ---------- */
app.post('/api/auth/register', authLimit, h(async (q, s) => {
  const b = q.body || {}, un = str(b.username, 20).toLowerCase(), dn = str(b.displayName, 40) || un, em = str(b.email, 120).toLowerCase(), mob = str(b.mobile, 20);
  if (!/^[a-z0-9_]{3,20}$/.test(un)) return bad(s, 'Username: 3 to 20 letters, numbers or underscore');
  if (dn.length < 2) return bad(s, 'Please enter your full name');
  if (em && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) return bad(s, 'Enter a valid email');
  if (mob && !/^\+?[0-9][0-9\s-]{8,14}$/.test(mob)) return bad(s, 'Enter a valid mobile number');
  if (typeof b.password !== 'string' || b.password.length < 8 || b.password.length > 72) return bad(s, 'Password must be 8 to 72 characters');
  if (await User.exists({ username: un })) return bad(s, 'Username already taken', 409);
  if (em && await User.exists({ email: em })) return bad(s, 'Email already registered', 409);
  const u = await User.create({ username: un, displayName: dn, email: em || undefined, mobile: mob, role: ADMIN_USERNAME && un === ADMIN_USERNAME ? 'admin' : 'user', passwordHash: await bcrypt.hash(b.password, 10) });
  setCk(s, u, !!b.remember); s.status(201).json(mePriv(u));
}));
app.post('/api/auth/login', authLimit, h(async (q, s) => {
  const b = q.body || {}, id = str(b.identifier, 120).toLowerCase();
  const u = id && await User.findOne({ $or: [{ username: id }, { email: id }] });
  if (!u || typeof b.password !== 'string' || !await bcrypt.compare(b.password, u.passwordHash)) return bad(s, 'Wrong username/email or password', 401);
  if (u.suspended) return bad(s, 'This account is suspended', 403);
  setCk(s, u, !!b.remember); s.json(mePriv(u));
}));
app.post('/api/auth/logout', (q, s) => { s.clearCookie('tk'); s.json({ ok: true }); });
app.post('/api/auth/logout-all', auth, h(async (q, s) => { await User.updateOne({ _id: q.user._id }, { $inc: { tv: 1 } }); s.clearCookie('tk'); s.json({ ok: true }); }));
app.get('/api/auth/me', auth, h(async (q, s) => { const bl = await User.find({ _id: { $in: q.user.blocked } }); s.json({ ...mePriv(q.user), blocked: bl.map(pub) }); }));
app.patch('/api/me', auth, h(async (q, s) => {
  const b = q.body || {}, u = q.user;
  if (b.displayName !== undefined) { const v = str(b.displayName, 40); if (v.length < 2) return bad(s, 'Name is too short'); u.displayName = v; }
  if (b.bio !== undefined) u.bio = str(b.bio, 200);
  if (b.mobile !== undefined) { const m = str(b.mobile, 20); if (m && !/^\+?[0-9][0-9\s-]{8,14}$/.test(m)) return bad(s, 'Enter a valid mobile number'); u.mobile = m; }
  if (typeof b.isPublic === 'boolean') u.isPublic = b.isPublic;
  await u.save(); s.json(mePriv(u));
}));
app.post('/api/me/password', auth, h(async (q, s) => {
  const b = q.body || {};
  if (typeof b.current !== 'string' || !await bcrypt.compare(b.current, q.user.passwordHash)) return bad(s, 'Current password is wrong', 401);
  if (typeof b.next !== 'string' || b.next.length < 8 || b.next.length > 72) return bad(s, 'New password must be 8 to 72 characters');
  q.user.passwordHash = await bcrypt.hash(b.next, 10); q.user.tv++; await q.user.save(); setCk(s, q.user, false); s.json({ ok: true });
}));
app.delete('/api/me', auth, h(async (q, s) => {
  const b = q.body || {};
  if (typeof b.password !== 'string' || !await bcrypt.compare(b.password, q.user.passwordHash)) return bad(s, 'Password is wrong', 401);
  const id = q.user._id, ps = await Post.find({ author: id }).distinct('_id');
  await Promise.all([Comment.deleteMany({ $or: [{ author: id }, { post: { $in: ps } }] }), Post.deleteMany({ author: id }), Msg.deleteMany({ $or: [{ from: id }, { to: id }] }), Notif.deleteMany({ $or: [{ user: id }, { from: id }] }), User.deleteOne({ _id: id })]);
  s.clearCookie('tk'); s.json({ ok: true });
}));

/* ---------- public: online, search, profile ---------- */
app.get('/api/online', (q, s) => s.json({ count: online.size }));
app.get('/api/suggest', maybe, h(async (q, s) => {
  const t = str(q.query.q, 30); if (t.length < 2) return s.json([]);
  const re = new RegExp('^' + esc(t), 'i'), ex = await excl(q);
  const us = await User.find({ _id: { $nin: ex }, isPublic: true, $or: [{ username: re }, { displayName: re }] }).limit(5);
  s.json(us.map(u => u.displayName));
}));
async function shapePosts(q, ps) {
  const ids = ps.map(p => p._id), cs = await Comment.aggregate([{ $match: { post: { $in: ids } } }, { $group: { _id: '$post', n: { $sum: 1 } } }]);
  const m = Object.fromEntries(cs.map(c => [String(c._id), c.n])), me = q.user && String(q.user._id);
  return ps.map(p => ({ id: String(p._id), text: p.text, createdAt: p.createdAt, edited: p.updatedAt - p.createdAt > 1000,
    author: p.author ? { id: String(p.author._id), username: p.author.username, displayName: p.author.displayName } : null,
    likes: p.likes.length, liked: !!me && p.likes.some(l => String(l) === me), comments: m[String(p._id)] || 0 }));
}
const shapeCom = c => ({ id: String(c._id), text: c.text, parent: c.parent ? String(c.parent) : null, createdAt: c.createdAt, post: String(c.post), author: c.author ? { id: String(c.author._id), username: c.author.username, displayName: c.author.displayName } : null });
app.get('/api/search', maybe, h(async (q, s) => {
  const t = str(q.query.q, 60), type = ['users', 'posts', 'comments'].includes(q.query.type) ? q.query.type : 'all';
  if (t.length < 2) return s.json({ users: [], posts: [], comments: [] });
  const re = new RegExp(esc(t), 'i'), ex = await excl(q), pg = Math.max(0, +q.query.page || 0), lim = type === 'all' ? 5 : 10, sk = type === 'all' ? 0 : pg * 10, out = {};
  if (type === 'all' || type === 'users') out.users = (await User.find({ _id: { $nin: ex }, isPublic: true, $or: [{ username: re }, { displayName: re }, { bio: re }] }).skip(sk).limit(lim)).map(pub);
  if (type === 'all' || type === 'posts') out.posts = await shapePosts(q, await Post.find({ text: re, author: { $nin: ex } }).sort({ createdAt: -1 }).skip(sk).limit(lim).populate('author', 'username displayName'));
  if (type === 'all' || type === 'comments') out.comments = (await Comment.find({ text: re, author: { $nin: ex } }).sort({ createdAt: -1 }).skip(sk).limit(lim).populate('author', 'username displayName')).map(shapeCom);
  s.json(out);
}));
app.get('/api/u/:username', maybe, h(async (q, s) => {
  const u = await User.findOne({ username: str(q.params.username, 20).toLowerCase() });
  const self = q.user && u && String(q.user._id) === String(u._id), adm = q.user && q.user.role === 'admin';
  if (!u || (!u.isPublic && !self && !adm)) return bad(s, 'User not found', 404);
  s.json({ ...pub(u), createdAt: u.createdAt, posts: await Post.countDocuments({ author: u._id }) });
}));

/* ---------- posts + comments ---------- */
app.get('/api/posts', maybe, h(async (q, s) => {
  const f = { author: { $nin: await excl(q) } }; if (isId(q.query.author)) f.author = q.query.author;
  const pg = Math.max(0, +q.query.page || 0);
  s.json(await shapePosts(q, await Post.find(f).sort({ createdAt: -1 }).skip(pg * 10).limit(10).populate('author', 'username displayName')));
}));
app.get('/api/posts/:id', maybe, h(async (q, s) => {
  if (!isId(q.params.id)) return bad(s, 'Not found', 404);
  const p = await Post.findById(q.params.id).populate('author', 'username displayName');
  if (!p) return bad(s, 'Post not found', 404);
  const cs = await Comment.find({ post: p._id }).sort({ createdAt: 1 }).limit(300).populate('author', 'username displayName');
  s.json({ post: (await shapePosts(q, [p]))[0], comments: cs.map(shapeCom) });
}));
app.post('/api/posts', auth, writeLimit, h(async (q, s) => {
  const t = str((q.body || {}).text, 1000); if (t.length < 1) return bad(s, 'Write something first');
  const p = await Post.create({ author: q.user._id, text: t }); await p.populate('author', 'username displayName');
  s.status(201).json((await shapePosts(q, [p]))[0]);
}));
app.patch('/api/posts/:id', auth, h(async (q, s) => {
  const t = str((q.body || {}).text, 1000); if (!isId(q.params.id) || !t) return bad(s, 'Bad request');
  const p = await Post.findOne({ _id: q.params.id, author: q.user._id }); if (!p) return bad(s, 'Not found', 404);
  p.text = t; await p.save(); await p.populate('author', 'username displayName'); s.json((await shapePosts(q, [p]))[0]);
}));
app.delete('/api/posts/:id', auth, h(async (q, s) => {
  if (!isId(q.params.id)) return bad(s, 'Bad request');
  const p = await Post.findById(q.params.id); if (!p) return bad(s, 'Not found', 404);
  const own = String(p.author) === String(q.user._id); if (!own && q.user.role !== 'admin') return bad(s, 'Not allowed', 403);
  await Promise.all([Post.deleteOne({ _id: p._id }), Comment.deleteMany({ post: p._id })]); if (!own) audit(q, 'delete_post', p._id); s.json({ ok: true });
}));
app.post('/api/posts/:id/like', auth, h(async (q, s) => {
  if (!isId(q.params.id)) return bad(s, 'Bad request');
  const p = await Post.findById(q.params.id); if (!p) return bad(s, 'Not found', 404);
  const i = p.likes.findIndex(l => String(l) === String(q.user._id));
  if (i >= 0) p.likes.splice(i, 1); else { p.likes.push(q.user._id); notify(p.author, 'like', q.user._id, p._id, q.user.displayName + ' liked your post').catch(() => {}); }
  await p.save(); s.json({ likes: p.likes.length, liked: i < 0 });
}));
app.post('/api/posts/:id/comments', auth, writeLimit, h(async (q, s) => {
  const b = q.body || {}, t = str(b.text, 500); if (!isId(q.params.id) || !t) return bad(s, 'Write a comment first');
  const p = await Post.findById(q.params.id); if (!p) return bad(s, 'Post not found', 404);
  let par = null; if (isId(b.parent)) par = await Comment.findOne({ _id: b.parent, post: p._id });
  const c = await Comment.create({ post: p._id, author: q.user._id, parent: par ? par._id : null, text: t }); await c.populate('author', 'username displayName');
  notify(p.author, 'comment', q.user._id, p._id, q.user.displayName + ' commented on your post').catch(() => {});
  if (par) notify(par.author, 'reply', q.user._id, p._id, q.user.displayName + ' replied to your comment').catch(() => {});
  s.status(201).json(shapeCom(c));
}));
app.delete('/api/comments/:id', auth, h(async (q, s) => {
  if (!isId(q.params.id)) return bad(s, 'Bad request');
  const c = await Comment.findById(q.params.id); if (!c) return bad(s, 'Not found', 404);
  const p = await Post.findById(c.post), own = String(c.author) === String(q.user._id), pown = p && String(p.author) === String(q.user._id);
  if (!own && !pown && q.user.role !== 'admin') return bad(s, 'Not allowed', 403);
  await Comment.deleteMany({ $or: [{ _id: c._id }, { parent: c._id }] }); if (!own && !pown) audit(q, 'delete_comment', c._id); s.json({ ok: true });
}));

/* ---------- messages, blocks, reports, notifications ---------- */
app.get('/api/conversations', auth, h(async (q, s) => {
  const me = String(q.user._id), ms = await Msg.find({ $or: [{ from: me }, { to: me }] }).sort({ createdAt: -1 }).limit(1000), map = new Map();
  for (const m of ms) { const peer = String(m.from) === me ? String(m.to) : String(m.from); if (!map.has(peer)) map.set(peer, { last: outMsg(m), unread: 0 }); if (String(m.to) === me && m.status < 2) map.get(peer).unread++; }
  const us = await User.find({ _id: { $in: [...map.keys()] } });
  s.json(us.map(u => ({ peer: pub(u), ...map.get(String(u._id)) })).sort((a, b) => new Date(b.last.createdAt) - new Date(a.last.createdAt)));
}));
app.get('/api/messages/:peerId', auth, h(async (q, s) => {
  if (!isId(q.params.peerId)) return bad(s, 'Bad id');
  const f = { convId: convOf(q.user._id, q.params.peerId) }, b = new Date(q.query.before); if (q.query.before && !isNaN(b)) f.createdAt = { $lt: b };
  const peer = await User.findById(q.params.peerId);
  s.json({ peer: peer && pub(peer), blocked: q.user.blocked.some(x => String(x) === q.params.peerId), messages: (await Msg.find(f).sort({ createdAt: -1 }).limit(50)).reverse().map(outMsg) });
}));
app.delete('/api/messages/:id', auth, h(async (q, s) => {
  if (!isId(q.params.id)) return bad(s, 'Bad id');
  const m = await Msg.findOneAndDelete({ _id: q.params.id, from: q.user._id }); if (!m) return bad(s, 'Not found', 404);
  [m.from, m.to].forEach(x => io.to('u:' + x).emit('message_deleted', { id: String(m._id) })); s.json({ ok: true });
}));
app.post('/api/block/:id', auth, h(async (q, s) => {
  if (!isId(q.params.id) || q.params.id === String(q.user._id) || !await User.exists({ _id: q.params.id })) return bad(s, 'Bad request');
  const i = q.user.blocked.findIndex(x => String(x) === q.params.id);
  if (i >= 0) q.user.blocked.splice(i, 1); else q.user.blocked.push(q.params.id);
  await q.user.save(); s.json({ blocked: i < 0 });
}));
app.post('/api/report', auth, writeLimit, h(async (q, s) => {
  const b = q.body || {}, reason = str(b.reason, 300) || 'No reason given'; if (!isId(b.ref)) return bad(s, 'Bad request');
  let snap = '';
  if (b.kind === 'post') { const p = await Post.findById(b.ref); if (!p) return bad(s, 'Not found', 404); snap = p.text; }
  else if (b.kind === 'comment') { const c = await Comment.findById(b.ref); if (!c) return bad(s, 'Not found', 404); snap = c.text; }
  else if (b.kind === 'message') { const m = await Msg.findOne({ _id: b.ref, to: q.user._id }); if (!m) return bad(s, 'Not found', 404); snap = m.text; }
  else return bad(s, 'Bad request');
  await Report.create({ by: q.user._id, kind: b.kind, ref: b.ref, reason, snapshot: snap }); s.status(201).json({ ok: true });
}));
app.get('/api/notifications', auth, h(async (q, s) => {
  const ns = await Notif.find({ user: q.user._id }).sort({ createdAt: -1 }).limit(50);
  s.json({ unread: ns.filter(n => !n.read).length
