const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const app = express(), PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data'), FILE = path.join(DIR, 'db.json');
const SECRET = process.env.JWT_SECRET || 'dev-only-secret', MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
fs.mkdirSync(DIR, { recursive: true });
let db = { users: [], trades: [], accounts: [] };
try { db = { ...db, ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; } catch {}
const save = () => { fs.writeFileSync(FILE + '.tmp', JSON.stringify(db)); fs.renameSync(FILE + '.tmp', FILE); };
const id = () => crypto.randomBytes(8).toString('hex');
const mac = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const sign = u => { const p = Buffer.from(JSON.stringify({ u, e: Date.now() + 30 * 864e5 })).toString('base64url'); return p + '.' + mac(p); };
const verify = t => { try { const [p, s] = t.split('.'); if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(mac(p)))) return; const d = JSON.parse(Buffer.from(p, 'base64url')); return d.e > Date.now() ? d.u : undefined; } catch {} };
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
const check = (pw, st) => { const [s, h] = st.split(':'); return crypto.timingSafeEqual(Buffer.from(h, 'hex'), crypto.scryptSync(pw, s, 64)); };
const pub = u => ({ id: u.id, email: u.email, name: u.name, guest: !!u.guest });
const auth = (q, r, n) => {
  const u = db.users.find(x => x.id === verify((q.headers.authorization || '').slice(7)));
  if (!u) return r.status(401).json({ error: 'Please sign in again.' });
  q.uid = u.id; if (u.guest && Date.now() - (u.seen || 0) > 864e5) { u.seen = Date.now(); save(); } n();
};
const num = v => { const n = parseFloat(String(v ?? '').replace(/[\s,]/g, '')); return Number.isFinite(n) ? n : null; };
const clean = t => ({
  symbol: String(t.symbol || '').toUpperCase().replace(/\s/g, '').slice(0, 20),
  side: /sell|short/i.test(t.side) ? 'sell' : 'buy', lots: num(t.lots), entry: num(t.entry), exit: num(t.exit), pnl: num(t.pnl) ?? 0,
  date: String(t.date || '').replace(/\./g, '-').replace('T', ' ').slice(0, 19) || new Date().toISOString().slice(0, 19).replace('T', ' '),
  note: String(t.note || '').slice(0, 500)
});

app.set('trust proxy', 1);
app.use(express.json({ limit: '20mb' }));
app.get('/api/health', (q, r) => r.json({ ok: true, ai: !!process.env.ANTHROPIC_API_KEY }));

// ---- auth
app.post('/api/auth/register', (q, r) => {
  const { email, password, name } = q.body || {}, e = String(email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(e)) return r.status(400).json({ error: 'Enter a valid email.' });
  if (String(password || '').length < 8) return r.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (db.users.some(u => u.email === e)) return r.status(409).json({ error: 'That email already has an account. Sign in instead.' });
  const u = { id: id(), email: e, name: String(name || '').trim().slice(0, 40) || e.split('@')[0], pw: hash(String(password)) };
  db.users.push(u); save(); r.json({ token: sign(u.id), user: pub(u) });
});
app.post('/api/auth/login', (q, r) => {
  const { email, password } = q.body || {}, u = db.users.find(x => x.email === String(email || '').trim().toLowerCase());
  if (!u || !u.pw || !check(String(password || ''), u.pw)) return r.status(401).json({ error: 'Wrong email or password.' });
  r.json({ token: sign(u.id), user: pub(u) });
});
// ---- guest accounts (auto-deleted after 14 idle days, limited AI, upgradeable)
const hits = new Map();
app.post('/api/auth/guest', (q, r) => {
  const now = Date.now(), h = (hits.get(q.ip) || []).filter(t => now - t < 36e5);
  if (h.length >= 10) return r.status(429).json({ error: 'Too many guest accounts from this network. Try again in an hour, or create an account.' });
  hits.set(q.ip, [...h, now]);
  const u = { id: id(), email: '', name: 'Guest', guest: true, seen: now, ai: 0 };
  db.users.push(u); save(); r.json({ token: sign(u.id), user: pub(u) });
});
app.post('/api/auth/upgrade', auth, (q, r) => {
  const u = db.users.find(x => x.id === q.uid); if (!u.guest) return r.status(400).json({ error: 'This is already a full account.' });
  const { email, password, name } = q.body || {}, e = String(email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(e)) return r.status(400).json({ error: 'Enter a valid email.' });
  if (String(password || '').length < 8) return r.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (db.users.some(x => x.email === e)) return r.status(409).json({ error: 'That email already has an account. Sign in instead.' });
  Object.assign(u, { email: e, name: String(name || '').trim().slice(0, 40) || e.split('@')[0], pw: hash(String(password)), guest: false });
  delete u.seen; delete u.ai; save(); r.json({ user: pub(u) });
});
app.get('/api/me', auth, (q, r) => r.json({ user: pub(db.users.find(u => u.id === q.uid)) }));

// ---- accounts
app.get('/api/accounts', auth, (q, r) => r.json({ accounts: db.accounts.filter(a => a.uid === q.uid) }));
app.post('/api/accounts', auth, (q, r) => {
  const name = String(q.body.name || '').trim().slice(0, 40); if (!name) return r.status(400).json({ error: 'Give the account a name.' });
  db.accounts.push({ id: id(), uid: q.uid, name }); save(); r.json({ ok: true });
});
app.delete('/api/accounts/:id', auth, (q, r) => {
  db.accounts = db.accounts.filter(a => !(a.uid === q.uid && a.id === q.params.id));
  db.trades.forEach(t => { if (t.uid === q.uid && t.acct === q.params.id) t.acct = ''; }); save(); r.json({ ok: true });
});

// ---- trades
app.get('/api/trades', auth, (q, r) => r.json({ trades: db.trades.filter(t => t.uid === q.uid) }));
app.post('/api/trades', auth, (q, r) => {
  const list = (q.body.trades || []).slice(0, 200), acct = q.body.acct && q.body.acct !== 'all' ? q.body.acct : ''; let added = 0;
  for (const x of list) {
    const t = { ...clean(x), id: id(), uid: q.uid, acct };
    if (!t.symbol || db.trades.some(o => o.uid === q.uid && o.symbol === t.symbol && o.date === t.date && o.pnl === t.pnl)) continue;
    db.trades.push(t); added++;
  }
  save(); r.json({ added, skipped: list.length - added });
});
app.delete('/api/trades/:id', auth, (q, r) => { db.trades = db.trades.filter(t => !(t.uid === q.uid && t.id === q.params.id)); save(); r.json({ ok: true }); });
app.delete('/api/trades', auth, (q, r) => { db.trades = db.trades.filter(t => t.uid !== q.uid); save(); r.json({ ok: true }); });

// ---- AI (Anthropic)
async function claude(content, max) {
  if (!process.env.ANTHROPIC_API_KEY) throw new Error('AI is not set up yet. Add ANTHROPIC_API_KEY in your Render environment.');
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: MODEL, max_tokens: max, messages: [{ role: 'user', content }] })
  });
  const d = await res.json(); if (!res.ok) throw new Error(d.error?.message || 'AI request failed');
  return d.content.map(c => c.text || '').join('');
}
const GUEST_AI = 5;
const guestAI = (q, r) => {
  const u = db.users.find(x => x.id === q.uid); if (!u.guest || !process.env.ANTHROPIC_API_KEY) return true;
  if ((u.ai || 0) >= GUEST_AI) { r.status(403).json({ error: `Guest AI limit reached (${GUEST_AI} uses). Create a free account in Settings and keep going. Your trades come with you.` }); return false; }
  u.ai = (u.ai || 0) + 1; save(); return true;
};
const READ = `These are screenshots from a trading app (e.g. MetaTrader History > Positions). Extract every closed trade row. Return ONLY a JSON array, no prose, no markdown. Each item: {"symbol":string,"side":"buy"|"sell","lots":number,"entry":number,"exit":number,"date":"YYYY-MM-DD HH:mm:ss" (the close time shown),"pnl":number (the profit shown on that row; negative for losses)}. Remove thousands spaces from numbers. Use null for anything unreadable; never guess. Ignore summary totals (Profit, Deposit, Swap, Commission, Balance).`;
app.post('/api/analyze', auth, async (q, r) => {
  const imgs = (q.body.images || []).slice(0, 6); if (!imgs.length) return r.status(400).json({ error: 'Upload at least one screenshot.' }); if (!guestAI(q, r)) return;
  try {
    const txt = await claude([...imgs.map(i => ({ type: 'image', source: { type: 'base64', media_type: i.mime || 'image/jpeg', data: i.data } })), { type: 'text', text: READ }], 4000);
    const m = txt.match(/\[[\s\S]*\]/); r.json({ trades: JSON.parse(m ? m[0] : '[]').map(clean).filter(t => t.symbol) });
  } catch (e) { r.status(502).json({ error: e.message }); }
});
const COACH = 'You are a blunt, practical trading coach. Below are a trader\'s recent trades (date | symbol | side | lots | P/L). In 5 short bullets: spot patterns (overtrading, rapid-fire re-entries after losses, inconsistent lot sizes, instruments that bleed), note what is working, and end with ONE concrete rule for the next session. No price predictions, no financial advice.\n';
app.post('/api/coach', auth, async (q, r) => {
  const ts = db.trades.filter(t => t.uid === q.uid).sort((a, b) => a.date < b.date ? -1 : 1).slice(-60);
  if (ts.length < 3) return r.status(400).json({ error: 'Add at least 3 trades first.' }); if (!guestAI(q, r)) return;
  try { r.json({ text: await claude([{ type: 'text', text: COACH + ts.map(t => [t.date, t.symbol, t.side, t.lots, t.pnl].join(' | ')).join('\n') }], 700) }); }
  catch (e) { r.status(502).json({ error: e.message }); }
});

setInterval(() => {
  hits.clear(); const cut = Date.now() - 14 * 864e5, dead = new Set(db.users.filter(u => u.guest && (u.seen || 0) < cut).map(u => u.id));
  if (!dead.size) return;
  db.users = db.users.filter(u => !dead.has(u.id)); db.trades = db.trades.filter(t => !dead.has(t.uid)); db.accounts = db.accounts.filter(a => !dead.has(a.uid)); save();
}, 6 * 36e5).unref();
app.use(express.static(path.join(__dirname, 'public')));
app.use((e, q, r, n) => r.status(e.status || 500).json({ error: e.type === 'entity.too.large' ? 'Images are too large. Upload fewer screenshots.' : 'Server error.' }));
app.listen(PORT, () => console.log('LIQUID running on ' + PORT));
