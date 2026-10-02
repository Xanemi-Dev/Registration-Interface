require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const initializeSqlJs = require('sql.js');
const { rateLimit } = require('express-rate-limit');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ACCESS_TOKEN_SECONDS = 15 * 60;
const NORMAL_REFRESH_SECONDS = 24 * 60 * 60;
const REMEMBER_REFRESH_SECONDS = 7 * 24 * 60 * 60;

if (!JWT_SECRET || Buffer.byteLength(JWT_SECRET) < 32) {
  throw new Error('Set JWT_SECRET to a random value of at least 32 bytes before starting the server.');
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

let db;
let SQLRuntime;
let databasePath;
let transactionDepth = 0;
let dummyPasswordHash;
let findUserByEmail;
let findUserById;
let insertUser;
let insertRefreshToken;
let findRefreshToken;
let deleteRefreshToken;

function persistDatabase() {
  if (databasePath === ':memory:') return;
  const temporaryPath = \`\${databasePath}.\${process.pid}.\${crypto.randomUUID()}.tmp\`;
  fs.writeFileSync(temporaryPath, Buffer.from(db.export()), { mode: 0o600 });
  fs.renameSync(temporaryPath, databasePath);
}

function restoreDatabase(snapshot) {
  db.close();
  db = new SQLRuntime.Database(new Uint8Array(snapshot));
  db.exec('PRAGMA foreign_keys = ON');
}

function prepare(sql) {
  return {
    run(...params) {
      const snapshot = transactionDepth === 0 ? Buffer.from(db.export()) : null;
      const statement = db.prepare(sql);
      try {
        statement.run(params);
      } finally {
        statement.free();
      }
      if (snapshot) {
        try {
          persistDatabase();
        } catch (error) {
          restoreDatabase(snapshot);
          throw error;
        }
      }
    },
    get(...params) {
      const statement = db.prepare(sql);
      try {
        statement.bind(params);
        return statement.step() ? statement.getAsObject() : undefined;
      } finally {
        statement.free();
      }
    },
  };
}

function initializeDatabaseTransaction(callback) {
  const snapshot = Buffer.from(db.export());
  db.exec('BEGIN IMMEDIATE');
  transactionDepth++;
  let committed = false;
  try {
    const result = callback();
    db.exec('COMMIT');
    transactionDepth--;
    committed = true;
    try {
      persistDatabase();
    } catch (error) {
      restoreDatabase(snapshot);
      throw error;
    }
    return result;
  } catch (error) {
    if (!committed) {
      db.exec('ROLLBACK');
      transactionDepth--;
    }
    throw error;
  }
}

async function initializeDatabase() {
  databasePath = process.env.AUTH_DB_PATH || path.join(__dirname, 'auth.sqlite');
  dummyPasswordHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
  SQLRuntime = await initializeSqlJs();
  if (databasePath !== ':memory:') {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    db = fs.existsSync(databasePath)
      ? new SQLRuntime.Database(new Uint8Array(fs.readFileSync(databasePath)))
      : new SQLRuntime.Database();
  } else {
    db = new SQLRuntime.Database();
  }
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(\`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL COLLATE NOCASE UNIQUE,
      email TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
  \`);
  findUserByEmail = prepare('SELECT * FROM users WHERE email = ?');
  findUserById = prepare('SELECT id, username, email FROM users WHERE id = ?');
  insertUser = prepare(
    'INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
  );
  insertRefreshToken = prepare(
    'INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
  );
  findRefreshToken = prepare(
    'SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?',
  );
  deleteRefreshToken = prepare('DELETE FROM refresh_tokens WHERE token_hash = ?');
  if (databasePath !== ':memory:' && !fs.existsSync(databasePath)) persistDatabase();
}

function setRefreshCookie(res, token, rememberMe) {
  const options = {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/api',
  };
  if (rememberMe) options.maxAge = REMEMBER_REFRESH_SECONDS * 1000;
  res.cookie('refresh_token', token, options);
}

function clearRefreshCookie(res) {
  res.clearCookie('refresh_token', {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/api',
  });
}

function tokenDigest(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createCsrfToken(value) {
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(value).digest('base64url');
  return \`\${value}.\${signature}\`;
}

function validCsrfToken(token) {
  if (typeof token !== 'string') return false;
  const separator = token.indexOf('.');
  if (separator < 1) return false;
  const value = token.slice(0, separator);
  const suppliedSignature = token.slice(separator + 1);
  const expectedSignature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(value)
    .digest('base64url');
  return safeEqual(suppliedSignature, expectedSignature);
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin) {
    let parsedOrigin;
    try {
      parsedOrigin = new URL(origin);
    } catch {
      return res.status(403).json({ error: 'Invalid request origin.' });
    }
    if (parsedOrigin.host !== req.get('host') || parsedOrigin.protocol !== \`\${req.protocol}:\`) {
      return res.status(403).json({ error: 'Cross-origin requests are not allowed.' });
    }
  }
  next();
}

function requireCsrf(req, res, next) {
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.get('x-csrf-token');
  if (
    !validCsrfToken(cookieToken) ||
    !validCsrfToken(headerToken) ||
    !safeEqual(cookieToken, headerToken)
  ) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
  }
  next();
}

function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, type: 'access' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_SECONDS, issuer: 'registration-interface', audience: 'registration-interface' },
  );
}

function issueRefreshToken(userId, rememberMe) {
  const lifetime = rememberMe ? REMEMBER_REFRESH_SECONDS : NORMAL_REFRESH_SECONDS;
  const token = jwt.sign(
    { sub: userId, type: 'refresh', rememberMe, jti: crypto.randomUUID() },
    JWT_SECRET,
    {
      expiresIn: lifetime,
      issuer: 'registration-interface',
      audience: 'registration-interface',
    },
  );
  insertRefreshToken.run(tokenDigest(token), userId, Date.now() + lifetime * 1000);
  return token;
}

function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email };
}

function authenticateAccessToken(req, res, next) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer ([^\s]+)$/);
  if (!match) return res.status(401).json({ error: 'Authentication required.' });

  try {
    const payload = jwt.verify(match[1], JWT_SECRET, {
      issuer: 'registration-interface',
      audience: 'registration-interface',
    });
    if (payload.type !== 'access' || typeof payload.sub !== 'string') {
      return res.status(401).json({ error: 'Invalid access token.' });
    }
    const user = findUserById.get(payload.sub);
    if (!user) return res.status(401).json({ error: 'Invalid access token.' });
    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: 'Access token is invalid or expired.' });
    }
    next(error);
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' }),
});

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many registration attempts. Try again later.' }),
});

app.get('/api/csrf', (_req, res) => {
  const token = createCsrfToken(crypto.randomBytes(32).toString('base64url'));
  res.cookie('csrf_token', token, {
    httpOnly: false,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    path: '/',
    maxAge: 24 * 60 * 60 * 1000,
  });
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: token });
});

app.get('/', (_req, res) => {
  const nonce = crypto.randomBytes(18).toString('base64');
  res.set(
    'Content-Security-Policy',
    \`default-src 'self'; script-src 'self' 'nonce-\${nonce}'; style-src 'self' 'nonce-\${nonce}'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'\`,
  );
  res.type('html').send(INDEX_HTML.replaceAll('__CSP_NONCE__', nonce));
});

app.post('/api/register', requireSameOrigin, requireCsrf, registrationLimiter, async (req, res, next) => {
  const { username, email, password } = req.body || {};
  if (
    typeof username !== 'string' ||
    typeof email !== 'string' ||
    typeof password !== 'string'
  ) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }

  const normalizedUsername = username.trim();
  const normalizedEmail = email.trim().toLowerCase();
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(normalizedUsername)) {
    return res.status(400).json({ error: 'Username must be 3–32 characters using letters, numbers, _ or -.' });
  }
  if (normalizedEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (password.length < 12) {
    return res.status(400).json({ error: 'Password must be at least 12 characters.' });
  }
  if (Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ error: 'Password must be no more than 72 UTF-8 bytes.' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      id: crypto.randomUUID(),
      username: normalizedUsername,
      email: normalizedEmail,
    };
    insertUser.run(user.id, user.username, user.email, passwordHash, Date.now());
    res.status(201).json({ message: 'Account created. You can now sign in.', user });
  } catch (error) {
    if (/UNIQUE constraint failed: users\.(username|email)/i.test(error.message)) {
      return res.status(409).json({ error: 'That username or email is already registered.' });
    }
    next(error);
  }
});

app.post('/api/login', requireSameOrigin, requireCsrf, loginLimiter, async (req, res, next) => {
  const { email, password, rememberMe = false } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string' || typeof rememberMe !== 'boolean') {
    return res.status(400).json({ error: 'Enter a valid email address and password.' });
  }
  if (Buffer.byteLength(password, 'utf8') > 72) {
    return res.status(400).json({ error: 'Password is too long (maximum 72 UTF-8 bytes).' });
  }
  const user = findUserByEmail.get(email.trim().toLowerCase());
  const matches = await bcrypt.compare(password, user ? user.password_hash : dummyPasswordHash);
  if (!user || !matches) return res.status(401).json({ error: 'Email or password is incorrect.' });

  try {
    const refreshToken = issueRefreshToken(user.id, rememberMe);
    setRefreshCookie(res, refreshToken, rememberMe);
    res.set('Cache-Control', 'no-store');
    res.json({
      message: \`Welcome back, \${user.username}!\`,
      accessToken: issueAccessToken(user),
      user: publicUser(user),
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/refresh', requireSameOrigin, requireCsrf, (req, res, next) => {
  const token = req.cookies.refresh_token;
  if (!token) return res.status(401).json({ error: 'No refresh session found. Please sign in again.' });

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: 'registration-interface',
      audience: 'registration-interface',
    });
    if (payload.type !== 'refresh' || typeof payload.sub !== 'string') {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Invalid refresh session. Please sign in again.' });
    }
    const storedToken = findRefreshToken.get(tokenDigest(token));
    if (!storedToken || storedToken.expires_at <= Date.now() || storedToken.user_id !== payload.sub) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh session expired. Please sign in again.' });
    }

    const user = findUserById.get(payload.sub);
    if (!user) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Account not found. Please sign in again.' });
    }

    const rememberMe = payload.rememberMe === true;
    const rotateRefreshToken = () => initializeDatabaseTransaction(() => {
      deleteRefreshToken.run(tokenDigest(token));
      return issueRefreshToken(user.id, rememberMe);
    });
    const nextRefreshToken = rotateRefreshToken();
    setRefreshCookie(res, nextRefreshToken, rememberMe);
    res.set('Cache-Control', 'no-store');
    res.json({ accessToken: issueAccessToken(user), user: publicUser(user) });
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError || error instanceof jwt.TokenExpiredError) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh session expired. Please sign in again.' });
    }
    next(error);
  }
});

app.post('/api/logout', requireSameOrigin, requireCsrf, (req, res) => {
  const token = req.cookies.refresh_token;
  if (token) deleteRefreshToken.run(tokenDigest(token));
  clearRefreshCookie(res);
  res.json({ message: 'You have been signed out.' });
});

app.get('/api/user', authenticateAccessToken, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.use((err, _req, res, _next) => {
  console.error('Request failed:', err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

const INDEX_HTML = \`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#f5f7f5">
  <title>Welcome — Northstar</title>
  <style nonce="__CSP_NONCE__">
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #17251f;
      background: #f4f7f4;
      font-synthesis: none;
      text-rendering: optimizeLegibility;
      --green: #176b50;
      --green-dark: #10513c;
      --muted: #66756e;
      --line: #dce5df;
      --danger: #a83232;
    }
    * { box-sizing: border-box; }
    body {
      min-width: 320px;
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 32px 20px;
      background:
        radial-gradient(ellipse at 14% 10%, rgba(202, 228, 211, .58), transparent 34%),
        radial-gradient(ellipse at 90% 86%, rgba(222, 232, 218, .72), transparent 34%),
        #f4f7f4;
    }
    button, input { font: inherit; }
    .layout { width: min(100%, 980px); display: grid; grid-template-columns: 1fr 1fr; align-items: stretch; }
    .story {
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 620px;
      padding: 42px;
      border-radius: 24px 0 0 24px;
      color: #f5fbf7;
      background: linear-gradient(145deg, #15513f 0%, #1d7054 56%, #3b8a69 100%);
    }
    .story::after {
      position: absolute;
      right: -120px;
      bottom: 70px;
      width: 330px;
      height: 330px;
      border: 1px solid rgba(255,255,255,.17);
      border-radius: 50%;
      box-shadow: 0 0 0 38px rgba(255,255,255,.035), 0 0 0 78px rgba(255,255,255,.03);
      content: "";
    }
    .brand { display: flex; align-items: center; gap: 11px; font-size: 15px; font-weight: 700; letter-spacing: .02em; }
    .brand-mark { display: grid; width: 32px; height: 32px; place-items: center; border: 1px solid rgba(255,255,255,.4); border-radius: 11px; font-size: 18px; }
    .story-copy { position: relative; z-index: 1; max-width: 360px; margin: 35px 0 auto; padding-top: 92px; }
    .eyebrow { margin: 0 0 17px; color: #c2e4d0; font-size: 12px; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
    h1 { margin: 0; font-size: clamp(34px, 4vw, 48px); font-weight: 600; letter-spacing: -.045em; line-height: 1.11; }
    .story-copy > p:last-child { max-width: 330px; margin: 20px 0 0; color: #e0f0e6; font-size: 15px; line-height: 1.75; }
    .quote { position: relative; z-index: 1; max-width: 350px; margin: 35px 0 0; color: #dcece2; font-size: 13px; line-height: 1.7; }
    .quote strong { display: block; margin-top: 12px; color: #fff; font-size: 12px; font-weight: 600; }
    .panel {
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 44px clamp(28px, 5vw, 54px);
      border: 1px solid rgba(24, 54, 39, .06);
      border-radius: 0 24px 24px 0;
      background: #fff;
      box-shadow: 0 22px 70px rgba(29, 61, 42, .10);
    }
    .panel h2 { margin: 0; font-size: 27px; font-weight: 650; letter-spacing: -.04em; }
    .intro { margin: 9px 0 25px; color: var(--muted); font-size: 14px; line-height: 1.55; }
    .tabs { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; margin-bottom: 24px; padding: 4px; border-radius: 12px; background: #f2f5f2; }
    .tab { min-height: 39px; border: 0; border-radius: 9px; color: #607067; background: transparent; cursor: pointer; font-size: 13px; font-weight: 600; }
    .tab[aria-selected="true"] { color: #194d3b; background: #fff; box-shadow: 0 1px 4px rgba(20, 48, 32, .11); }
    .field { margin-bottom: 15px; }
    .field label { display: block; margin-bottom: 7px; color: #263a30; font-size: 12px; font-weight: 650; }
    .input-wrap { position: relative; }
    input[type="text"], input[type="email"], input[type="password"] {
      width: 100%;
      height: 46px;
      padding: 0 13px;
      border: 1px solid #d7e1da;
      border-radius: 10px;
      outline: none;
      color: #17251f;
      background: #fff;
      font-size: 13px;
      transition: border-color .16s ease, box-shadow .16s ease;
    }
    input:focus { border-color: #398466; box-shadow: 0 0 0 3px rgba(46, 130, 94, .13); }
    input[aria-invalid="true"] { border-color: #bb5454; }
    input::placeholder { color: #9aa79f; }
    .password-input { padding-right: 69px !important; }
    .show-password {
      position: absolute;
      top: 0;
      right: 8px;
      height: 46px;
      padding: 0 6px;
      border: 0;
      color: #526b5d;
      background: transparent;
      cursor: pointer;
      font-size: 11px;
      font-weight: 650;
    }
    .field-error { min-height: 0; margin: 5px 0 0; color: var(--danger); font-size: 11px; }
    .options { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: 3px 0 20px; }
    .remember { display: inline-flex; align-items: center; gap: 8px; color: #52635a; font-size: 12px; cursor: pointer; }
    .remember input { width: 15px; height: 15px; accent-color: var(--green); }
    a { color: var(--green); font-size: 12px; font-weight: 600; text-decoration: none; }
    a:hover { color: var(--green-dark); text-decoration: underline; }
    .submit {
      width: 100%;
      min-height: 47px;
      border: 0;
      border-radius: 10px;
      color: #fff;
      background: var(--green);
      box-shadow: 0 4px 10px rgba(23, 107, 80, .16);
      cursor: pointer;
      font-size: 13px;
      font-weight: 650;
      transition: background .16s ease, transform .16s ease, box-shadow .16s ease;
    }
    .submit:hover:not(:disabled) { transform: translateY(-1px); background: var(--green-dark); box-shadow: 0 7px 15px rgba(23, 107, 80, .2); }
    .submit:focus-visible, .tab:focus-visible, .show-password:focus-visible, a:focus-visible { outline: 3px solid #85b99e; outline-offset: 3px; }
    .submit:disabled { cursor: not-allowed; opacity: .58; box-shadow: none; }
    .message { min-height: 20px; margin: 12px 0 0; color: var(--danger); font-size: 12px; line-height: 1.5; }
    .message[data-kind="success"] { color: #176b50; }
    .signed-in-view { padding: 18px; border: 1px solid #dce9df; border-radius: 12px; background: #f5faf6; }
    .signed-in-message { margin: 0 0 16px; color: #176b50; font-size: 14px; font-weight: 600; }
    .fine-print { margin: 17px 0 0; color: #78867e; font-size: 11px; line-height: 1.6; text-align: center; }
    .hidden { display: none !important; }
    @media (max-width: 720px) {
      body { padding: 20px 15px; }
      .layout { max-width: 460px; grid-template-columns: 1fr; }
      .story { min-height: auto; padding: 24px 25px 20px; border-radius: 20px 20px 0 0; }
      .story-copy { margin: 23px 0 0; padding-top: 0; }
      .story-copy h1 { max-width: 360px; font-size: 29px; }
      .story-copy > p:last-child { margin-top: 9px; font-size: 13px; }
      .quote { display: none; }
      .panel { padding: 29px 25px 30px; border-radius: 0 0 20px 20px; }
      .panel h2 { font-size: 24px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; }
    }
  </style>
</head>
<body>
  <main class="layout">
    <section class="story" aria-label="About Northstar">
      <div class="brand"><span class="brand-mark" aria-hidden="true">n</span><span>northstar</span></div>
      <div class="story-copy">
        <p class="eyebrow">A clearer way forward</p>
        <h1>Make room for what matters.</h1>
        <p>Your work, your ideas, and the people who make them possible — all in one thoughtful space.</p>
      </div>
      <blockquote class="quote">"The best tools don't ask for your attention. They give it back to you."<strong>— A calmer kind of workspace</strong></blockquote>
    </section>
    <section class="panel" aria-labelledby="form-title">
      <h2 id="form-title">Good to see you</h2>
      <p class="intro" id="form-intro">Sign in to pick up where you left off.</p>
      <div class="tabs" role="tablist" aria-label="Account access">
        <button class="tab" id="login-tab" type="button" role="tab" aria-selected="true" aria-controls="auth-form">Sign in</button>
        <button class="tab" id="register-tab" type="button" role="tab" aria-selected="false" aria-controls="auth-form">Create account</button>
      </div>
      <form id="auth-form" novalidate>
        <div class="field hidden" id="username-field">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autocomplete="username" minlength="3" maxlength="32" placeholder="e.g. alex_morgan" aria-describedby="username-error">
          <p class="field-error" id="username-error" aria-live="polite"></p>
        </div>
        <div class="field">
          <label for="email">Email address</label>
          <input id="email" name="email" type="email" autocomplete="email" maxlength="254" placeholder="you@example.com" required aria-describedby="email-error">
          <p class="field-error" id="email-error" aria-live="polite"></p>
        </div>
        <div class="field">
          <label for="password">Password</label>
          <div class="input-wrap">
            <input class="password-input" id="password" name="password" type="password" autocomplete="current-password" required aria-describedby="password-error">
            <button class="show-password" type="button" aria-label="Show password" aria-pressed="false">Show</button>
          </div>
          <p class="field-error" id="password-error" aria-live="polite"></p>
        </div>
        <div class="options">
          <label class="remember" id="remember-option"><input id="remember-me" type="checkbox"> <span>Remember me</span></label>
          <a href="#forgot-password" id="forgot-link">Forgot password?</a>
        </div>
        <button class="submit" id="submit-button" type="submit">Sign in</button>
        <p class="message" id="form-message" role="status" aria-live="polite"></p>
      </form>
      <div class="signed-in-view hidden" id="signed-in-view" aria-live="polite">
        <p class="signed-in-message" id="signed-in-message"></p>
        <button class="submit" id="sign-out-button" type="button">Sign out</button>
      </div>
      <p class="fine-print">By continuing, you agree to keep your account details secure.</p>
    </section>
  </main>
  <script nonce="__CSP_NONCE__">
    const form = document.querySelector('#auth-form');
    const loginTab = document.querySelector('#login-tab');
    const registerTab = document.querySelector('#register-tab');
    const usernameField = document.querySelector('#username-field');
    const usernameInput = document.querySelector('#username');
    const emailInput = document.querySelector('#email');
    const passwordInput = document.querySelector('#password');
    const passwordToggle = document.querySelector('.show-password');
    const rememberOption = document.querySelector('#remember-option');
    const rememberInput = document.querySelector('#remember-me');
    const submitButton = document.querySelector('#submit-button');
    const formMessage = document.querySelector('#form-message');
    const signedInView = document.querySelector('#signed-in-view');
    const signedInMessage = document.querySelector('#signed-in-message');
    const signOutButton = document.querySelector('#sign-out-button');
    const tabs = document.querySelector('.tabs');
    let isRegistering = false;
    let csrfToken = '';
    let accessToken = '';
    submitButton.disabled = true;

    function showMessage(message, kind = 'error') {
      formMessage.textContent = message;
      formMessage.dataset.kind = kind;
    }

    function clearErrors() {
      for (const name of ['username', 'email', 'password']) {
        const input = document.querySelector('#' + name);
        const error = document.querySelector('#' + name + '-error');
        input.removeAttribute('aria-invalid');
        error.textContent = '';
      }
    }

    function setFieldError(name, message) {
      document.querySelector('#' + name).setAttribute('aria-invalid', 'true');
      document.querySelector('#' + name + '-error').textContent = message;
    }

    function chooseMode(registering) {
      isRegistering = registering;
      loginTab.setAttribute('aria-selected', String(!registering));
      registerTab.setAttribute('aria-selected', String(registering));
      usernameField.classList.toggle('hidden', !registering);
      usernameInput.required = registering;
      passwordInput.autocomplete = registering ? 'new-password' : 'current-password';
      rememberOption.classList.toggle('hidden', registering);
      document.querySelector('#form-title').textContent = registering ? 'Create your account' : 'Good to see you';
      document.querySelector('#form-intro').textContent = registering
        ? 'A few details and you'll be ready to go.'
        : 'Sign in to pick up where you left off.';
      submitButton.textContent = registering ? 'Create account' : 'Sign in';
      showMessage('');
      clearErrors();
    }

    async function api(path, options = {}) {
      const headers = new Headers(options.headers || {});
      headers.set('Content-Type', 'application/json');
      headers.set('X-CSRF-Token', csrfToken);
      if (accessToken) headers.set('Authorization', 'Bearer ' + accessToken);
      const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
      const body = await response.json();
      if (!response.ok) {
        const error = new Error(body.error || 'Request failed. Please try again.');
        error.status = response.status;
        throw error;
      }
      return body;
    }

    function setSignedIn(username) {
      form.classList.add('hidden');
      tabs.classList.add('hidden');
      signedInMessage.textContent = 'Welcome back, ' + username + '. You're signed in.';
      signedInView.classList.remove('hidden');
    }

    async function signOut() {
      signOutButton.disabled = true;
      try {
        const result = await api('/api/logout', { method: 'POST', body: '{}' });
        accessToken = '';
        signedInView.classList.add('hidden');
        form.classList.remove('hidden');
        tabs.classList.remove('hidden');
        chooseMode(false);
        showMessage(result.message, 'success');
      } catch (error) {
        signedInMessage.textContent = error.message;
      } finally {
        signOutButton.disabled = false;
      }
    }

    function validateForm() {
      clearErrors();
      let valid = true;
      if (isRegistering && !/^[a-zA-Z0-9_-]{3,32}$/.test(usernameInput.value.trim())) {
        setFieldError('username', 'Use 3–32 letters, numbers, underscores, or hyphens.');
        valid = false;
      }
      if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(emailInput.value.trim())) {
        setFieldError('email', 'Email invalid — enter a valid email address.');
        valid = false;
      }
      if (isRegistering && passwordInput.value.length < 12) {
        setFieldError('password', 'Password too short — use at least 12 characters.');
        valid = false;
      } else if (new TextEncoder().encode(passwordInput.value).length > 72) {
        setFieldError('password', 'Password is too long (maximum 72 UTF-8 bytes).');
        valid = false;
      } else if (!passwordInput.value) {
        setFieldError('password', 'Enter your password.');
        valid = false;
      }
      return valid;
    }

    loginTab.addEventListener('click', () => chooseMode(false));
    registerTab.addEventListener('click', () => chooseMode(true));
    passwordToggle.addEventListener('click', () => {
      const showing = passwordInput.type === 'text';
      passwordInput.type = showing ? 'password' : 'text';
      passwordToggle.textContent = showing ? 'Show' : 'Hide';
      passwordToggle.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
      passwordToggle.setAttribute('aria-pressed', String(!showing));
    });
    document.querySelector('#forgot-link').addEventListener('click', event => {
      event.preventDefault();
      showMessage('Password reset is not set up yet. Please contact your workspace administrator.');
    });

    form.addEventListener('submit', async event => {
      event.preventDefault();
      showMessage('');
      if (!validateForm()) return;
      submitButton.disabled = true;
      submitButton.textContent = isRegistering ? 'Creating account…' : 'Signing in…';
      try {
        if (isRegistering) {
          await api('/api/register', {
            method: 'POST',
            body: JSON.stringify({
              username: usernameInput.value.trim(),
              email: emailInput.value.trim(),
              password: passwordInput.value,
            }),
          });
          chooseMode(false);
          showMessage('Your account is ready. Sign in to continue.', 'success');
          passwordInput.focus();
        } else {
          const result = await api('/api/login', {
            method: 'POST',
            body: JSON.stringify({
              email: emailInput.value.trim(),
              password: passwordInput.value,
              rememberMe: rememberInput.checked,
            }),
          });
          accessToken = result.accessToken;
          form.reset();
          setSignedIn(result.user.username);
        }
      } catch (error) {
        showMessage(error.message);
      } finally {
        if (submitButton.type === 'submit') {
          submitButton.disabled = false;
          submitButton.textContent = isRegistering ? 'Create account' : 'Sign in';
        } else {
          submitButton.disabled = false;
        }
      }
    });

    signOutButton.addEventListener('click', signOut);

    async function restoreSession() {
      try {
        const csrfResponse = await fetch('/api/csrf', { credentials: 'same-origin' });
        if (!csrfResponse.ok) throw new Error('Could not initialize secure sign-in. Please reload the page.');
        const csrfBody = await csrfResponse.json();
        csrfToken = csrfBody.csrfToken;
        const result = await api('/api/refresh', { method: 'POST', body: '{}' });
        accessToken = result.accessToken;
        setSignedIn(result.user.username);
      } catch (error) {
        if (error.status !== 401) showMessage(error.message);
      } finally {
        submitButton.disabled = false;
      }
    }
    restoreSession();
  </script>
</body>
</html>\`;

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(\`Registration interface running at http://localhost:\${PORT}\`);
    });
  })
  .catch(error => {
    console.error('Could not initialize the authentication database:', error);
    process.exitCode = 1;
  });