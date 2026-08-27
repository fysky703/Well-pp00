import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import { Pool } from 'pg';
import { OAuth2Client } from 'google-auth-library';
import QRCode from 'qrcode';
import speakeasy from 'speakeasy';
import bcrypt from 'bcryptjs';

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

const isProd = process.env.NODE_ENV === 'production';
const APP_URL = process.env.APP_URL || 'http://localhost:5173';
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3001/api/auth/google/callback';

for (const name of ['DATABASE_URL', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'MASTER_KEY_HEX']) {
  if (!process.env[name]) console.warn(`Missing environment variable: ${name}`);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 10_000
});

const oauth = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_HEX || '', 'hex');
if (MASTER_KEY.length !== 32) {
  console.warn('MASTER_KEY_HEX must decode to exactly 32 bytes. Run: npm run generate:key');
}

const SESSION_COOKIE = 'khmer_session';
const OAUTH_STATE_COOKIE = 'google_oauth_state';
const SESSION_DAYS = 7;

type User = {
  id: string;
  google_id: string;
  email: string;
  name: string;
  avatar_url: string | null;
  totp_enabled: boolean;
};

type SessionRow = {
  id: string;
  user_id: string;
  two_factor_verified: boolean;
  expires_at: string;
  google_id: string;
  email: string;
  name: string;
  avatar_url: string | null;
  totp_enabled: boolean;
};

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function sha256(value: string) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function encrypt(value: string) {
  if (MASTER_KEY.length !== 32) throw new Error('MASTER_KEY_HEX is not configured correctly');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

function decrypt(payload: string) {
  if (MASTER_KEY.length !== 32) throw new Error('MASTER_KEY_HEX is not configured correctly');
  const [ivPart, tagPart, dataPart] = payload.split('.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, Buffer.from(ivPart, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(dataPart, 'base64url')),
    decipher.final()
  ]).toString('utf8');
}

async function createSession(userId: string, twoFactorVerified: boolean) {
  const raw = randomToken();
  const id = sha256(raw);
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await pool.query(
    `INSERT INTO sessions (id, user_id, two_factor_verified, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [id, userId, twoFactorVerified, expires]
  );
  return { raw, expires };
}

function setSessionCookie(res: Response, raw: string) {
  res.cookie(SESSION_COOKIE, raw, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    ...(process.env.COOKIE_DOMAIN ? { domain: process.env.COOKIE_DOMAIN } : {})
  });
}

async function getSession(req: Request): Promise<SessionRow | null> {
  const raw = req.cookies?.[SESSION_COOKIE];
  if (!raw) return null;
  const id = sha256(raw);
  const { rows } = await pool.query<SessionRow>(
    `SELECT s.id, s.user_id, s.two_factor_verified, s.expires_at,
            u.google_id, u.email, u.name, u.avatar_url, u.totp_enabled
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = $1 AND s.expires_at > NOW()`
    , [id]
  );
  return rows[0] || null;
}

async function requireSignedIn(req: Request, res: Response, next: NextFunction) {
  try {
    const session = await getSession(req);
    if (!session) return res.status(401).json({ message: 'សូមចូលគណនីជាមុនសិន។' });
    (req as any).session = session;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'មានបញ្ហាជាមួយ server។' });
  }
}

async function requireFullyAuthenticated(req: Request, res: Response, next: NextFunction) {
  await requireSignedIn(req, res, () => {
    const session = (req as any).session as SessionRow;
    if (session.totp_enabled && !session.two_factor_verified) {
      return res.status(403).json({ message: 'សូមផ្ទៀងផ្ទាត់ Google Authenticator ជាមុនសិន។', code: 'TWO_FACTOR_REQUIRED' });
    }
    next();
  });
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'khmer-google-2fa' }));

app.get('/api/auth/google', async (_req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res.status(500).send('Google OAuth configuration is missing.');
  }
  const state = randomToken(24);
  res.cookie(OAUTH_STATE_COOKIE, state, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60 * 1000
  });
  const url = oauth.generateAuthUrl({
    access_type: 'offline',
    scope: ['openid', 'email', 'profile'],
    state,
    prompt: 'select_account'
  });
  res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query as { code?: string; state?: string };
    const expectedState = req.cookies?.[OAUTH_STATE_COOKIE];
    res.clearCookie(OAUTH_STATE_COOKIE, { path: '/' });
    if (!code || !state || !expectedState || state !== expectedState) {
      return res.redirect(`${APP_URL}/?error=oauth_state`);
    }

    const { tokens } = await oauth.getToken(code);
    if (!tokens.id_token) throw new Error('Google did not return an ID token');
    const ticket = await oauth.verifyIdToken({ idToken: tokens.id_token, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.sub || !payload.email) throw new Error('Google account data is incomplete');

    const googleId = payload.sub;
    const email = payload.email;
    const name = payload.name || email.split('@')[0];
    const avatar = payload.picture || null;

    const existing = await pool.query<User>(`SELECT * FROM users WHERE google_id = $1`, [googleId]);
    let user: User;
    if (existing.rows[0]) {
      const updated = await pool.query<User>(
        `UPDATE users SET email=$2, name=$3, avatar_url=$4, updated_at=NOW() WHERE google_id=$1 RETURNING id, google_id, email, name, avatar_url, totp_enabled`,
        [googleId, email, name, avatar]
      );
      user = updated.rows[0];
    } else {
      const created = await pool.query<User>(
        `INSERT INTO users (google_id, email, name, avatar_url) VALUES ($1,$2,$3,$4)
         RETURNING id, google_id, email, name, avatar_url, totp_enabled`,
        [googleId, email, name, avatar]
      );
      user = created.rows[0];
    }

    // If 2FA is enabled, OAuth only establishes identity; the session remains pending until OTP succeeds.
    const { raw, expires } = await createSession(user.id, !user.totp_enabled);
    setSessionCookie(res, raw);
    res.redirect(`${APP_URL}/?auth=success&expires=${encodeURIComponent(expires.toISOString())}`);
  } catch (error) {
    console.error('Google callback:', error);
    res.redirect(`${APP_URL}/?error=oauth_failed`);
  }
});

app.get('/api/auth/me', requireSignedIn, async (req, res) => {
  const session = (req as any).session as SessionRow;
  res.json({
    authenticated: true,
    requiresTwoFactor: session.totp_enabled && !session.two_factor_verified,
    user: {
      id: session.user_id,
      email: session.email,
      name: session.name,
      avatarUrl: session.avatar_url,
      twoFactorEnabled: session.totp_enabled
    }
  });
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const raw = req.cookies?.[SESSION_COOKIE];
    if (raw) await pool.query(`DELETE FROM sessions WHERE id=$1`, [sha256(raw)]);
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'មិនអាចចាកចេញបានទេ។' });
  }
});

app.post('/api/auth/2fa/verify', requireSignedIn, async (req, res) => {
  try {
    const session = (req as any).session as SessionRow;
    if (!session.totp_enabled) return res.status(400).json({ message: 'គណនីនេះមិនទាន់បើក 2FA ទេ។' });
    const code = String(req.body?.code || '').replace(/\s/g, '');
    if (!code) return res.status(400).json({ message: 'សូមបញ្ចូលលេខកូដ។' });

    const result = await pool.query<{ totp_secret_encrypted: string | null; backup_codes_hashes: string[] }>(
      `SELECT totp_secret_encrypted, backup_codes_hashes FROM users WHERE id=$1`, [session.user_id]
    );
    const encrypted = result.rows[0]?.totp_secret_encrypted;
    if (!encrypted) return res.status(400).json({ message: 'មិនមាន Google Authenticator secret ទេ។' });

    let ok = false;
    if (/^\d{6}$/.test(code)) {
      const secret = decrypt(encrypted);
      ok = speakeasy.totp.verify({ secret, encoding: 'base32', token: code, window: 1 });
    }

    if (!ok && code.includes('-')) {
      const hashes = result.rows[0]?.backup_codes_hashes || [];
      for (let i = 0; i < hashes.length; i++) {
        if (await bcrypt.compare(code.toUpperCase(), hashes[i])) {
          hashes.splice(i, 1);
          await pool.query(`UPDATE users SET backup_codes_hashes=$2 WHERE id=$1`, [session.user_id, hashes]);
          ok = true;
          break;
        }
      }
    }

    if (!ok) return res.status(401).json({ message: 'លេខកូដមិនត្រឹមត្រូវ ឬផុតកំណត់។' });

    await pool.query(`UPDATE sessions SET two_factor_verified=true WHERE id=$1`, [session.id]);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'មិនអាចផ្ទៀងផ្ទាត់បានទេ។' });
  }
});

app.post('/api/auth/2fa/setup', requireFullyAuthenticated, async (req, res) => {
  try {
    const session = (req as any).session as SessionRow;
    if (session.totp_enabled) return res.status(400).json({ message: 'Google Authenticator ត្រូវបានបើករួចហើយ។' });

    const secret = speakeasy.generateSecret({ length: 20, name: `${session.email}`, issuer: 'Khmer Secure Website' });
    const encrypted = encrypt(secret.base32);
    await pool.query(`UPDATE users SET totp_secret_encrypted=$2 WHERE id=$1`, [session.user_id, encrypted]);
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url || '');

    res.json({ ok: true, qrDataUrl, manualKey: secret.base32 });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'មិនអាចបង្កើត QR Code បានទេ។' });
  }
});

app.post('/api/auth/2fa/enable', requireFullyAuthenticated, async (req, res) => {
  try {
    const session = (req as any).session as SessionRow;
    if (session.totp_enabled) return res.status(400).json({ message: '2FA ត្រូវបានបើករួចហើយ។' });
    const code = String(req.body?.code || '').replace(/\s/g, '');
    const result = await pool.query<{ totp_secret_encrypted: string | null }>(
      `SELECT totp_secret_encrypted FROM users WHERE id=$1`, [session.user_id]
    );
    const encrypted = result.rows[0]?.totp_secret_encrypted;
    if (!encrypted) return res.status(400).json({ message: 'សូមចាប់ផ្តើម setup 2FA មុន។' });
    const secret = decrypt(encrypted);
    const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token: code, window: 1 });
    if (!ok) return res.status(401).json({ message: 'កូដមិនត្រឹមត្រូវ។' });

    const backupCodes: string[] = Array.from({ length: 8 }, () => `${randomToken(5).slice(0, 5)}-${randomToken(5).slice(0, 5)}`.toUpperCase());
    await pool.query(`UPDATE users SET totp_enabled=true, updated_at=NOW() WHERE id=$1`, [session.user_id]);
    const hashes = await Promise.all(backupCodes.map((item) => bcrypt.hash(item, 12)));
    await pool.query(`UPDATE users SET backup_codes_hashes=$2 WHERE id=$1`, [session.user_id, hashes]);
    await pool.query(`UPDATE sessions SET two_factor_verified=true WHERE id=$1`, [session.id]);

    res.json({ ok: true, backupCodes });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'មិនអាចបើក 2FA បានទេ។' });
  }
});

app.post('/api/auth/2fa/disable', requireFullyAuthenticated, async (req, res) => {
  try {
    const session = (req as any).session as SessionRow;
    const code = String(req.body?.code || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ message: 'សូមបញ្ចូលលេខ 6 ខ្ទង់ពី Authenticator។' });
    const result = await pool.query<{ totp_secret_encrypted: string | null }>(`SELECT totp_secret_encrypted FROM users WHERE id=$1`, [session.user_id]);
    const encrypted = result.rows[0]?.totp_secret_encrypted;
    if (!encrypted) return res.status(400).json({ message: '2FA មិនបានកំណត់ទេ។' });
    const secret = decrypt(encrypted);
    const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token: code, window: 1 });
    if (!ok) return res.status(401).json({ message: 'កូដមិនត្រឹមត្រូវ។' });
    await pool.query(`UPDATE users SET totp_enabled=false, totp_secret_encrypted=NULL, backup_codes_hashes=NULL, updated_at=NOW() WHERE id=$1`, [session.user_id]);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'មិនអាចបិទ 2FA បានទេ។' });
  }
});

app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error(error);
  res.status(500).json({ message: 'មានបញ្ហាជាមួយ server។' });
});

export default app;
