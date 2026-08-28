import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { Pool } from 'pg';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';

export const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.APP_URL || true,
  credentials: true
}));

// Helper: Hash Session Token
function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Middleware: Authenticate User Session
export async function requireAuth(req: Request & { user?: any; sessionId?: string }, res: Response, next: NextFunction) {
  try {
    const sessionToken = req.cookies?.session_token || req.headers.authorization?.replace('Bearer ', '');
    if (!sessionToken) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const tokenHash = hashToken(sessionToken);
    const query = `
      SELECT s.id as session_id, s.user_id, u.email, u.name, u.avatar_url, u.google_id
      FROM user_sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.session_token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()
    `;
    const result = await pool.query(query, [tokenHash]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Session expired or revoked' });
    }

    // Update last_active_at asynchronously
    pool.query('UPDATE user_sessions SET last_active_at = NOW() WHERE id = $1', [result.rows[0].session_id]).catch(console.error);

    req.user = result.rows[0];
    req.sessionId = result.rows[0].session_id;
    next();
  } catch (err) {
    return res.status(500).json({ error: 'Internal auth error' });
  }
}

// 1. Google OAuth Flow
app.get('/api/auth/google', (req, res) => {
  const url = googleClient.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
    prompt: 'consent'
  });
  res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const code = req.query.code as string;
  if (!code) return res.status(400).send('Authorization code missing');

  try {
    const { tokens } = await googleClient.getToken(code);
    googleClient.setCredentials(tokens);

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token!,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload()!;

    // Upsert User
    const userRes = await pool.query(`
      INSERT INTO users (google_id, email, name, avatar_url)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (google_id) DO UPDATE 
      SET name = EXCLUDED.name, avatar_url = EXCLUDED.avatar_url, updated_at = NOW()
      RETURNING id, email, name, avatar_url
    `, [payload.sub, payload.email, payload.name, payload.picture]);

    const user = userRes.rows[0];

    // Create New Session
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    const ua = req.headers['user-agent'] || '';
    const isMobile = /mobile/i.test(ua);
    const isTablet = /tablet|ipad/i.test(ua);
    const deviceType = isTablet ? 'tablet' : isMobile ? 'phone' : 'desktop';
    const deviceName = isMobile ? 'Mobile Device' : 'Desktop Browser';

    await pool.query(`
      INSERT INTO user_sessions (user_id, session_token_hash, device_name, device_type, user_agent, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [user.id, tokenHash, deviceName, deviceType, ua, expiresAt]);

    res.cookie('session_token', rawToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: expiresAt
    });

    res.redirect('/');
  } catch (error) {
    console.error('OAuth error:', error);
    res.status(500).send('Authentication failed');
  }
});

// 2. Current User Profile
app.get('/api/me', requireAuth, async (req: any, res) => {
  const vaultRes = await pool.query('SELECT pin_length, updated_at FROM vaults WHERE user_id = $1', [req.user.user_id]);
  const hasVault = vaultRes.rows.length > 0;
  res.json({
    user: {
      id: req.user.user_id,
      name: req.user.name,
      email: req.user.email,
      avatarUrl: req.user.avatar_url
    },
    hasVault,
    pinLength: hasVault ? vaultRes.rows[0].pin_length : null
  });
});

// 3. Vault Operations (Zero Knowledge Encrypted Data Sync)
app.post('/api/vault/create', requireAuth, async (req: any, res) => {
  const { pinHash, pinSalt, pinLength, encryptedData, encryptionMetadata } = req.body;
  if (!pinHash || !pinSalt || !pinLength) {
    return res.status(400).json({ error: 'Missing required vault setup fields' });
  }

  try {
    await pool.query(`
      INSERT INTO vaults (user_id, pin_hash, pin_salt, pin_length, encrypted_data, encryption_metadata)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (user_id) DO UPDATE
      SET pin_hash = EXCLUDED.pin_hash,
          pin_salt = EXCLUDED.pin_salt,
          pin_length = EXCLUDED.pin_length,
          encrypted_data = EXCLUDED.encrypted_data,
          encryption_metadata = EXCLUDED.encryption_metadata,
          updated_at = NOW()
    `, [req.user.user_id, pinHash, pinSalt, pinLength, encryptedData || '', JSON.stringify(encryptionMetadata || {})]);

    res.json({ success: true, message: 'Vault initialized successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create vault' });
  }
});

app.get('/api/vault', requireAuth, async (req: any, res) => {
  try {
    const result = await pool.query('SELECT pin_hash, pin_salt, pin_length, encrypted_data, encryption_metadata FROM vaults WHERE user_id = $1', [req.user.user_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Vault not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve vault' });
  }
});

app.post('/api/vault/sync', requireAuth, async (req: any, res) => {
  const { encryptedData, encryptionMetadata } = req.body;
  try {
    await pool.query(`
      UPDATE vaults 
      SET encrypted_data = $1, encryption_metadata = $2, updated_at = NOW() 
      WHERE user_id = $3
    `, [encryptedData, JSON.stringify(encryptionMetadata), req.user.user_id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync vault' });
  }
});

// 4. Active Devices & Remote Logout
app.get('/api/sessions', requireAuth, async (req: any, res) => {
  try {
    const result = await pool.query(`
      SELECT id, device_name, device_type, browser, operating_system, last_active_at, created_at,
             (id = $1) as is_current_device
      FROM user_sessions
      WHERE user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY last_active_at DESC
    `, [req.sessionId, req.user.user_id]);

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

app.delete('/api/sessions/:id', requireAuth, async (req: any, res) => {
  const sessionId = req.params.id;
  try {
    await pool.query('UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2', [sessionId, req.user.user_id]);
    res.json({ success: true, message: 'Device logged out' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke session' });
  }
});

app.post('/api/sessions/logout-others', requireAuth, async (req: any, res) => {
  try {
    await pool.query('UPDATE user_sessions SET revoked_at = NOW() WHERE user_id = $1 AND id != $2', [req.user.user_id, req.sessionId]);
    res.json({ success: true, message: 'All other devices logged out' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke other sessions' });
  }
});

app.post('/api/auth/logout', requireAuth, async (req: any, res) => {
  await pool.query('UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1', [req.sessionId]);
  res.clearCookie('session_token');
  res.json({ success: true });
});