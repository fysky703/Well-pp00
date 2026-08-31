import express, { Request, Response, NextFunction } from 'express';
import { Pool } from 'pg';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';

export const app = express();

// ==========================================
// 1. DATABASE CONNECTION (Neon PostgreSQL)
// ==========================================
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('[DB] Unexpected error on idle client:', err.message);
});

// ==========================================
// 2. GOOGLE OAUTH CLIENT
// ==========================================
const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI || `${process.env.APP_URL || ''}/api/auth/google/callback`
);

// ==========================================
// 3. MIDDLEWARE (Zero external dependencies)
// ==========================================
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// Built-in Native CORS Middleware (No external 'cors' package needed)
app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin as string;
  const allowedOrigin = process.env.APP_URL || origin || '*';
  
  res.header('Access-Control-Allow-Origin', origin || allowedOrigin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cookie');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// Built-in Cookie Parser
function getCookie(req: Request, name: string): string | null {
  const rawCookie = req.headers.cookie;
  if (!rawCookie) return null;
  const match = rawCookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
  return match ? decodeURIComponent(match[3]) : null;
}

// Helper: Hash Session Token with SHA-256
function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Interface for Authenticated Request
export interface AuthRequest extends Request {
  user?: {
    user_id: string;
    email: string;
    name: string;
    avatar_url: string;
    google_id: string;
  };
  sessionId?: string;
}

// Security Middleware: Require Valid Session
export async function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  try {
    const sessionToken = getCookie(req, 'session_token') || req.headers.authorization?.replace('Bearer ', '');
    
    if (!sessionToken) {
      return res.status(401).json({ error: 'Unauthorized: Authentication required' });
    }

    const tokenHash = hashToken(sessionToken);
    const query = `
      SELECT s.id as session_id, s.user_id, u.email, u.name, u.avatar_url, u.google_id
      FROM user_sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.session_token_hash = $1 
        AND s.revoked_at IS NULL 
        AND s.expires_at > NOW()
    `;
    const result = await pool.query(query, [tokenHash]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Unauthorized: Session expired or revoked' });
    }

    // Update last_active_at asynchronously in the background
    pool.query('UPDATE user_sessions SET last_active_at = NOW() WHERE id = $1', [result.rows[0].session_id]).catch(() => {});

    req.user = result.rows[0];
    req.sessionId = result.rows[0].session_id;
    next();
  } catch (err: any) {
    console.error('[Auth Error]:', err.message);
    return res.status(500).json({ error: 'Internal authentication error' });
  }
}



// ==========================================
// 4B. RECOVERY CODES
// ==========================================
function normalizeRecoveryCode(code: string): string {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}
function formatRecoveryCode(raw: string): string {
  return raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 12);
}
function createRecoveryCode(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  const bytes = crypto.randomBytes(12);
  for (let i = 0; i < 12; i++) out += alphabet[bytes[i] % alphabet.length];
  return formatRecoveryCode(out);
}
async function createSessionForUser(userId: string, req: Request, res: Response) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const ua = String(req.headers['user-agent'] || '');
  await pool.query(`INSERT INTO user_sessions (user_id, session_token_hash, device_name, device_type, browser, operating_system, user_agent, expires_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [userId, hashToken(rawToken), /mobile|android|iphone/i.test(ua) ? 'Mobile Phone' : 'Browser', /mobile|android|iphone/i.test(ua) ? 'phone' : 'desktop', 'Browser', 'Unknown OS', ua, expiresAt]);
  const secure = process.env.NODE_ENV === 'production' ? 'Secure; ' : '';
  res.setHeader('Set-Cookie', `session_token=${rawToken}; Path=/; HttpOnly; ${secure}SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}`);
}

app.get('/api/recovery-codes/status', requireAuth, async (req: AuthRequest, res: Response) => {
  const r = await pool.query('SELECT COUNT(*)::int AS count FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL AND replaced_at IS NULL', [req.user!.user_id]);
  res.json({ activeCodes: r.rows[0].count });
});

app.post('/api/recovery-codes/generate', requireAuth, async (req: AuthRequest, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE recovery_codes SET replaced_at=NOW() WHERE user_id=$1 AND used_at IS NULL AND replaced_at IS NULL', [req.user!.user_id]);
    const codes: string[] = [];
    for (let i=0;i<10;i++) {
      let code = createRecoveryCode();
      // extremely unlikely collision; retry safely if it happens
      let inserted = false;
      while (!inserted) {
        const r = await client.query('INSERT INTO recovery_codes (user_id,code_hash) VALUES ($1,$2) ON CONFLICT (code_hash) DO NOTHING RETURNING id', [req.user!.user_id, hashToken(normalizeRecoveryCode(code))]);
        if (r.rowCount) inserted = true; else code = createRecoveryCode();
      }
      codes.push(code);
    }
    await client.query('COMMIT');
    res.json({ codes, warning: 'Each recovery code works once. Save them now; they cannot be shown again.' });
  } catch (e:any) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Failed to generate recovery codes' }); }
  finally { client.release(); }
});

// Sign in to this application without Google OAuth by proving possession of a recovery code.
app.post('/api/auth/recovery', async (req: Request, res: Response) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const normalized = normalizeRecoveryCode(String(req.body?.code || ''));
  if (!email || normalized.length !== 12) return res.status(400).json({ error: 'Email and a valid recovery code are required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [email]);
    if (!user.rows[0]) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Invalid recovery credentials' }); }
    const used = await client.query(`UPDATE recovery_codes SET used_at=NOW() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL AND replaced_at IS NULL RETURNING id`, [user.rows[0].id, hashToken(normalized)]);
    if (!used.rowCount) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Invalid or already used recovery code' }); }
    await client.query('COMMIT');
    await createSessionForUser(user.rows[0].id, req, res);
    res.json({ success: true, message: 'Recovery sign-in successful. This code is now consumed.' });
  } catch (e:any) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Recovery sign-in failed' }); }
  finally { client.release(); }
});


// ==========================================
// RECOVERY CODES (one-time account recovery)
// ==========================================
const RECOVERY_CODE_COUNT = 10;
function normalizeRecoveryCode(value: string): string {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}
function makeRecoveryCode(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const raw = Array.from(crypto.randomBytes(10), b => alphabet[b % alphabet.length]).join('');
  return raw.slice(0, 5) + '-' + raw.slice(5);
}
function hashRecoveryCode(code: string): string {
  return crypto.createHash('sha256').update(normalizeRecoveryCode(code)).digest('hex');
}
async function createSessionForUser(userId: string, req: Request, res: Response) {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const ua = String(req.headers['user-agent'] || '');
  const isMobile = /mobile|iphone|android/i.test(ua);
  const isTablet = /ipad|tablet/i.test(ua);
  const deviceType = isTablet ? 'tablet' : isMobile ? 'phone' : 'desktop';
  const deviceName = isMobile ? 'Mobile Phone' : isTablet ? 'Tablet' : 'Desktop Browser';
  let browser = 'Browser'; if (/chrome/i.test(ua)) browser='Chrome'; else if (/safari/i.test(ua)) browser='Safari'; else if (/firefox/i.test(ua)) browser='Firefox'; else if (/edge/i.test(ua)) browser='Edge';
  let os = 'Unknown OS'; if (/android/i.test(ua)) os='Android'; else if (/iphone|ipad|ios/i.test(ua)) os='iOS'; else if (/windows/i.test(ua)) os='Windows'; else if (/macintosh|mac os x/i.test(ua)) os='macOS'; else if (/linux/i.test(ua)) os='Linux';
  await pool.query(`INSERT INTO user_sessions (user_id, session_token_hash, device_name, device_type, browser, operating_system, user_agent, ip_address, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [userId, tokenHash, deviceName, deviceType, browser, os, ua, req.ip || null, expiresAt]);
  const isProduction = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', `session_token=${rawToken}; Path=/; HttpOnly; ${isProduction ? 'Secure;' : ''} SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}`);
}

app.get('/api/recovery-codes/status', requireAuth, async (req: AuthRequest, res: Response) => {
  const result = await pool.query('SELECT COUNT(*)::int AS remaining FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL AND revoked_at IS NULL', [req.user!.user_id]);
  res.json({ remaining: result.rows[0].remaining });
});

app.post('/api/recovery-codes/generate', requireAuth, async (req: AuthRequest, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE recovery_codes SET revoked_at=NOW() WHERE user_id=$1 AND used_at IS NULL AND revoked_at IS NULL', [req.user!.user_id]);
    const codes = Array.from({ length: RECOVERY_CODE_COUNT }, makeRecoveryCode);
    for (const code of codes) await client.query('INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1,$2)', [req.user!.user_id, hashRecoveryCode(code)]);
    await client.query('COMMIT');
    res.json({ codes, count: codes.length, warning: 'Save these codes now. They will not be shown again.' });
  } catch (e: any) { await client.query('ROLLBACK'); res.status(500).json({ error: 'Failed to generate recovery codes' }); }
  finally { client.release(); }
});

app.post('/api/auth/recovery-code', async (req: Request, res: Response) => {
  const code = normalizeRecoveryCode(req.body?.code);
  if (code.length !== 10) return res.status(400).json({ error: 'Invalid recovery code format' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(`SELECT id,user_id FROM recovery_codes WHERE code_hash=$1 AND used_at IS NULL AND revoked_at IS NULL FOR UPDATE`, [hashRecoveryCode(code)]);
    if (!found.rows[0]) { await client.query('ROLLBACK'); return res.status(401).json({ error: 'Invalid, expired, or already used recovery code' }); }
    await client.query('UPDATE recovery_codes SET used_at=NOW() WHERE id=$1', [found.rows[0].id]);
    await client.query('COMMIT');
    await createSessionForUser(found.rows[0].user_id, req, res);
    res.json({ success: true });
  } catch (e: any) { await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({ error: 'Recovery login failed' }); }
  finally { client.release(); }
});

// ==========================================
// 4. HEALTH CHECK
// ==========================================
app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    const dbTest = await pool.query('SELECT NOW()');
    res.json({
      status: 'ok',
      dbConnected: true,
      time: dbTest.rows[0].now
    });
  } catch (e: any) {
    res.status(500).json({
      status: 'degraded',
      dbConnected: false,
      error: e.message
    });
  }
});

// ==========================================
// 5. GOOGLE OAUTH FLOW
// ==========================================
app.get('/api/auth/google', (_req: Request, res: Response) => {
  const url = googleClient.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email'
    ],
    prompt: 'consent'
  });
  res.redirect(url);
});

app.get('/api/auth/google/callback', async (req: Request, res: Response) => {
  const code = req.query.code as string;
  if (!code) {
    return res.status(400).send('Google Authorization code missing');
  }

  try {
    const { tokens } = await googleClient.getToken(code);
    googleClient.setCredentials(tokens);

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token!,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();

    if (!payload || !payload.sub || !payload.email) {
      return res.status(400).send('Invalid Google user profile');
    }

    // Upsert user in database
    const userRes = await pool.query(`
      INSERT INTO users (google_id, email, name, avatar_url)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (google_id) DO UPDATE 
      SET name = EXCLUDED.name, avatar_url = EXCLUDED.avatar_url, updated_at = NOW()
      RETURNING id, email, name, avatar_url
    `, [payload.sub, payload.email, payload.name || payload.email, payload.picture || '']);

    const user = userRes.rows[0];

    // Create session token
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 Days

    // Device parsing
    const ua = req.headers['user-agent'] || '';
    const isMobile = /mobile|iphone|android/i.test(ua);
    const isTablet = /ipad|tablet/i.test(ua);
    const deviceType = isTablet ? 'tablet' : isMobile ? 'phone' : 'desktop';
    const deviceName = isMobile ? 'Mobile Phone' : isTablet ? 'Tablet' : 'Desktop Browser';

    let browser = 'Browser';
    if (/chrome/i.test(ua)) browser = 'Chrome';
    else if (/safari/i.test(ua)) browser = 'Safari';
    else if (/firefox/i.test(ua)) browser = 'Firefox';
    else if (/edge/i.test(ua)) browser = 'Edge';

    let os = 'Unknown OS';
    if (/android/i.test(ua)) os = 'Android';
    else if (/iphone|ipad|ios/i.test(ua)) os = 'iOS';
    else if (/windows/i.test(ua)) os = 'Windows';
    else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
    else if (/linux/i.test(ua)) os = 'Linux';

    await pool.query(`
      INSERT INTO user_sessions (user_id, session_token_hash, device_name, device_type, browser, operating_system, user_agent, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [user.id, tokenHash, deviceName, deviceType, browser, os, ua, expiresAt]);

    // Set secure cookie
    const isProduction = process.env.NODE_ENV === 'production';
    res.setHeader('Set-Cookie', [
      `session_token=${rawToken}; Path=/; HttpOnly; ${isProduction ? 'Secure;' : ''} SameSite=Lax; Max-Age=${30 * 24 * 60 * 60}`
    ]);

    // Redirect to frontend app
    res.redirect('/');
  } catch (error: any) {
    console.error('[OAuth Callback Error]:', error);
    res.status(500).send(`Authentication failed: ${error.message || 'Unknown error'}`);
  }
});

// ==========================================
// 6. USER PROFILE & VAULT STATUS
// ==========================================
app.get('/api/me', requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const vaultRes = await pool.query(
      'SELECT pin_length, updated_at FROM vaults WHERE user_id = $1',
      [req.user!.user_id]
    );

    const hasVault = vaultRes.rows.length > 0;
    res.json({
      user: {
        id: req.user!.user_id,
        name: req.user!.name,
        email: req.user!.email,
        avatarUrl: req.user!.avatar_url
      },
      hasVault,
      pinLength: hasVault ? vaultRes.rows[0].pin_length : null
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 7. VAULT OPERATIONS (Zero-Knowledge Sync)
// ==========================================
app.post('/api/vault/create', requireAuth, async (req: AuthRequest, res: Response) => {
  const { pinHash, pinSalt, pinLength, encryptedData, encryptionMetadata } = req.body;
  
  if (!pinHash || !pinSalt || !pinLength) {
    return res.status(400).json({ error: 'Missing required parameters (pinHash, pinSalt, pinLength)' });
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
    `, [
      req.user!.user_id,
      pinHash,
      pinSalt,
      pinLength,
      encryptedData || '',
      JSON.stringify(encryptionMetadata || {})
    ]);

    res.json({ success: true, message: 'Vault initialized successfully' });
  } catch (err: any) {
    console.error('[Vault Create Error]:', err);
    res.status(500).json({ error: 'Failed to create vault' });
  }
});

app.get('/api/vault', requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const result = await pool.query(
      'SELECT pin_hash, pin_salt, pin_length, encrypted_data, encryption_metadata FROM vaults WHERE user_id = $1',
      [req.user!.user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Vault not found' });
    }

    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch vault' });
  }
});

app.post('/api/vault/sync', requireAuth, async (req: AuthRequest, res: Response) => {
  const { encryptedData, encryptionMetadata } = req.body;
  try {
    await pool.query(`
      UPDATE vaults 
      SET encrypted_data = $1, 
          encryption_metadata = $2, 
          updated_at = NOW() 
      WHERE user_id = $3
    `, [
      encryptedData,
      JSON.stringify(encryptionMetadata || {}),
      req.user!.user_id
    ]);

    res.json({ success: true, message: 'Vault synced successfully' });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to sync vault' });
  }
});

app.post('/api/vault/change-pin', requireAuth, async (req: AuthRequest, res: Response) => {
  const { newPinHash, newPinSalt, newPinLength, reEncryptedData, newEncryptionMetadata } = req.body;
  
  if (!newPinHash || !newPinSalt || !newPinLength) {
    return res.status(400).json({ error: 'Missing new PIN data' });
  }

  try {
    await pool.query(`
      UPDATE vaults 
      SET pin_hash = $1,
          pin_salt = $2,
          pin_length = $3,
          encrypted_data = $4,
          encryption_metadata = $5,
          updated_at = NOW()
      WHERE user_id = $6
    `, [
      newPinHash,
      newPinSalt,
      newPinLength,
      reEncryptedData,
      JSON.stringify(newEncryptionMetadata || {}),
      req.user!.user_id
    ]);

    res.json({ success: true, message: 'Vault PIN updated successfully' });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to change PIN' });
  }
});

// ==========================================
// 8. ACTIVE SESSIONS & REMOTE LOGOUT
// ==========================================
app.get('/api/sessions', requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT id, device_name, device_type, browser, operating_system, last_active_at, created_at,
             (id = $1) as is_current_device
      FROM user_sessions
      WHERE user_id = $2 
        AND revoked_at IS NULL 
        AND expires_at > NOW()
      ORDER BY last_active_at DESC
    `, [req.sessionId, req.user!.user_id]);

    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve sessions' });
  }
});

app.delete('/api/sessions/:id', requireAuth, async (req: AuthRequest, res: Response) => {
  const targetSessionId = req.params.id;
  try {
    await pool.query(
      'UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2',
      [targetSessionId, req.user!.user_id]
    );

    res.json({ success: true, message: 'Device session revoked' });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to revoke device session' });
  }
});

app.post('/api/sessions/logout-others', requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    await pool.query(
      'UPDATE user_sessions SET revoked_at = NOW() WHERE user_id = $1 AND id != $2',
      [req.user!.user_id, req.sessionId]
    );

    res.json({ success: true, message: 'All other devices logged out' });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to logout other sessions' });
  }
});

app.post('/api/auth/logout', requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    await pool.query('UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1', [req.sessionId]);
    res.setHeader('Set-Cookie', ['session_token=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax']);
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err: any) {
    res.status(500).json({ error: 'Logout failed' });
  }
});
// បន្ថែមនៅខាងក្រោម app.get('/api/me', ...)

// គាំទ្រទាំង 2 ទម្រង់ URL
app.get('/api/auth/me', requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    const vaultRes = await pool.query(
      'SELECT pin_length, updated_at FROM vaults WHERE user_id = $1',
      [req.user!.user_id]
    );

    const hasVault = vaultRes.rows.length > 0;
    res.json({
      user: {
        id: req.user!.user_id,
        name: req.user!.name,
        email: req.user!.email,
        avatarUrl: req.user!.avatar_url
      },
      hasVault,
      pinLength: hasVault ? vaultRes.rows[0].pin_length : null
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GMAIL CONNECTIONS
function makeOAuthState(userId:string){const payload=Buffer.from(JSON.stringify({userId,exp:Date.now()+600000})).toString('base64url');const secret=process.env.OAUTH_STATE_SECRET||process.env.GOOGLE_CLIENT_SECRET||'development-only-change-me';return payload+'.'+crypto.createHmac('sha256',secret).update(payload).digest('base64url');}
function readOAuthState(state:string){const [payload,sig]=state.split('.');if(!payload||!sig)return null;const secret=process.env.OAUTH_STATE_SECRET||process.env.GOOGLE_CLIENT_SECRET||'development-only-change-me';const expected=crypto.createHmac('sha256',secret).update(payload).digest('base64url');if(sig!==expected)return null;const data=JSON.parse(Buffer.from(payload,'base64url').toString());return data.exp>Date.now()?data:null;}
app.get('/api/gmail/connect',requireAuth,(req:AuthRequest,res:Response)=>{res.redirect(googleClient.generateAuthUrl({access_type:'offline',prompt:'consent select_account',scope:['https://www.googleapis.com/auth/userinfo.email','https://www.googleapis.com/auth/gmail.readonly'],state:makeOAuthState(req.user!.user_id)}));});
app.get('/api/gmail/callback',async(req:Request,res:Response)=>{try{const state=readOAuthState(String(req.query.state||''));const code=String(req.query.code||'');if(!state||!code)return res.status(400).send('Invalid Gmail authorization');const client=new OAuth2Client(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET,process.env.GMAIL_REDIRECT_URI||`${process.env.APP_URL}/api/gmail/callback`);const {tokens}=await client.getToken(code);client.setCredentials(tokens);const profile=await google.oauth2({version:'v2',auth:client}).userinfo.get();const email=profile.data.email;if(!email)return res.status(400).send('Email not returned');await pool.query(`INSERT INTO gmail_accounts (user_id,email,access_token,refresh_token,token_expiry) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (user_id,email) DO UPDATE SET access_token=EXCLUDED.access_token,refresh_token=COALESCE(EXCLUDED.refresh_token,gmail_accounts.refresh_token),token_expiry=EXCLUDED.token_expiry,updated_at=NOW()`,[state.userId,email,tokens.access_token||null,tokens.refresh_token||null,tokens.expiry_date?new Date(tokens.expiry_date):null]);res.redirect('/');}catch(e:any){console.error(e);res.status(500).send('Gmail authorization failed');}});
app.get('/api/gmail/accounts',requireAuth,async(req:AuthRequest,res:Response)=>{const r=await pool.query('SELECT id,email,created_at FROM gmail_accounts WHERE user_id=$1 ORDER BY created_at DESC',[req.user!.user_id]);res.json({accounts:r.rows});});
app.get('/api/gmail/inbox',requireAuth,async(req:AuthRequest,res:Response)=>{try{const r=await pool.query('SELECT * FROM gmail_accounts WHERE id=$1 AND user_id=$2',[String(req.query.accountId||''),req.user!.user_id]);if(!r.rows[0])return res.status(404).json({error:'Gmail account not found'});const a=r.rows[0];const client=new OAuth2Client(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET);client.setCredentials({access_token:a.access_token,refresh_token:a.refresh_token,expiry_date:a.token_expiry?new Date(a.token_expiry).getTime():undefined});const gmail=google.gmail({version:'v1',auth:client});const list=await gmail.users.messages.list({userId:'me',labelIds:['INBOX'],maxResults:30});const messages=await Promise.all((list.data.messages||[]).map(async m=>{const d=await gmail.users.messages.get({userId:'me',id:m.id!,format:'metadata',metadataHeaders:['From','Subject','Date']});const h=d.data.payload?.headers||[];const get=(n:string)=>h.find(x=>x.name?.toLowerCase()===n.toLowerCase())?.value||'';return{id:m.id,threadId:m.threadId,from:get('From'),subject:get('Subject')||'(No subject)',date:get('Date'),snippet:d.data.snippet||''};}));res.json({messages});}catch(e:any){console.error(e);res.status(500).json({error:e.message||'Failed to load inbox'});}});
