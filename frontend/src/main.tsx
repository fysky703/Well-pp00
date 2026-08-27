import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type User = {
  id: string;
  email: string;
  name: string;
  avatarUrl: string | null;
  twoFactorEnabled: boolean;
};

type Me = {
  authenticated: boolean;
  requiresTwoFactor: boolean;
  user: User;
};

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || 'មានបញ្ហា');
  return data as T;
}

function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [totpSetup, setTotpSetup] = useState<{ qrDataUrl: string; manualKey: string } | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const oauthError = params.get('error');
    if (oauthError) setError('ការចូល Google មិនបានជោគជ័យទេ។ សូមព្យាយាមម្តងទៀត។');
    loadMe();
    if (params.has('auth') || params.has('error')) window.history.replaceState({}, '', '/');
  }, []);

  async function loadMe() {
    try {
      setMe(await api<Me>('/api/auth/me'));
    } catch {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }

  async function setup2fa() {
    setError('');
    try {
      const data = await api<{ qrDataUrl: string; manualKey: string }>('/api/auth/2fa/setup', { method: 'POST', body: '{}' });
      setTotpSetup(data);
    } catch (e) { setError((e as Error).message); }
  }

  async function logout() {
    await api('/api/auth/logout', { method: 'POST', body: '{}' }).catch(() => undefined);
    setMe(null); setTotpSetup(null); setBackupCodes(null);
  }

  if (loading) return <div className="page center"><div className="loader" /><p>កំពុងផ្ទៀងផ្ទាត់...</p></div>;

  if (!me) {
    return <div className="page"><div className="card auth-card">
      <div className="logo">🔐</div>
      <h1>ចូលប្រើគណនី</h1>
      <p className="muted">ការពារគណនីរបស់អ្នកដោយ Google Login និង Google Authenticator</p>
      {error && <div className="alert error">{error}</div>}
      <a className="google-btn" href="/api/auth/google"><span className="google-icon">G</span> បន្តជាមួយ Google</a>
      <div className="security-note"><b>សុវត្ថិភាព</b><span>យើងប្រើ OAuth របស់ Google និងមិនរក្សាទុក password Google របស់អ្នកឡើយ។</span></div>
    </div></div>;
  }

  if (me.requiresTwoFactor) {
    return <TwoFactorScreen onSuccess={loadMe} onLogout={logout} error={error} setError={setError} />;
  }

  return <div className="page"><div className="card dashboard">
    <div className="topbar">
      <div><div className="eyebrow">គណនីសុវត្ថិភាព</div><h1>សួស្តី, {me.user.name} 👋</h1></div>
      <button className="ghost" onClick={logout}>ចាកចេញ</button>
    </div>
    <div className="profile">
      {me.user.avatarUrl ? <img src={me.user.avatarUrl} className="avatar" /> : <div className="avatar placeholder">{me.user.name.slice(0,1).toUpperCase()}</div>}
      <div><div className="name">{me.user.name}</div><div className="muted">{me.user.email}</div></div>
    </div>
    {error && <div className="alert error">{error}</div>}
    <div className="section">
      <div className="section-title"><div><h2>Google Authenticator</h2><p className="muted">បន្ថែមការពារមួយជាន់ទៀតសម្រាប់ Login</p></div><span className={me.user.twoFactorEnabled ? 'badge success' : 'badge'}>{me.user.twoFactorEnabled ? 'បានបើក' : 'មិនទាន់បើក'}</span></div>
      {!me.user.twoFactorEnabled ? <>
        <p>នៅពេលអ្នក Login ជាមួយ Google រួច Website នឹងស្នើលេខ 6 ខ្ទង់ពី Google Authenticator។</p>
        {!totpSetup ? <button className="primary" onClick={setup2fa}>រៀបចំ Google Authenticator</button> : <Setup2FA data={totpSetup} onDone={(codes) => { setBackupCodes(codes); setTotpSetup(null); loadMe(); }} setError={setError} />}
      </> : <Disable2FA setError={setError} onDone={loadMe} />}
    </div>
    {backupCodes && <BackupCodes codes={backupCodes} onClose={() => setBackupCodes(null)} />}
  </div></div>;
}

function Setup2FA({ data, onDone, setError }: { data: { qrDataUrl: string; manualKey: string }, onDone: (codes: string[]) => void, setError: (s: string) => void }) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  async function enable() {
    setBusy(true); setError('');
    try { const res = await api<{ backupCodes: string[] }>('/api/auth/2fa/enable', { method: 'POST', body: JSON.stringify({ code }) }); onDone(res.backupCodes); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  return <div className="setup-grid">
    <div className="qr-wrap"><img src={data.qrDataUrl} className="qr" alt="QR Code Google Authenticator" /></div>
    <div>
      <ol><li>បើក Google Authenticator នៅលើទូរស័ព្ទ</li><li>ចុច <b>+</b> → Scan QR Code</li><li>ស្កេន QR ខាងឆ្វេង</li></ol>
      <p className="muted small">បើស្កេនមិនបាន អ្នកអាចបញ្ចូល Key ដោយដៃ៖</p><code className="secret">{data.manualKey}</code>
      <label>លេខ 6 ខ្ទង់</label><input inputMode="numeric" maxLength={6} value={code} onChange={e => setCode(e.target.value.replace(/\D/g,'').slice(0,6))} placeholder="123456" />
      <button className="primary" disabled={busy || code.length !== 6} onClick={enable}>{busy ? 'កំពុងរក្សាទុក...' : 'បើក 2FA'}</button>
    </div>
  </div>;
}

function TwoFactorScreen({ onSuccess, onLogout, error, setError }: { onSuccess: () => Promise<void> | void; onLogout: () => Promise<void>; error: string; setError: (s: string) => void }) {
  const [code, setCode] = useState(''); const [busy, setBusy] = useState(false);
  async function verify() { setBusy(true); setError(''); try { await api('/api/auth/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) }); await onSuccess(); } catch(e){ setError((e as Error).message); } finally { setBusy(false); } }
  return <div className="page"><div className="card auth-card">
    <div className="logo">🛡️</div><h1>ផ្ទៀងផ្ទាត់ 2FA</h1><p className="muted">បើក Google Authenticator ហើយបញ្ចូលលេខ 6 ខ្ទង់។ អ្នកក៏អាចប្រើ Backup Code ម្តងមួយបាន។</p>
    {error && <div className="alert error">{error}</div>}
    <input className="otp" inputMode="numeric" value={code} onChange={e => setCode(e.target.value.replace(/[^0-9-]/g,'').slice(0,20))} placeholder="123456" autoFocus />
    <button className="primary" disabled={busy || !code} onClick={verify}>{busy ? 'កំពុងផ្ទៀងផ្ទាត់...' : 'ផ្ទៀងផ្ទាត់'}</button>
    <button className="ghost full" onClick={onLogout}>ចាកចេញ</button>
  </div></div>;
}

function Disable2FA({ setError, onDone }: { setError: (s: string) => void; onDone: () => Promise<void> | void }) {
  const [open, setOpen] = useState(false); const [code, setCode] = useState(''); const [busy, setBusy] = useState(false);
  async function disable(){setBusy(true); setError(''); try{await api('/api/auth/2fa/disable',{method:'POST',body:JSON.stringify({code})}); await onDone(); setOpen(false);}catch(e){setError((e as Error).message);}finally{setBusy(false)}}
  return <div><p>Google Authenticator កំពុងការពារគណនីរបស់អ្នក។</p>{!open ? <button className="danger" onClick={()=>setOpen(true)}>បិទ 2FA</button> : <div className="inline-form"><input inputMode="numeric" maxLength={6} value={code} onChange={e=>setCode(e.target.value.replace(/\D/g,'').slice(0,6))} placeholder="លេខ 6 ខ្ទង់" /><button className="danger" disabled={busy || code.length!==6} onClick={disable}>{busy?'...':'បិទ 2FA'}</button><button className="ghost" onClick={()=>setOpen(false)}>បោះបង់</button></div>}</div>;
}

function BackupCodes({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  return <div className="modal"><div className="modal-card"><h2>រក្សាទុក Backup Codes</h2><p className="muted">កូដទាំងនេះបង្ហាញតែពេលនេះ។ រក្សាទុកនៅកន្លែងសុវត្ថិភាព។</p><div className="codes">{codes.map(c=><code key={c}>{c}</code>)}</div><button className="primary" onClick={()=>{navigator.clipboard?.writeText(codes.join('\n')); onClose();}}>ចម្លង និងបិទ</button></div></div>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
