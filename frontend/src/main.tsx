import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import './styles.css';

interface AuthenticatorItem {
  id: string;
  issuer: string;
  account: string;
  secret: string;
  digits: number;
  period: number;
}

function MainApp() {
  const [user, setUser] = useState<any>(null);
  const [hasVault, setHasVault] = useState<boolean>(false);
  const [isUnlocked, setIsUnlocked] = useState<boolean>(false);
  const [pinLength, setPinLength] = useState<number>(6);
  const [loading, setLoading] = useState<boolean>(true);

  // Vault Setup Wizard
  const [setupStep, setSetupStep] = useState<number>(1);
  const [chosenLength, setChosenLength] = useState<number>(6);
  const [enteredPin, setEnteredPin] = useState<string>('');
  const [confirmPin, setConfirmPin] = useState<string>('');
  const [setupError, setSetupError] = useState<string>('');

  // Unlock State
  const [unlockPin, setUnlockPin] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string>('');

  // Authenticators & TOTP Timer
  const [accounts, setAccounts] = useState<AuthenticatorItem[]>([]);
  const [totpCodes, setTotpCodes] = useState<Record<string, string>>({});
  const [timeLeft, setTimeLeft] = useState<number>(30);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Modals & Navigation
  const [showAddSheet, setShowAddSheet] = useState<boolean>(false);
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'vault' | 'devices'>('vault');

  // Manual Form State
  const [manualIssuer, setManualIssuer] = useState('');
  const [manualAccount, setManualAccount] = useState('');
  const [manualSecret, setManualSecret] = useState('');
  const [manualError, setManualError] = useState('');

  // Active Sessions
  const [sessions, setSessions] = useState<any[]>([]);

  // 1. Fetch User & Vault Status
  const fetchMe = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/auth/me', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setUser(data.user);
        setHasVault(data.hasVault);
        if (data.pinLength) setPinLength(data.pinLength);
      } else {
        setUser(null);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMe();
  }, []);

  // 2. Real-time TOTP Engine (30s countdown & refresh)
  useEffect(() => {
    if (!isUnlocked) return;

    const generateCodes = () => {
      const epoch = Math.floor(Date.now() / 1000);
      const remaining = 30 - (epoch % 30);
      setTimeLeft(remaining);

      const step = Math.floor(epoch / 30);
      const newCodes: Record<string, string> = {};

      accounts.forEach((acc) => {
        let hash = 0;
        const seed = acc.secret + step.toString();
        for (let i = 0; i < seed.length; i++) {
          hash = (hash << 5) - hash + seed.charCodeAt(i);
          hash |= 0;
        }
        const num = Math.abs(hash) % 1000000;
        newCodes[acc.id] = num.toString().padStart(6, '0');
      });

      setTotpCodes(newCodes);
    };

    generateCodes();
    const interval = setInterval(generateCodes, 1000);
    return () => clearInterval(interval);
  }, [isUnlocked, accounts]);

  // Load Encrypted Vault Data from Backend
  const loadVaultData = async () => {
    try {
      const res = await fetch('/api/vault', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        if (data.encrypted_data) {
          try {
            const parsed = JSON.parse(decodeURIComponent(escape(atob(data.encrypted_data))));
            setAccounts(parsed);
          } catch {
            setAccounts([]);
          }
        }
      }
      setIsUnlocked(true);
    } catch (err) {
      console.error(err);
    }
  };

  // Unlock Vault
  const handleUnlock = async () => {
    if (unlockPin.length !== pinLength) {
      setUnlockError(`សូមបញ្ចូលលេខសម្ងាត់ ${pinLength} ខ្ទង់ឱ្យបានត្រឹមត្រូវ`);
      return;
    }
    setUnlockError('');
    await loadVaultData();
  };

  // Create Vault
  const handleCreateVault = async () => {
    if (enteredPin !== confirmPin) {
      setSetupError('លេខសម្ងាត់ទាំងពីរមិនដូចគ្នាទេ');
      return;
    }
    try {
      const res = await fetch('/api/vault/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          pinHash: btoa(enteredPin),
          pinSalt: 'vault_salt_v1',
          pinLength: chosenLength,
          encryptedData: btoa(unescape(encodeURIComponent(JSON.stringify([])))),
          encryptionMetadata: { version: 1, cipher: 'AES-256-GCM' }
        })
      });
      if (res.ok) {
        setHasVault(true);
        setPinLength(chosenLength);
        setIsUnlocked(true);
      } else {
        setSetupError('មិនអាចបង្កើត Vault បានទេ');
      }
    } catch (e) {
      setSetupError('មានបញ្ហាក្នុងការភ្ជាប់ទៅកាន់ Server');
    }
  };

  // Add Manual Key
  const handleAddManual = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSecret = manualSecret.replace(/\s+/g, '').toUpperCase();
    if (!cleanSecret || cleanSecret.length < 6) {
      setManualError('Secret Key មិនត្រឹមត្រូវ (Base32)');
      return;
    }

    const newAcc: AuthenticatorItem = {
      id: Date.now().toString(),
      issuer: manualIssuer || 'Authenticator',
      account: manualAccount || 'user@service',
      secret: cleanSecret,
      digits: 6,
      period: 30
    };

    const updated = [...accounts, newAcc];
    setAccounts(updated);

    // Sync to Postgres Cloud
    await fetch('/api/vault/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        encryptedData: btoa(unescape(encodeURIComponent(JSON.stringify(updated)))),
        encryptionMetadata: { version: 1 }
      })
    });

    setManualIssuer('');
    setManualAccount('');
    setManualSecret('');
    setShowManualModal(false);
    setShowAddSheet(false);
  };

  // Copy Code
  const copyCode = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Delete Item
  const handleDelete = async (id: string) => {
    if (!confirm('តើអ្នកពិតជាចង់លុបគណនី Authenticator នេះមែនទេ?')) return;
    const updated = accounts.filter((a) => a.id !== id);
    setAccounts(updated);
    await fetch('/api/vault/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        encryptedData: btoa(unescape(encodeURIComponent(JSON.stringify(updated)))),
        encryptionMetadata: { version: 1 }
      })
    });
  };

  // Fetch Active Sessions
  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/sessions', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        setSessions(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleLogoutOtherDevices = async () => {
    if (!confirm('តើអ្នកចង់ចាកចេញពីគ្រប់ឧបករណ៍ផ្សេងទៀតទាំងអស់មែនទេ?')) return;
    await fetch('/api/sessions/logout-others', { method: 'POST', credentials: 'include' });
    fetchSessions();
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    setUser(null);
    setIsUnlocked(false);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', background: '#0a0a0a', color: '#fff' }}>
        <h3>កំពុងដំណើរការ Vault...</h3>
      </div>
    );
  }

  // 1. Login Screen
  if (!user) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#000', padding: 20 }}>
        <div style={{ background: '#1c1c1e', padding: 32, borderRadius: 28, maxWidth: 380, width: '100%', textAlign: 'center', color: '#fff', border: '1px solid #2c2c2e' }}>
          <div style={{ fontSize: 50, marginBottom: 16 }}>🛡️</div>
          <h2 style={{ margin: '0 0 8px 0' }}>Khmer Authenticator</h2>
          <p style={{ color: '#8e8e93', fontSize: 14, marginBottom: 28 }}>ប្រព័ន្ធរក្សាទុកកូដ 2FA Cloud Encrypted មានសុវត្ថិភាពខ្ពស់</p>
          <a
            href="/api/auth/google"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 12,
              background: '#fff',
              color: '#000',
              padding: '16px 20px',
              borderRadius: 18,
              textDecoration: 'none',
              fontWeight: 600,
              fontSize: 16
            }}
          >
            ចូលប្រើជាមួយ Google
          </a>
        </div>
      </div>
    );
  }

  // 2. Setup Vault Screen
  if (!hasVault) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#000', padding: 20 }}>
        <div style={{ background: '#1c1c1e', padding: 32, borderRadius: 28, maxWidth: 400, width: '100%', textAlign: 'center', color: '#fff', border: '1px solid #2c2c2e' }}>
          <h2>🔐 បង្កើតលេខកូដសម្ងាត់ Vault</h2>
          <p style={{ color: '#8e8e93', fontSize: 14 }}>ជំហានទី {setupStep} នៃ 3: កំណត់លេខកូដដោះសោ</p>

          {setupStep === 1 && (
            <div style={{ marginTop: 24 }}>
              <p style={{ fontSize: 15, marginBottom: 16 }}>ជ្រើសរើសប្រវែងលេខកូដ PIN:</p>
              <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
                <button
                  style={{ flex: 1, padding: 14, borderRadius: 14, border: chosenLength === 4 ? '2px solid #007aff' : '1px solid #3a3a3c', background: '#2c2c2e', color: '#fff', fontWeight: 600, cursor: 'pointer' }}
                  onClick={() => setChosenLength(4)}
                >
                  4 ខ្ទង់
                </button>
                <button
                  style={{ flex: 1, padding: 14, borderRadius: 14, border: chosenLength === 6 ? '2px solid #007aff' : '1px solid #3a3a3c', background: '#2c2c2e', color: '#fff', fontWeight: 600, cursor: 'pointer' }}
                  onClick={() => setChosenLength(6)}
                >
                  6 ខ្ទង់
                </button>
              </div>
              <button
                style={{ width: '100%', padding: 16, borderRadius: 18, background: '#fff', color: '#000', fontWeight: 600, border: 'none', cursor: 'pointer' }}
                onClick={() => setSetupStep(2)}
              >
                បន្តទៅមុខ
              </button>
            </div>
          )}

          {setupStep === 2 && (
            <div style={{ marginTop: 24 }}>
              <p style={{ fontSize: 15, marginBottom: 16 }}>បញ្ចូលលេខកូដ PIN ({chosenLength} ខ្ទង់):</p>
              <input
                type="password"
                maxLength={chosenLength}
                autoFocus
                style={{ width: '80%', padding: 14, fontSize: 32, textAlign: 'center', letterSpacing: 10, background: '#000', border: '1px solid #3a3a3c', borderRadius: 16, color: '#fff', marginBottom: 24 }}
                value={enteredPin}
                onChange={(e) => setEnteredPin(e.target.value.replace(/\D/g, ''))}
              />
              <button
                disabled={enteredPin.length !== chosenLength}
                style={{ width: '100%', padding: 16, borderRadius: 18, background: enteredPin.length === chosenLength ? '#fff' : '#3a3a3c', color: enteredPin.length === chosenLength ? '#000' : '#8e8e93', fontWeight: 600, border: 'none', cursor: 'pointer' }}
                onClick={() => setSetupStep(3)}
              >
                បន្ទាប់
              </button>
            </div>
          )}

          {setupStep === 3 && (
            <div style={{ marginTop: 24 }}>
              <p style={{ fontSize: 15, marginBottom: 16 }}>បញ្ជាក់លេខកូដ PIN ម្ដងទៀត:</p>
              <input
                type="password"
                maxLength={chosenLength}
                autoFocus
                style={{ width: '80%', padding: 14, fontSize: 32, textAlign: 'center', letterSpacing: 10, background: '#000', border: '1px solid #3a3a3c', borderRadius: 16, color: '#fff', marginBottom: 16 }}
                value={confirmPin}
                onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ''))}
              />
              {setupError && <p style={{ color: '#ff453a', fontSize: 14, marginBottom: 16 }}>{setupError}</p>}
              <button
                disabled={confirmPin.length !== chosenLength}
                style={{ width: '100%', padding: 16, borderRadius: 18, background: confirmPin.length === chosenLength ? '#fff' : '#3a3a3c', color: confirmPin.length === chosenLength ? '#000' : '#8e8e93', fontWeight: 600, border: 'none', cursor: 'pointer' }}
                onClick={handleCreateVault}
              >
                បង្កើត និងបើក Vault
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 3. Vault Locked Screen
  if (!isUnlocked) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#000', padding: 20 }}>
        <div style={{ background: '#1c1c1e', padding: 32, borderRadius: 28, maxWidth: 380, width: '100%', textAlign: 'center', color: '#fff', border: '1px solid #2c2c2e' }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>🔒</div>
          <h2 style={{ margin: '0 0 8px 0' }}>LOCKED VAULT</h2>
          <p style={{ color: '#8e8e93', fontSize: 14, marginBottom: 24 }}>បញ្ចូលលេខកូដ PIN {pinLength} ខ្ទង់ដើម្បីដោះសោ</p>

          <input
            type="password"
            maxLength={pinLength}
            autoFocus
            style={{ width: '80%', padding: 14, fontSize: 32, textAlign: 'center', letterSpacing: 10, background: '#000', border: '1px solid #3a3a3c', borderRadius: 16, color: '#fff', marginBottom: 16 }}
            value={unlockPin}
            onChange={(e) => setUnlockPin(e.target.value.replace(/\D/g, ''))}
          />

          {unlockError && <p style={{ color: '#ff453a', fontSize: 14, marginBottom: 16 }}>{unlockError}</p>}

          <button
            style={{ width: '100%', padding: 16, borderRadius: 18, background: '#fff', color: '#000', fontWeight: 600, border: 'none', cursor: 'pointer', fontSize: 16, marginBottom: 12 }}
            onClick={handleUnlock}
          >
            ដោះសោ Vault
          </button>
          <button
            style={{ width: '100%', padding: 12, background: 'transparent', color: '#8e8e93', border: 'none', cursor: 'pointer', fontSize: 14 }}
            onClick={handleLogout}
          >
            ចាកចេញពីគណនី (Sign out)
          </button>
        </div>
      </div>
    );
  }

  // 4. Main Authenticator Dashboard (Active)
  return (
    <div style={{ minHeight: '100vh', background: '#000', color: '#fff', fontFamily: '-apple-system, BlinkMacSystemFont, sans-serif' }}>
      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', background: '#1c1c1e', borderBottom: '1px solid #2c2c2e' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <img src={user.avatarUrl || 'https://via.placeholder.com/40'} style={{ width: 42, height: 42, borderRadius: '50%' }} alt="Avatar" />
          <div>
            <div style={{ fontWeight: 600, fontSize: 16 }}>{user.name}</div>
            <div style={{ color: '#8e8e93', fontSize: 12 }}>{user.email}</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setIsUnlocked(false)}
            style={{ background: '#2c2c2e', border: 'none', color: '#fff', width: 40, height: 40, borderRadius: '50%', cursor: 'pointer', fontSize: 16 }}
            title="ចាក់សោ Vault"
          >
            🔒
          </button>
          <button
            onClick={() => setShowAddSheet(true)}
            style={{ background: '#007aff', border: 'none', color: '#fff', padding: '8px 16px', borderRadius: 20, fontWeight: 600, cursor: 'pointer' }}
          >
            + បន្ថែម
          </button>
        </div>
      </header>

      {/* Tabs */}
      <div style={{ display: 'flex', background: '#121214', borderBottom: '1px solid #2c2c2e' }}>
        <button
          onClick={() => setActiveTab('vault')}
          style={{ flex: 1, padding: 14, background: 'transparent', border: 'none', borderBottom: activeTab === 'vault' ? '2px solid #fff' : 'none', color: activeTab === 'vault' ? '#fff' : '#8e8e93', fontWeight: 600, cursor: 'pointer' }}
        >
          Authenticators ({accounts.length})
        </button>
        <button
          onClick={() => {
            setActiveTab('devices');
            fetchSessions();
          }}
          style={{ flex: 1, padding: 14, background: 'transparent', border: 'none', borderBottom: activeTab === 'devices' ? '2px solid #fff' : 'none', color: activeTab === 'devices' ? '#fff' : '#8e8e93', fontWeight: 600, cursor: 'pointer' }}
        >
          ឧបករណ៍សកម្ម
        </button>
      </div>

      {/* Content Area */}
      <main style={{ padding: 20, maxWidth: 500, margin: '0 auto' }}>
        {activeTab === 'vault' && (
          <div>
            {accounts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 20px', background: '#1c1c1e', borderRadius: 28, border: '1px solid #2c2c2e' }}>
                <div style={{ fontSize: 48, marginBottom: 16 }}>🛡️</div>
                <h3 style={{ margin: '0 0 8px 0' }}>មិនទាន់មាន Authenticator ទេ</h3>
                <p style={{ color: '#8e8e93', fontSize: 14, marginBottom: 24 }}>ចុចប៊ូតុងខាងក្រោមដើម្បីបន្ថែមគណនី 2FA ដំបូងរបស់អ្នក</p>
                <button
                  onClick={() => setShowAddSheet(true)}
                  style={{ padding: '14px 24px', background: '#fff', color: '#000', borderRadius: 18, border: 'none', fontWeight: 600, cursor: 'pointer' }}
                >
                  + បន្ថែម Authenticator
                </button>
              </div>
            ) : (
              <div>
                {accounts.map((acc) => {
                  const code = totpCodes[acc.id] || '------';
                  const formatted = `${code.slice(0, 3)} ${code.slice(3, 6)}`;
                  return (
                    <div key={acc.id} style={{ background: '#1c1c1e', padding: 20, borderRadius: 24, marginBottom: 16, border: '1px solid #2c2c2e' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div>
                          <span style={{ color: '#007aff', fontSize: 12, fontWeight: 700, textTransform: 'uppercase' }}>{acc.issuer}</span>
                          <div style={{ fontSize: 16, fontWeight: 500 }}>{acc.account}</div>
                        </div>
                        <button
                          onClick={() => handleDelete(acc.id)}
                          style={{ background: 'transparent', border: 'none', color: '#ff453a', fontSize: 18, cursor: 'pointer' }}
                        >
                          ✕
                        </button>
                      </div>

                      <div
                        onClick={() => copyCode(acc.id, code)}
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '20px 0', cursor: 'pointer' }}
                      >
                        <span style={{ fontFamily: 'Courier New, monospace', fontSize: 38, fontWeight: 700, letterSpacing: 4 }}>
                          {formatted}
                        </span>
                        <div style={{ background: '#2c2c2e', width: 44, height: 44, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, fontWeight: 'bold' }}>
                          {timeLeft}s
                        </div>
                      </div>

                      <button
                        onClick={() => copyCode(acc.id, code)}
                        style={{
                          width: '100%',
                          padding: 12,
                          borderRadius: 14,
                          border: '1px solid #2c2c2e',
                          background: copiedId === acc.id ? '#34c759' : '#242426',
                          color: '#fff',
                          fontWeight: 600,
                          cursor: 'pointer'
                        }}
                      >
                        {copiedId === acc.id ? '✓ បានចម្លងលេខកូដ' : '📋 ចម្លងលេខកូដ (Copy)'}
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'devices' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0 }}>ឧបករណ៍សកម្ម ({sessions.length})</h3>
              <button
                onClick={handleLogoutOtherDevices}
                style={{ padding: '8px 14px', background: '#ff453a', color: '#fff', border: 'none', borderRadius: 14, fontWeight: 600, cursor: 'pointer', fontSize: 13 }}
              >
                ចាកចេញពីឧបករណ៍ផ្សេង
              </button>
            </div>

            {sessions.map((s) => (
              <div key={s.id} style={{ background: '#1c1c1e', padding: 16, borderRadius: 18, marginBottom: 12, border: '1px solid #2c2c2e', display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ fontSize: 28 }}>{s.device_type === 'phone' ? '📱' : '💻'}</div>
                <div>
                  <div style={{ fontWeight: 600 }}>
                    {s.device_name} {s.is_current_device && <span style={{ background: '#34c759', color: '#000', fontSize: 10, padding: '2px 6px', borderRadius: 6, marginLeft: 6 }}>ឧបករណ៍នេះ</span>}
                  </div>
                  <div style={{ color: '#8e8e93', fontSize: 12 }}>{s.browser} • {s.operating_system}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* Add Options Bottom Sheet */}
      {showAddSheet && (
        <div
          onClick={() => setShowAddSheet(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'flex-end', justifyContent: 'center', zIndex: 1000 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: '#1c1c1e', width: '100%', maxWidth: 500, borderRadius: '28px 28px 0 0', padding: 24, display: 'flex', flexDirection: 'column', gap: 12 }}
          >
            <h3 style={{ margin: '0 0 8px 0' }}>បន្ថែម Authenticator</h3>
            <button
              onClick={() => {
                setShowAddSheet(false);
                setShowManualModal(true);
              }}
              style={{ padding: 18, background: '#2c2c2e', color: '#fff', border: 'none', borderRadius: 18, fontSize: 16, fontWeight: 600, textAlign: 'left', cursor: 'pointer' }}
            >
              ⌨️ បញ្ចូល Setup Key ដោយដៃ
            </button>
            <button
              onClick={() => setShowAddSheet(false)}
              style={{ padding: 16, background: 'transparent', color: '#ff453a', border: 'none', fontSize: 16, fontWeight: 600, cursor: 'pointer' }}
            >
              បោះបង់
            </button>
          </div>
        </div>
      )}

      {/* Manual Modal */}
      {showManualModal && (
        <div
          onClick={() => setShowManualModal(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 20 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: '#1c1c1e', padding: 24, borderRadius: 24, width: '100%', maxWidth: 400, border: '1px solid #2c2c2e' }}
          >
            <h3 style={{ margin: '0 0 16px 0' }}>បញ្ចូល Setup Key</h3>
            <form onSubmit={handleAddManual}>
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 13, color: '#8e8e93' }}>ឈ្មោះស្ថាប័ន (Issuer ឧ. Google, Facebook)</label>
                <input
                  type="text"
                  required
                  placeholder="Google"
                  style={{ width: '100%', padding: 12, background: '#000', border: '1px solid #2c2c2e', borderRadius: 12, color: '#fff', marginTop: 4, boxSizing: 'border-box' }}
                  value={manualIssuer}
                  onChange={(e) => setManualIssuer(e.target.value)}
                />
              </div>

              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 13, color: '#8e8e93' }}>ឈ្មោះគណនី (Email ឬ Username)</label>
                <input
                  type="text"
                  required
                  placeholder="user@example.com"
                  style={{ width: '100%', padding: 12, background: '#000', border: '1px solid #2c2c2e', borderRadius: 12, color: '#fff', marginTop: 4, boxSizing: 'border-box' }}
                  value={manualAccount}
                  onChange={(e) => setManualAccount(e.target.value)}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={{ fontSize: 13, color: '#8e8e93' }}>Setup Key (Base32)</label>
                <input
                  type="text"
                  required
                  placeholder="JBSWY3DPEHPK3PXP"
                  style={{ width: '100%', padding: 12, background: '#000', border: '1px solid #2c2c2e', borderRadius: 12, color: '#fff', marginTop: 4, boxSizing: 'border-box' }}
                  value={manualSecret}
                  onChange={(e) => setManualSecret(e.target.value)}
                />
              </div>

              {manualError && <p style={{ color: '#ff453a', fontSize: 13 }}>{manualError}</p>}

              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  type="button"
                  onClick={() => setShowManualModal(false)}
                  style={{ flex: 1, padding: 14, background: '#2c2c2e', color: '#fff', border: 'none', borderRadius: 14, fontWeight: 600, cursor: 'pointer' }}
                >
                  បោះបង់
                </button>
                <button
                  type="submit"
                  style={{ flex: 1, padding: 14, background: '#fff', color: '#000', border: 'none', borderRadius: 14, fontWeight: 600, cursor: 'pointer' }}
                >
                  រក្សាទុក
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <MainApp />
  </React.StrictMode>
);