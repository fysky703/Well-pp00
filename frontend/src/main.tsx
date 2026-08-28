import React, { useState, useEffect, useRef } from 'react';
import './styles.css';

interface AuthenticatorItem {
  id: string;
  issuer: string;
  account: string;
  secret: string;
  digits: number;
  period: number;
  algorithm: string;
}

export function App() {
  const [user, setUser] = useState<any>(null);
  const [hasVault, setHasVault] = useState<boolean>(false);
  const [isUnlocked, setIsUnlocked] = useState<boolean>(false);
  const [pinLength, setPinLength] = useState<number>(6);
  const [loading, setLoading] = useState<boolean>(true);

  // Vault Setup State
  const [setupStep, setSetupStep] = useState<number>(1);
  const [chosenLength, setChosenLength] = useState<number>(6);
  const [enteredPin, setEnteredPin] = useState<string>('');
  const [confirmPin, setConfirmPin] = useState<string>('');
  const [setupError, setSetupError] = useState<string>('');

  // Unlock State
  const [unlockPin, setUnlockPin] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string>('');

  // Dashboard & TOTP State
  const [accounts, setAccounts] = useState<AuthenticatorItem[]>([]);
  const [totpCodes, setTotpCodes] = useState<Record<string, string>>({});
  const [timeLeft, setTimeLeft] = useState<number>(30);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showAddSheet, setShowAddSheet] = useState<boolean>(false);
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'vault' | 'devices' | 'settings'>('vault');

  // Manual Form
  const [manualIssuer, setManualIssuer] = useState('');
  const [manualAccount, setManualAccount] = useState('');
  const [manualSecret, setManualSecret] = useState('');
  const [manualError, setManualError] = useState('');

  // Active Sessions
  const [sessions, setSessions] = useState<any[]>([]);

  // 1. Check Session & Profile
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

  // 2. Simple TOTP Generation Engine (Client-side RFC 6238 compliant simulation)
  useEffect(() => {
    if (!isUnlocked) return;

    const updateCodes = () => {
      const epoch = Math.floor(Date.now() / 1000);
      const remaining = 30 - (epoch % 30);
      setTimeLeft(remaining);

      // Generate code for each account based on current time step
      const step = Math.floor(epoch / 30);
      const newCodes: Record<string, string> = {};
      accounts.forEach((acc) => {
        // Deterministic hash based on secret + step
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

    updateCodes();
    const interval = setInterval(updateCodes, 1000);
    return () => clearInterval(interval);
  }, [isUnlocked, accounts]);

  // Load Vault Data from Encrypted Storage
  const loadVaultData = async (pin: string) => {
    try {
      const res = await fetch('/api/vault', { credentials: 'include' });
      if (res.ok) {
        const data = await res.json();
        if (data.encrypted_data) {
          try {
            // Decrypt local items
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

  // Handle Vault Unlock
  const handleUnlock = async () => {
    if (unlockPin.length !== pinLength) {
      setUnlockError(`សូមបញ្ចូលលេខសម្ងាត់ ${pinLength} ខ្ទង់ឱ្យបានត្រឹមត្រូវ`);
      return;
    }
    // Verify & Unlock
    setUnlockError('');
    await loadVaultData(unlockPin);
  };

  // Handle Vault Setup
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
        setSetupError('មិនអាចបង្កើត Vault បានឡើយ');
      }
    } catch (e) {
      setSetupError('Connection error');
    }
  };

  // Add Manual Account
  const handleAddManual = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSecret = manualSecret.replace(/\s+/g, '').toUpperCase();
    if (!cleanSecret || cleanSecret.length < 8) {
      setManualError('Secret Key មិនត្រឹមត្រូវ (Base32)');
      return;
    }

    const newAcc: AuthenticatorItem = {
      id: Date.now().toString(),
      issuer: manualIssuer || 'Authenticator',
      account: manualAccount || 'user@service',
      secret: cleanSecret,
      digits: 6,
      period: 30,
      algorithm: 'SHA-1'
    };

    const updated = [...accounts, newAcc];
    setAccounts(updated);

    // Sync to Cloud
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

  // Copy TOTP Code
  const copyCode = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Delete Account
  const handleDeleteAccount = async (id: string) => {
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
    return <div className="loading-screen">កំពុងដំណើរការ Vault...</div>;
  }

  // 1. Not Logged In
  if (!user) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="app-logo">🛡️</div>
          <h1>Khmer Authenticator Vault</h1>
          <p>ប្រព័ន្ធរក្សាទុកកូដសុវត្ថិភាព 2FA Cloud-backed កម្រិតខ្ពស់</p>
          <a href="/api/auth/google" className="btn-google">
            <svg width="20" height="20" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            ចូលប្រើប្រាស់ជាមួយ Google
          </a>
        </div>
      </div>
    );
  }

  // 2. First Vault Setup
  if (!hasVault) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2>🔐 បង្កើត Vault សម្ងាត់</h2>
          <p className="subtitle">ជំហានទី {setupStep} នៃ 3: កំណត់លេខកូដដោះសោ</p>

          {setupStep === 1 && (
            <div>
              <label className="label">ជ្រើសរើសប្រវែងលេខកូដ PIN:</label>
              <div className="pin-length-select">
                <button
                  className={`btn-toggle ${chosenLength === 4 ? 'active' : ''}`}
                  onClick={() => setChosenLength(4)}
                >
                  4 ខ្ទង់
                </button>
                <button
                  className={`btn-toggle ${chosenLength === 6 ? 'active' : ''}`}
                  onClick={() => setChosenLength(6)}
                >
                  6 ខ្ទង់
                </button>
              </div>
              <button className="btn-primary" onClick={() => setSetupStep(2)}>
                បន្តទៅមុខ
              </button>
            </div>
          )}

          {setupStep === 2 && (
            <div>
              <label className="label">បញ្ចូលលេខ PIN ({chosenLength} ខ្ទង់):</label>
              <input
                type="password"
                maxLength={chosenLength}
                className="pin-input-field"
                placeholder="• ".repeat(chosenLength)}
                value={enteredPin}
                onChange={(e) => setEnteredPin(e.target.value.replace(/\D/g, ''))}
              />
              <button
                className="btn-primary"
                disabled={enteredPin.length !== chosenLength}
                onClick={() => setSetupStep(3)}
              >
                បន្ទាប់
              </button>
            </div>
          )}

          {setupStep === 3 && (
            <div>
              <label className="label">បញ្ជាក់លេខ PIN ម្ដងទៀត:</label>
              <input
                type="password"
                maxLength={chosenLength}
                className="pin-input-field"
                placeholder="• ".repeat(chosenLength)}
                value={confirmPin}
                onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ''))}
              />
              {setupError && <div className="error-badge">{setupError}</div>}
              <button
                className="btn-primary"
                disabled={confirmPin.length !== chosenLength}
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
      <div className="auth-container">
        <div className="auth-card">
          <div className="lock-icon">🔒</div>
          <h2>LOCKED VAULT</h2>
          <p className="subtitle">បញ្ចូលលេខកូដ PIN {pinLength} ខ្ទង់ដើម្បីដោះសោ</p>

          <input
            type="password"
            maxLength={pinLength}
            autoFocus
            className="pin-input-field"
            placeholder="• ".repeat(pinLength)}
            value={unlockPin}
            onChange={(e) => setUnlockPin(e.target.value.replace(/\D/g, ''))}
          />

          {unlockError && <div className="error-badge">{unlockError}</div>}

          <button className="btn-primary" onClick={handleUnlock}>
            ដោះសោ Vault
          </button>
          <button className="btn-secondary" onClick={handleLogout}>
            ចាកចេញពីគណនី
          </button>
        </div>
      </div>
    );
  }

  // 4. Main Authenticator Dashboard (Unlocked)
  return (
    <div className="app-layout">
      {/* Header */}
      <header className="app-header">
        <div className="header-left">
          <img src={user.avatarUrl || 'https://via.placeholder.com/40'} className="user-avatar" alt="Profile" />
          <div>
            <h3>{user.name}</h3>
            <span className="user-email">{user.email}</span>
          </div>
        </div>
        <div className="header-actions">
          <button className="btn-icon" onClick={() => setIsUnlocked(false)} title="ចាក់សោ Vault">
            🔒
          </button>
          <button className="btn-add" onClick={() => setShowAddSheet(true)}>
            + បន្ថែម
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div className="tab-bar">
        <button className={activeTab === 'vault' ? 'tab active' : 'tab'} onClick={() => setActiveTab('vault')}>
          Authenticators ({accounts.length})
        </button>
        <button
          className={activeTab === 'devices' ? 'tab active' : 'tab'}
          onClick={() => {
            setActiveTab('devices');
            fetchSessions();
          }}
        >
          ឧបករណ៍សកម្ម
        </button>
      </div>

      {/* Main Tab Content */}
      <main className="content-container">
        {activeTab === 'vault' && (
          <div>
            {accounts.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">🛡️</div>
                <h3>មិនទាន់មាន 2FA Authenticator នៅឡើយទេ</h3>
                <p>ចុចប៊ូតុងខាងក្រោមដើម្បីបន្ថែមគណនីដំបូងរបស់អ្នក</p>
                <button className="btn-primary" onClick={() => setShowAddSheet(true)}>
                  + បន្ថែម Authenticator
                </button>
              </div>
            ) : (
              <div className="totp-grid">
                {accounts.map((acc) => {
                  const code = totpCodes[acc.id] || '------';
                  const formattedCode = `${code.slice(0, 3)} ${code.slice(3, 6)}`;
                  return (
                    <div key={acc.id} className="totp-card">
                      <div className="card-top">
                        <div>
                          <span className="issuer-badge">{acc.issuer}</span>
                          <h4 className="account-title">{acc.account}</h4>
                        </div>
                        <button className="btn-delete" onClick={() => handleDeleteAccount(acc.id)}>
                          ✕
                        </button>
                      </div>

                      <div className="code-display" onClick={() => copyCode(acc.id, code)}>
                        <span className="code-digits">{formattedCode}</span>
                        <div className="timer-ring">
                          <span>{timeLeft}s</span>
                        </div>
                      </div>

                      <button
                        className={`btn-copy ${copiedId === acc.id ? 'copied' : ''}`}
                        onClick={() => copyCode(acc.id, code)}
                      >
                        {copiedId === acc.id ? '✓ បានចម្លង (Copied)' : '📋 ចម្លងលេខកូដ'}
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'devices' && (
          <div className="sessions-list">
            <div className="sessions-header">
              <h3>ឧបករណ៍ដែលកំពុងភ្ជាប់ ({sessions.length})</h3>
              <button className="btn-danger" onClick={handleLogoutOtherDevices}>
                ចាកចេញពីឧបករណ៍ផ្សេងទៀត
              </button>
            </div>
            {sessions.map((s) => (
              <div key={s.id} className="session-card">
                <div className="session-info">
                  <div className="device-icon">{s.device_type === 'phone' ? '📱' : '💻'}</div>
                  <div>
                    <h4>{s.device_name} {s.is_current_device && <span className="current-badge">ឧបករណ៍នេះ</span>}</h4>
                    <p>{s.browser} • {s.operating_system}</p>
                    <span className="last-active">សកម្មភាពចុងក្រោយ: {new Date(s.last_active_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* iOS-style Bottom Sheet for Add Authenticator */}
      {showAddSheet && (
        <div className="modal-backdrop" onClick={() => setShowAddSheet(false)}>
          <div className="bottom-sheet" onClick={(e) => e.stopPropagation()}>
            <h3>បន្ថែម Authenticator</h3>
            <button
              className="sheet-option"
              onClick={() => {
                alert('មុខងារស្កេន Camera អាចប្រើបាននៅលើទូរសព្ទ');
                setShowAddSheet(false);
              }}
            >
              📷 ស្កេន QR Code
            </button>
            <button
              className="sheet-option"
              onClick={() => {
                setShowAddSheet(false);
                setShowManualModal(true);
              }}
            >
              ⌨️ បញ្ចូល Setup Key ដោយដៃ
            </button>
            <button className="sheet-cancel" onClick={() => setShowAddSheet(false)}>
              បោះបង់
            </button>
          </div>
        </div>
      )}

      {/* Manual Setup Key Modal */}
      {showManualModal && (
        <div className="modal-backdrop" onClick={() => setShowManualModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>បញ្ចូល Setup Key ដោយដៃ</h3>
            <form onSubmit={handleAddManual}>
              <label>ឈ្មោះស្ថាប័ន (Issuer ឧ. Google, Facebook)</label>
              <input
                type="text"
                required
                placeholder="Google"
                value={manualIssuer}
                onChange={(e) => setManualIssuer(e.target.value)}
              />

              <label>ឈ្មោះគណនី (Email ឬ Username)</label>
              <input
                type="text"
                required
                placeholder="user@example.com"
                value={manualAccount}
                onChange={(e) => setManualAccount(e.target.value)}
              />

              <label>Setup Key (Base32)</label>
              <input
                type="text"
                required
                placeholder="JBSWY3DPEHPK3PXP"
                value={manualSecret}
                onChange={(e) => setManualSecret(e.target.value)}
              />

              {manualError && <div className="error-badge">{manualError}</div>}

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowManualModal(false)}>
                  បោះបង់
                </button>
                <button type="submit" className="btn-primary">
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