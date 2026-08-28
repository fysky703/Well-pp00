import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom/client';
import { calculateTOTP, getRemainingSeconds, isValidBase32, parseOTPAuthURI, ParsedOTPAuth } from './totp';
import { encryptVault, decryptVault } from './crypto';
import {
  IconShield,
  IconLock,
  IconPlus,
  IconCopy,
  IconCheck,
  IconCamera,
  IconKeyboard,
  IconTrash,
  IconPhone,
  IconComputer
} from './icons';
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

function MainApp() {
  const [user, setUser] = useState<any>(null);
  const [hasVault, setHasVault] = useState<boolean>(false);
  const [isUnlocked, setIsUnlocked] = useState<boolean>(false);
  const [pinLength, setPinLength] = useState<number>(6);
  const [currentPin, setCurrentPin] = useState<string>('');
  const [vaultSalt, setVaultSalt] = useState<string>('default_salt');
  const [loading, setLoading] = useState<boolean>(true);

  // Setup Flow
  const [setupStep, setSetupStep] = useState<number>(1);
  const [chosenLength, setChosenLength] = useState<number>(6);
  const [enteredPin, setEnteredPin] = useState<string>('');
  const [confirmPin, setConfirmPin] = useState<string>('');
  const [setupError, setSetupError] = useState<string>('');

  // Unlock State
  const [unlockPin, setUnlockPin] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string>('');

  // Dashboard Accounts & Real TOTP
  const [accounts, setAccounts] = useState<AuthenticatorItem[]>([]);
  const [totpCodes, setTotpCodes] = useState<Record<string, string>>({});
  const [timeLeft, setTimeLeft] = useState<number>(30);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Modals & Navigation
  const [showAddSheet, setShowAddSheet] = useState<boolean>(false);
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [showScannerModal, setShowScannerModal] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'vault' | 'devices'>('vault');

  // Manual Setup State
  const [manualIssuer, setManualIssuer] = useState('');
  const [manualAccount, setManualAccount] = useState('');
  const [manualSecret, setManualSecret] = useState('');
  const [manualPreviewCode, setManualPreviewCode] = useState('');
  const [manualError, setManualError] = useState('');

  // Camera QR Scanner State
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [scannerError, setScannerError] = useState('');
  const [scannedResult, setScannedResult] = useState<ParsedOTPAuth | null>(null);
  const scanStreamRef = useRef<MediaStream | null>(null);

  // Active Sessions
  const [sessions, setSessions] = useState<any[]>([]);

  // 1. Initial Authentication Check
  const fetchAuth = async () => {
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
    fetchAuth();
  }, []);

  // 2. Real-Time RFC 6238 TOTP Generation (Syncs every second with Unix Time)
  useEffect(() => {
    if (!isUnlocked || accounts.length === 0) return;

    let isMounted = true;

    const refreshCodes = async () => {
      const now = Date.now();
      const remaining = getRemainingSeconds(30, now);
      if (isMounted) setTimeLeft(remaining);

      const calculated: Record<string, string> = {};
      for (const acc of accounts) {
        calculated[acc.id] = await calculateTOTP(
          acc.secret,
          acc.period || 30,
          acc.digits || 6,
          acc.algorithm || 'SHA-1',
          now
        );
      }
      if (isMounted) setTotpCodes(calculated);
    };

    refreshCodes();
    const interval = setInterval(refreshCodes, 1000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [isUnlocked, accounts]);

  // Preview manual code live as user types
  useEffect(() => {
    const clean = manualSecret.replace(/\s+/g, '').toUpperCase();
    if (isValidBase32(clean)) {
      calculateTOTP(clean).then(setManualPreviewCode);
      setManualError('');
    } else {
      setManualPreviewCode('');
      if (clean.length >= 4) setManualError('Invalid Base32 characters');
    }
  }, [manualSecret]);

  // Load and Decrypt Vault
  const handleUnlock = async () => {
    if (unlockPin.length !== pinLength) {
      setUnlockError(`Please enter a valid ${pinLength}-digit PIN`);
      return;
    }

    try {
      const res = await fetch('/api/vault', { credentials: 'include' });
      if (!res.ok) {
        setUnlockError('Could not fetch vault data');
        return;
      }

      const vaultData = await res.json();
      const salt = vaultData.pin_salt || 'vault_salt_v1';
      setVaultSalt(salt);

      if (vaultData.encrypted_data && vaultData.encryption_metadata?.iv) {
        try {
          const decrypted = await decryptVault(
            vaultData.encrypted_data,
            vaultData.encryption_metadata.iv,
            unlockPin,
            salt
          );
          setAccounts(decrypted);
        } catch (decryptErr) {
          setUnlockError('Incorrect PIN or corrupted vault');
          return;
        }
      } else {
        setAccounts([]);
      }

      setCurrentPin(unlockPin);
      setIsUnlocked(true);
      setUnlockError('');
    } catch (e: any) {
      setUnlockError(e.message || 'Unlock failed');
    }
  };

  // Create New Vault
  const handleCreateVault = async () => {
    if (enteredPin !== confirmPin) {
      setSetupError('PINs do not match');
      return;
    }

    try {
      const salt = 'salt_' + Math.random().toString(36).substring(2);
      const encrypted = await encryptVault([], enteredPin, salt);

      const res = await fetch('/api/vault/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          pinHash: btoa(enteredPin),
          pinSalt: salt,
          pinLength: chosenLength,
          encryptedData: encrypted.ciphertext,
          encryptionMetadata: { iv: encrypted.iv, version: 1, cipher: 'AES-GCM-256' }
        })
      });

      if (res.ok) {
        setHasVault(true);
        setPinLength(chosenLength);
        setCurrentPin(enteredPin);
        setVaultSalt(salt);
        setAccounts([]);
        setIsUnlocked(true);
      } else {
        setSetupError('Server rejected vault creation');
      }
    } catch (err: any) {
      setSetupError(err.message || 'Failed to create vault');
    }
  };

  // Save Account & Encrypt Vault
  const saveAccountsToVault = async (newAccounts: AuthenticatorItem[]) => {
    setAccounts(newAccounts);
    try {
      const encrypted = await encryptVault(newAccounts, currentPin, vaultSalt);
      await fetch('/api/vault/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          encryptedData: encrypted.ciphertext,
          encryptionMetadata: { iv: encrypted.iv, version: 1 }
        })
      });
    } catch (e) {
      console.error('Failed to sync vault:', e);
    }
  };

  const handleAddManual = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSecret = manualSecret.replace(/\s+/g, '').toUpperCase();
    if (!isValidBase32(cleanSecret)) {
      setManualError('Invalid Base32 secret key');
      return;
    }

    const newItem: AuthenticatorItem = {
      id: Date.now().toString(),
      issuer: manualIssuer.trim() || 'Authenticator',
      account: manualAccount.trim() || 'user',
      secret: cleanSecret,
      digits: 6,
      period: 30,
      algorithm: 'SHA-1'
    };

    await saveAccountsToVault([...accounts, newItem]);
    setManualIssuer('');
    setManualAccount('');
    setManualSecret('');
    setShowManualModal(false);
  };

  // Real Camera Scanner Start
  const startCameraScanner = async () => {
    setShowAddSheet(false);
    setShowScannerModal(true);
    setScannerError('');
    setScannedResult(null);

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      });
      scanStreamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
      }

      // Check native BarcodeDetector support
      if ('BarcodeDetector' in window) {
        const detector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });
        const interval = setInterval(async () => {
          if (!videoRef.current || !scanStreamRef.current) {
            clearInterval(interval);
            return;
          }
          try {
            const barcodes = await detector.detect(videoRef.current);
            if (barcodes && barcodes.length > 0) {
              const rawValue = barcodes[0].rawValue;
              const parsed = parseOTPAuthURI(rawValue);
              if (parsed) {
                setScannedResult(parsed);
                stopCameraScanner();
                clearInterval(interval);
              } else {
                setScannerError('QR code is not a valid standard otpauth:// TOTP format.');
              }
            }
          } catch {}
        }, 500);
      }
    } catch (err: any) {
      setScannerError('Camera access denied or unsupported on this device: ' + err.message);
    }
  };

  const stopCameraScanner = () => {
    if (scanStreamRef.current) {
      scanStreamRef.current.getTracks().forEach((track) => track.stop());
      scanStreamRef.current = null;
    }
  };

  const handleSaveScanned = async () => {
    if (!scannedResult) return;
    const newItem: AuthenticatorItem = {
      id: Date.now().toString(),
      issuer: scannedResult.issuer,
      account: scannedResult.account,
      secret: scannedResult.secret,
      digits: scannedResult.digits,
      period: scannedResult.period,
      algorithm: scannedResult.algorithm
    };
    await saveAccountsToVault([...accounts, newItem]);
    setShowScannerModal(false);
    setScannedResult(null);
  };

  // Copy Real TOTP Code
  const copyCode = (id: string, code: string) => {
    if (!code || code === '------') return;
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Delete Account
  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this authenticator?')) return;
    await saveAccountsToVault(accounts.filter((a) => a.id !== id));
  };

  // Sessions Management
  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/sessions', { credentials: 'include' });
      if (res.ok) {
        setSessions(await res.json());
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleLogoutOthers = async () => {
    if (!confirm('Log out all other active sessions?')) return;
    await fetch('/api/sessions/logout-others', { method: 'POST', credentials: 'include' });
    fetchSessions();
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    setUser(null);
    setIsUnlocked(false);
    setCurrentPin('');
  };

  if (loading) {
    return (
      <div className="center-screen">
        <IconShield size={48} />
        <p>Loading Authenticator Vault...</p>
      </div>
    );
  }

  // 1. Google OAuth Login Required
  if (!user) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="brand-badge">
            <IconShield size={40} />
          </div>
          <h1>Khmer Authenticator Vault</h1>
          <p className="subtitle">Secure, Zero-Knowledge 2FA Cloud Backup</p>
          <a href="/api/auth/google" className="btn-google">
            <svg width="20" height="20" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            Sign in with Google
          </a>
        </div>
      </div>
    );
  }

  // 2. Initial Setup Wizard
  if (!hasVault) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <h2>Create Vault PIN</h2>
          <p className="subtitle">Step {setupStep} of 3: Set your hardware unlock PIN</p>

          {setupStep === 1 && (
            <div>
              <p className="input-label">Select PIN Length:</p>
              <div className="button-group">
                <button
                  className={`btn-choice ${chosenLength === 4 ? 'active' : ''}`}
                  onClick={() => setChosenLength(4)}
                >
                  4-Digit PIN
                </button>
                <button
                  className={`btn-choice ${chosenLength === 6 ? 'active' : ''}`}
                  onClick={() => setChosenLength(6)}
                >
                  6-Digit PIN
                </button>
              </div>
              <button className="btn-primary" onClick={() => setSetupStep(2)}>
                Continue
              </button>
            </div>
          )}

          {setupStep === 2 && (
            <div>
              <p className="input-label">Enter your {chosenLength}-digit PIN:</p>
              <input
                type="password"
                maxLength={chosenLength}
                autoFocus
                className="pin-box"
                value={enteredPin}
                onChange={(e) => setEnteredPin(e.target.value.replace(/\D/g, ''))}
              />
              <button
                className="btn-primary"
                disabled={enteredPin.length !== chosenLength}
                onClick={() => setSetupStep(3)}
              >
                Next
              </button>
            </div>
          )}

          {setupStep === 3 && (
            <div>
              <p className="input-label">Confirm your PIN:</p>
              <input
                type="password"
                maxLength={chosenLength}
                autoFocus
                className="pin-box"
                value={confirmPin}
                onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ''))}
              />
              {setupError && <p className="error-text">{setupError}</p>}
              <button
                className="btn-primary"
                disabled={confirmPin.length !== chosenLength}
                onClick={handleCreateVault}
              >
                Initialize Encrypted Vault
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 3. Locked Vault Screen
  if (!isUnlocked) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="brand-badge">
            <IconLock size={36} />
          </div>
          <h2>LOCKED VAULT</h2>
          <p className="subtitle">Enter your {pinLength}-digit Vault PIN to view authenticators</p>

          <input
            type="password"
            maxLength={pinLength}
            autoFocus
            className="pin-box"
            value={unlockPin}
            onChange={(e) => setUnlockPin(e.target.value.replace(/\D/g, ''))}
            onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
          />

          {unlockError && <p className="error-text">{unlockError}</p>}

          <button className="btn-primary" onClick={handleUnlock}>
            Unlock Vault
          </button>
          <button className="btn-link" onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      </div>
    );
  }

  // 4. Main Authenticator Dashboard (Unlocked)
  return (
    <div className="app-shell">
      {/* Header */}
      <header className="navbar">
        <div className="user-profile">
          <img src={user.avatarUrl || 'https://via.placeholder.com/40'} alt="Avatar" className="avatar-img" />
          <div>
            <div className="user-name">{user.name}</div>
            <div className="user-email">{user.email}</div>
          </div>
        </div>
        <div className="nav-actions">
          <button className="btn-icon" onClick={() => setIsUnlocked(false)} aria-label="Lock Vault">
            <IconLock size={18} />
          </button>
          <button className="btn-action" onClick={() => setShowAddSheet(true)}>
            <IconPlus size={16} /> Add
          </button>
        </div>
      </header>

      {/* Tabs */}
      <nav className="tab-container">
        <button
          className={`tab-btn ${activeTab === 'vault' ? 'active' : ''}`}
          onClick={() => setActiveTab('vault')}
        >
          Authenticators ({accounts.length})
        </button>
        <button
          className={`tab-btn ${activeTab === 'devices' ? 'active' : ''}`}
          onClick={() => {
            setActiveTab('devices');
            fetchSessions();
          }}
        >
          Active Devices
        </button>
      </nav>

      {/* Main Content */}
      <main className="main-content">
        {activeTab === 'vault' && (
          <div>
            {accounts.length === 0 ? (
              <div className="empty-panel">
                <IconShield size={44} />
                <h3>No Authenticator Accounts</h3>
                <p>Add your first 2FA account using a Setup Key or Camera Scan.</p>
                <button className="btn-primary" onClick={() => setShowAddSheet(true)}>
                  <IconPlus size={16} /> Add Authenticator
                </button>
              </div>
            ) : (
              <div className="card-list">
                {accounts.map((acc) => {
                  const code = totpCodes[acc.id] || '------';
                  const formatted = `${code.slice(0, 3)} ${code.slice(3, 6)}`;
                  return (
                    <article key={acc.id} className="totp-card">
                      <div className="card-header">
                        <div>
                          <span className="issuer-tag">{acc.issuer}</span>
                          <h3 className="account-tag">{acc.account}</h3>
                        </div>
                        <button
                          className="btn-delete"
                          onClick={() => handleDelete(acc.id)}
                          aria-label="Delete authenticator"
                        >
                          <IconTrash size={16} />
                        </button>
                      </div>

                      <div className="code-container" onClick={() => copyCode(acc.id, code)}>
                        <span className="totp-digits">{formatted}</span>
                        <div className="timer-badge">{timeLeft}s</div>
                      </div>

                      <button
                        className={`btn-copy ${copiedId === acc.id ? 'copied' : ''}`}
                        onClick={() => copyCode(acc.id, code)}
                      >
                        {copiedId === acc.id ? (
                          <>
                            <IconCheck size={16} /> Copied to Clipboard
                          </>
                        ) : (
                          <>
                            <IconCopy size={16} /> Copy Code
                          </>
                        )}
                      </button>
                    </article>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'devices' && (
          <div className="devices-panel">
            <div className="devices-header">
              <h3>Active Sessions ({sessions.length})</h3>
              <button className="btn-danger" onClick={handleLogoutOthers}>
                Log Out Others
              </button>
            </div>

            {sessions.map((s) => (
              <div key={s.id} className="device-card">
                <div className="device-icon">
                  {s.device_type === 'phone' ? <IconPhone size={22} /> : <IconComputer size={22} />}
                </div>
                <div className="device-details">
                  <div className="device-title">
                    {s.device_name}
                    {s.is_current_device && <span className="current-tag">This Device</span>}
                  </div>
                  <div className="device-meta">{s.browser} • {s.operating_system}</div>
                  <div className="device-time">Last active: {new Date(s.last_active_at).toLocaleString()}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* iOS-Style Add Bottom Sheet */}
      {showAddSheet && (
        <div className="sheet-backdrop" onClick={() => setShowAddSheet(false)}>
          <div className="sheet-dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Add Authenticator</h3>
            <button className="sheet-btn" onClick={startCameraScanner}>
              <IconCamera size={20} /> Scan QR Code
            </button>
            <button
              className="sheet-btn"
              onClick={() => {
                setShowAddSheet(false);
                setShowManualModal(true);
              }}
            >
              <IconKeyboard size={20} /> Enter Setup Key
            </button>
            <button className="sheet-btn cancel" onClick={() => setShowAddSheet(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Real Camera QR Scanner Modal */}
      {showScannerModal && (
        <div className="modal-backdrop" onClick={() => { stopCameraScanner(); setShowScannerModal(false); }}>
          <div className="modal-dialog scanner-dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Scan TOTP QR Code</h3>
            {scannerError ? (
              <div className="error-panel">
                <p>{scannerError}</p>
                <button className="btn-primary" onClick={() => { stopCameraScanner(); setShowScannerModal(false); setShowManualModal(true); }}>
                  Switch to Manual Setup Key
                </button>
              </div>
            ) : scannedResult ? (
              <div className="confirm-panel">
                <h4>Confirm Authenticator Account</h4>
                <p><strong>Issuer:</strong> {scannedResult.issuer}</p>
                <p><strong>Account:</strong> {scannedResult.account}</p>
                <p><strong>Period:</strong> {scannedResult.period}s | <strong>Digits:</strong> {scannedResult.digits}</p>
                <div className="modal-actions">
                  <button className="btn-secondary" onClick={() => setScannedResult(null)}>
                    Scan Again
                  </button>
                  <button className="btn-primary" onClick={handleSaveScanned}>
                    Add Account
                  </button>
                </div>
              </div>
            ) : (
              <div>
                <video ref={videoRef} className="camera-view" playsInline muted />
                <p className="scanner-hint">Point your camera at a standard TOTP QR code</p>
                <button className="btn-secondary" onClick={() => { stopCameraScanner(); setShowScannerModal(false); }}>
                  Cancel
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Manual Setup Key Modal */}
      {showManualModal && (
        <div className="modal-backdrop" onClick={() => setShowManualModal(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Enter Setup Key</h3>
            <form onSubmit={handleAddManual}>
              <div className="form-group">
                <label>Issuer (e.g., Google, Telegram, Facebook)</label>
                <input
                  type="text"
                  required
                  placeholder="Google"
                  value={manualIssuer}
                  onChange={(e) => setManualIssuer(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Account Name (e.g., user@example.com)</label>
                <input
                  type="text"
                  required
                  placeholder="user@gmail.com"
                  value={manualAccount}
                  onChange={(e) => setManualAccount(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Setup Secret Key (Base32)</label>
                <input
                  type="text"
                  required
                  placeholder="JBSWY3DPEHPK3PXP"
                  value={manualSecret}
                  onChange={(e) => setManualSecret(e.target.value)}
                />
              </div>

              {manualPreviewCode && (
                <div className="preview-box">
                  <span>Live TOTP Preview:</span>
                  <strong>{manualPreviewCode}</strong>
                </div>
              )}

              {manualError && <p className="error-text">{manualError}</p>}

              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowManualModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={!manualPreviewCode}>
                  Save Account
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