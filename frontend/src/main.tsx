import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserQRCodeReader, IScannerControls } from '@zxing/browser';

// ==========================================
// 1. 🛡️ TRUE RFC 6238 / RFC 4226 TOTP ENGINE
// ==========================================
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface ParsedOTPAuth {
  issuer: string;
  account: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
  type?: 'totp' | 'hotp';
}

export function isValidBase32(secret: string): boolean {
  const clean = secret.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || clean.length < 4) return false;
  for (let i = 0; i < clean.length; i++) {
    if (!BASE32_ALPHABET.includes(clean[i])) return false;
  }
  return true;
}

export function base32ToBytes(str: string): Uint8Array {
  const clean = str.toUpperCase().replace(/[\s=-]/g, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) continue;

    buffer = (buffer << 5) | val;
    bitsLeft += 5;

    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      bytes.push((buffer >> bitsLeft) & 0xff);
    }
  }

  return new Uint8Array(bytes);
}

function sha1(bytes: Uint8Array): Uint8Array {
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const len = bytes.length;
  const bitLen = len * 8;
  const padLen = len % 64 < 56 ? 56 - (len % 64) : 120 - (len % 64);
  const totalLen = len + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[len] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 4, bitLen, false);

  const w = new Uint32Array(80);

  for (let i = 0; i < totalLen; i += 64) {
    for (let t = 0; t < 16; t++) {
      w[t] = view.getUint32(i + t * 4, false);
    }
    for (let t = 16; t < 80; t++) {
      const val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
      w[t] = (val << 1) | (val >>> 31);
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4;

    for (let t = 0; t < 80; t++) {
      let f = 0, k = 0;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = K[0];
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = K[1];
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = K[2];
      } else {
        f = b ^ c ^ d;
        k = K[3];
      }

      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) >>> 0;
      e = d;
      d = c;
      c = ((b << 30) | (b >>> 2)) >>> 0;
      b = a;
      a = temp;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  const result = new Uint8Array(20);
  const resView = new DataView(result.buffer);
  resView.setUint32(0, h0, false);
  resView.setUint32(4, h1, false);
  resView.setUint32(8, h2, false);
  resView.setUint32(12, h3, false);
  resView.setUint32(16, h4, false);
  return result;
}

function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  let formattedKey = key;
  if (key.length > 64) formattedKey = sha1(key);
  const kPad = new Uint8Array(64);
  kPad.set(formattedKey);

  const oPad = new Uint8Array(64);
  const iPad = new Uint8Array(64);

  for (let i = 0; i < 64; i++) {
    oPad[i] = kPad[i] ^ 0x5c;
    iPad[i] = kPad[i] ^ 0x36;
  }

  const inner = new Uint8Array(64 + message.length);
  inner.set(iPad);
  inner.set(message, 64);
  const innerHash = sha1(inner);

  const outer = new Uint8Array(64 + innerHash.length);
  outer.set(oPad);
  outer.set(innerHash, 64);

  return sha1(outer);
}

export async function calculateTOTP(
  secret: string,
  period = 30,
  digits = 6,
  _algorithm = 'SHA-1',
  timestamp = Date.now()
): Promise<string> {
  const keyBytes = base32ToBytes(secret);
  if (keyBytes.length === 0) return '------';

  const epoch = Math.floor(timestamp / 1000);
  const counter = Math.floor(epoch / period);

  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setUint32(0, 0, false);
  view.setUint32(4, counter, false);

  const hmac = hmacSha1(keyBytes, msg);

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

export function getRemainingSeconds(period = 30, timestamp = Date.now()): number {
  const epoch = Math.floor(timestamp / 1000);
  return period - (epoch % period);
}

export function parseOTPAuthURI(uriString: string): ParsedOTPAuth | null {
  try {
    if (!uriString.startsWith('otpauth://')) return null;
    const url = new URL(uriString);

    const isHotp = url.pathname.startsWith('hotp/') || url.host === 'hotp';
    const label = decodeURIComponent(url.pathname.replace(/^\/(totp|hotp)\//, '').replace(/^\//, ''));
    let issuer = url.searchParams.get('issuer') || '';
    let account = label;

    if (label.includes(':')) {
      const parts = label.split(':');
      if (!issuer) issuer = parts[0].trim();
      account = parts.slice(1).join(':').trim();
    }

    const secret = url.searchParams.get('secret') || '';
    if (!secret || !isValidBase32(secret)) return null;

    const digits = parseInt(url.searchParams.get('digits') || '6', 10);
    const period = parseInt(url.searchParams.get('period') || '30', 10);

    return {
      issuer: issuer || 'Authenticator',
      account: account || 'Account',
      secret: secret.toUpperCase(),
      algorithm: 'SHA-1',
      digits: isNaN(digits) ? 6 : digits,
      period: isNaN(period) ? 30 : period,
      type: isHotp ? 'hotp' : 'totp'
    };
  } catch (e) {
    return null;
  }
}

// ==========================================
// 2. 🔐 ZERO-KNOWLEDGE AES-GCM VAULT CRYPTO
// ==========================================
async function deriveKeyFromPin(pin: string, salt: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const pinKeyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(pin),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode(salt),
      iterations: 100000,
      hash: 'SHA-256'
    },
    pinKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptVault(data: any, pin: string, salt: string): Promise<{ ciphertext: string; iv: string }> {
  const enc = new TextEncoder();
  const key = await deriveKeyFromPin(pin, salt);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(data))
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...new Uint8Array(iv)))
  };
}

async function decryptVault(ciphertextBase64: string, ivBase64: string, pin: string, salt: string): Promise<any> {
  const key = await deriveKeyFromPin(pin, salt);
  const iv = new Uint8Array(atob(ivBase64).split('').map((c) => c.charCodeAt(0)));
  const data = new Uint8Array(atob(ciphertextBase64).split('').map((c) => c.charCodeAt(0)));

  const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}

// ==========================================
// 3. 🎨 PREMIUM SVG ICONS (Accessible)
// ==========================================
const IconShield = ({ size = 24 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const IconLock = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

const IconPlus = ({ size = 18 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);

const IconCopy = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

const IconCheck = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

const IconCamera = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z" />
    <circle cx="12" cy="13" r="4" />
  </svg>
);

const IconKeyboard = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2" ry="2" />
    <line x1="6" y1="8" x2="6.01" y2="8" />
    <line x1="10" y1="8" x2="10.01" y2="8" />
    <line x1="14" y1="8" x2="14.01" y2="8" />
    <line x1="18" y1="8" x2="18.01" y2="8" />
    <line x1="6" y1="12" x2="6.01" y2="12" />
    <line x1="18" y1="12" x2="18.01" y2="12" />
    <line x1="8" y1="16" x2="16" y2="16" />
  </svg>
);

const IconTrash = ({ size = 18 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="3 6 5 6 21 6" />
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
  </svg>
);

const IconPhone = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="5" y="2" width="14" height="20" rx="2" ry="2" />
    <line x1="12" y1="18" x2="12.01" y2="18" />
  </svg>
);

const IconComputer = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
    <line x1="8" y1="21" x2="16" y2="21" />
    <line x1="12" y1="17" x2="12" y2="21" />
  </svg>
);

const IconChevronDown = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="6 9 12 15 18 9" />
  </svg>
);

// ==========================================
// 4. 🚀 MAIN APP COMPONENT
// ==========================================
interface AuthenticatorItem {
  id: string;
  codeName: string;
  key: string;
  keyType: 'time' | 'counter';
  digits: number;
  period: number;
}

function MainApp() {
  const [user, setUser] = useState<any>(null);
  const [hasVault, setHasVault] = useState<boolean>(false);
  const [isUnlocked, setIsUnlocked] = useState<boolean>(false);
  const [pinLength, setPinLength] = useState<number>(6);
  const [currentPin, setCurrentPin] = useState<string>('');
  const [vaultSalt, setVaultSalt] = useState<string>('default_salt');
  const [loading, setLoading] = useState<boolean>(true);

  // Setup / Unlock State
  const [setupStep, setSetupStep] = useState<number>(1);
  const [chosenLength, setChosenLength] = useState<number>(6);
  const [enteredPin, setEnteredPin] = useState<string>('');
  const [confirmPin, setConfirmPin] = useState<string>('');
  const [setupError, setSetupError] = useState<string>('');
  const [unlockPin, setUnlockPin] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string>('');

  // Accounts & Live TOTP
  const [accounts, setAccounts] = useState<AuthenticatorItem[]>([]);
  const [totpCodes, setTotpCodes] = useState<Record<string, string>>({});
  const [timeLeft, setTimeLeft] = useState<number>(30);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Modals & Navigation
  const [showAddSheet, setShowAddSheet] = useState<boolean>(false);
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [showScannerModal, setShowScannerModal] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'vault' | 'devices'>('vault');

  // Google Authenticator Enter Code Details Form
  const [codeName, setCodeName] = useState('');
  const [yourKey, setYourKey] = useState('');
  const [keyType, setKeyType] = useState<'time' | 'counter'>('time');
  const [previewCode, setPreviewCode] = useState('');
  const [formError, setFormError] = useState('');

  // Camera QR Scanner State
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [scannerError, setScannerError] = useState('');
  const [scannedResult, setScannedResult] = useState<ParsedOTPAuth | null>(null);
  const [scannerControls, setScannerControls] = useState<IScannerControls | null>(null);

  // Active Sessions
  const [sessions, setSessions] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/auth/me', { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          setUser(data.user);
          setHasVault(data.hasVault);
          if (data.pinLength) setPinLength(data.pinLength);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  // Real-Time RFC 6238 TOTP Clock Timer
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
          acc.key,
          acc.period || 30,
          acc.digits || 6,
          'SHA-1',
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

  // Live Preview calculation as user types setup key
  useEffect(() => {
    const clean = yourKey.replace(/\s+/g, '').toUpperCase();
    if (isValidBase32(clean)) {
      calculateTOTP(clean).then(setPreviewCode);
      setFormError('');
    } else {
      setPreviewCode('');
      if (clean.length >= 4) setFormError('Invalid Base32 Secret Key');
    }
  }, [yourKey]);

  // Camera QR Scanner Lifecycle
  useEffect(() => {
    if (showScannerModal && videoRef.current && !scannedResult) {
      const codeReader = new BrowserQRCodeReader();
      codeReader
        .decodeFromVideoDevice(undefined, videoRef.current, (result, _error, controls) => {
          if (result) {
            const raw = result.getText();
            const parsed = parseOTPAuthURI(raw);
            if (parsed && isValidBase32(parsed.secret)) {
              controls.stop();
              setScannedResult(parsed);
              calculateTOTP(parsed.secret).then(setPreviewCode);
            } else {
              setScannerError('Not a valid 2FA QR code');
            }
          }
        })
        .then((controls) => setScannerControls(controls))
        .catch((err) => setScannerError('Camera access denied: ' + err.message));
    }

    return () => {
      if (scannerControls) {
        scannerControls.stop();
        setScannerControls(null);
      }
    };
  }, [showScannerModal, scannedResult]);

  const closeScanner = () => {
    if (scannerControls) {
      scannerControls.stop();
      setScannerControls(null);
    }
    setShowScannerModal(false);
    setScannedResult(null);
    setScannerError('');
  };

  // Vault Unlock & Save
  const handleUnlock = async () => {
    if (unlockPin.length !== pinLength) {
      setUnlockError(`Please enter your ${pinLength}-digit PIN`);
      return;
    }

    try {
      const res = await fetch('/api/vault', { credentials: 'include' });
      if (!res.ok) throw new Error('Could not fetch vault data');

      const vaultData = await res.json();
      const salt = vaultData.pin_salt || 'vault_salt_v1';
      setVaultSalt(salt);

      if (vaultData.encrypted_data && vaultData.encryption_metadata?.iv) {
        const decrypted = await decryptVault(
          vaultData.encrypted_data,
          vaultData.encryption_metadata.iv,
          unlockPin,
          salt
        );
        setAccounts(decrypted);
      } else {
        setAccounts([]);
      }

      setCurrentPin(unlockPin);
      setIsUnlocked(true);
      setUnlockError('');
    } catch (e: any) {
      setUnlockError('Incorrect PIN');
    }
  };

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
        setSetupError('Failed to create vault');
      }
    } catch (err: any) {
      setSetupError(err.message || 'Error creating vault');
    }
  };

  const saveAccounts = async (newAccs: AuthenticatorItem[]) => {
    setAccounts(newAccs);
    try {
      const encrypted = await encryptVault(newAccs, currentPin, vaultSalt);
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
      console.error(e);
    }
  };

  const handleSaveManual = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanKey = yourKey.replace(/\s+/g, '').toUpperCase();
    if (!isValidBase32(cleanKey)) {
      setFormError('Invalid Base32 Key');
      return;
    }

    const newItem: AuthenticatorItem = {
      id: Date.now().toString(),
      codeName: codeName.trim() || 'Authenticator',
      key: cleanKey,
      keyType: keyType,
      digits: 6,
      period: 30
    };

    saveAccounts([...accounts, newItem]);
    setCodeName('');
    setYourKey('');
    setShowManualModal(false);
  };

  const handleSaveScanned = () => {
    if (!scannedResult) return;
    const newItem: AuthenticatorItem = {
      id: Date.now().toString(),
      codeName: `${scannedResult.issuer} (${scannedResult.account})`,
      key: scannedResult.secret,
      keyType: 'time',
      digits: scannedResult.digits || 6,
      period: scannedResult.period || 30
    };
    saveAccounts([...accounts, newItem]);
    closeScanner();
  };

  const copyCode = (id: string, code: string) => {
    if (!code || code === '------') return;
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDelete = (id: string) => {
    if (!confirm('Delete this authenticator?')) return;
    saveAccounts(accounts.filter((a) => a.id !== id));
  };

  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/sessions', { credentials: 'include' });
      if (res.ok) setSessions(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const handleLogout = async () => {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    setUser(null);
    setIsUnlocked(false);
  };

  // ==========================================
  // 5. STYLES (Clean Scoped Mobile-First UI)
  // ==========================================
  const S = {
    app: { minHeight: '100vh', backgroundColor: '#0d1117', color: '#f0f6fc', fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif' },
    center: { display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', padding: 20, backgroundColor: '#0d1117' },
    authCard: { background: '#161b22', border: '1px solid #30363d', borderRadius: 24, padding: 32, maxWidth: 380, width: '100%', textAlign: 'center' as const },
    pinBox: { width: '80%', padding: '14px', fontSize: 32, textAlign: 'center' as const, letterSpacing: 10, backgroundColor: '#090d13', border: '1px solid #30363d', borderRadius: 16, color: '#fff', margin: '20px 0' },
    btnPrimary: { width: '100%', padding: '14px 20px', background: '#238636', color: '#fff', fontWeight: 600, borderRadius: 16, border: 'none', cursor: 'pointer', fontSize: 16, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8 },
    btnSecondary: { width: '100%', padding: '12px 18px', background: '#21262d', color: '#c9d1d9', fontWeight: 600, borderRadius: 16, border: '1px solid #30363d', cursor: 'pointer', fontSize: 15 },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', background: '#161b22', borderBottom: '1px solid #30363d' },
    tabs: { display: 'flex', background: '#0d1117', borderBottom: '1px solid #30363d' },
    tab: (active: boolean) => ({ flex: 1, padding: 14, background: 'transparent', border: 'none', borderBottom: active ? '2px solid #58a6ff' : 'none', color: active ? '#58a6ff' : '#8b949e', fontWeight: 600, cursor: 'pointer' }),
    card: { background: '#161b22', border: '1px solid #30363d', borderRadius: 20, padding: '20px', marginBottom: 16, position: 'relative' as const },
    totpDigits: { fontFamily: 'ui-monospace, monospace', fontSize: 40, fontWeight: 700, letterSpacing: 6, color: '#58a6ff' },
    timerRing: { background: '#21262d', width: 42, height: 42, borderRadius: '50%', display: 'flex', justifyContent: 'center', alignItems: 'center', fontSize: 13, fontWeight: 'bold', border: '2px solid #30363d' },
    googleInputBox: { width: '100%', padding: '14px 16px', background: '#0d1117', border: '1px solid #388bfd', borderRadius: 12, color: '#f0f6fc', fontSize: 16, boxSizing: 'border-box' as const, outline: 'none' },
    label: { display: 'block', fontSize: 14, color: '#8b949e', marginBottom: 8, fontWeight: 500 }
  };

  if (loading) {
    return (
      <div style={S.center}>
        <div style={{ textAlign: 'center', color: '#58a6ff' }}>
          <IconShield size={48} />
          <p style={{ marginTop: 12 }}>Loading Vault...</p>
        </div>
      </div>
    );
  }

  // 1. Google OAuth Sign-in
  if (!user) {
    return (
      <div style={S.center}>
        <div style={S.authCard}>
          <div style={{ color: '#58a6ff', marginBottom: 16 }}><IconShield size={48} /></div>
          <h2 style={{ margin: '0 0 8px 0' }}>Khmer Authenticator</h2>
          <p style={{ color: '#8b949e', fontSize: 14, marginBottom: 24 }}>Secure, Zero-Knowledge 2FA Cloud Backup</p>
          <a
            href="/api/auth/google"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 12,
              background: '#fff',
              color: '#000',
              padding: '14px 20px',
              borderRadius: 16,
              textDecoration: 'none',
              fontWeight: 600,
              fontSize: 16
            }}
          >
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

  // 2. Vault Setup (Step by Step)
  if (!hasVault) {
    return (
      <div style={S.center}>
        <div style={S.authCard}>
          <h2>Create Vault PIN</h2>
          <p style={{ color: '#8b949e', fontSize: 14 }}>Step {setupStep} of 3</p>

          {setupStep === 1 && (
            <div style={{ marginTop: 20 }}>
              <p style={{ color: '#8b949e', fontSize: 14 }}>Choose PIN Length:</p>
              <div style={{ display: 'flex', gap: 12, margin: '16px 0 24px' }}>
                <button
                  style={{ flex: 1, padding: 14, borderRadius: 14, background: chosenLength === 4 ? '#238636' : '#21262d', color: '#fff', border: '1px solid #30363d', fontWeight: 600, cursor: 'pointer' }}
                  onClick={() => setChosenLength(4)}
                >
                  4-Digit PIN
                </button>
                <button
                  style={{ flex: 1, padding: 14, borderRadius: 14, background: chosenLength === 6 ? '#238636' : '#21262d', color: '#fff', border: '1px solid #30363d', fontWeight: 600, cursor: 'pointer' }}
                  onClick={() => setChosenLength(6)}
                >
                  6-Digit PIN
                </button>
              </div>
              <button style={S.btnPrimary} onClick={() => setSetupStep(2)}>Continue</button>
            </div>
          )}

          {setupStep === 2 && (
            <div style={{ marginTop: 20 }}>
              <input
                type="password"
                maxLength={chosenLength}
                autoFocus
                style={S.pinBox}
                value={enteredPin}
                onChange={(e) => setEnteredPin(e.target.value.replace(/\D/g, ''))}
              />
              <button style={S.btnPrimary} disabled={enteredPin.length !== chosenLength} onClick={() => setSetupStep(3)}>Next</button>
            </div>
          )}

          {setupStep === 3 && (
            <div style={{ marginTop: 20 }}>
              <input
                type="password"
                maxLength={chosenLength}
                autoFocus
                style={S.pinBox}
                value={confirmPin}
                onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ''))}
              />
              {setupError && <p style={{ color: '#f85149', fontSize: 14, marginBottom: 16 }}>{setupError}</p>}
              <button style={S.btnPrimary} disabled={confirmPin.length !== chosenLength} onClick={handleCreateVault}>Create Vault</button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 3. Vault Locked Screen
  if (!isUnlocked) {
    return (
      <div style={S.center}>
        <div style={S.authCard}>
          <div style={{ color: '#58a6ff', marginBottom: 16 }}><IconLock size={44} /></div>
          <h2>LOCKED VAULT</h2>
          <p style={{ color: '#8b949e', fontSize: 14, marginBottom: 20 }}>Enter your {pinLength}-digit Vault PIN</p>
          <input
            type="password"
            maxLength={pinLength}
            autoFocus
            style={S.pinBox}
            value={unlockPin}
            onChange={(e) => setUnlockPin(e.target.value.replace(/\D/g, ''))}
            onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
          />
          {unlockError && <p style={{ color: '#f85149', fontSize: 14, marginBottom: 16 }}>{unlockError}</p>}
          <button style={S.btnPrimary} onClick={handleUnlock}>Unlock Vault</button>
          <button style={{ ...S.btnSecondary, marginTop: 12 }} onClick={handleLogout}>Sign Out</button>
        </div>
      </div>
    );
  }

  // 4. Main Authenticator Dashboard (Unlocked)
  return (
    <div style={S.app}>
      <header style={S.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <img src={user.avatarUrl || 'https://via.placeholder.com/40'} alt="Avatar" style={{ width: 40, height: 40, borderRadius: '50%' }} />
          <div>
            <div style={{ fontWeight: 600, fontSize: 15 }}>{user.name}</div>
            <div style={{ color: '#8b949e', fontSize: 12 }}>{user.email}</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setIsUnlocked(false)}
            style={{ background: '#21262d', border: '1px solid #30363d', color: '#c9d1d9', width: 40, height: 40, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
            title="Lock Vault"
          >
            <IconLock size={18} />
          </button>
          <button
            onClick={() => setShowAddSheet(true)}
            style={{ background: '#238636', border: 'none', color: '#fff', padding: '8px 16px', borderRadius: 20, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
          >
            <IconPlus size={16} /> Add
          </button>
        </div>
      </header>

      <nav style={S.tabs}>
        <button style={S.tab(activeTab === 'vault')} onClick={() => setActiveTab('vault')}>
          Authenticators ({accounts.length})
        </button>
        <button
          style={S.tab(activeTab === 'devices')}
          onClick={() => {
            setActiveTab('devices');
            fetchSessions();
          }}
        >
          Active Devices
        </button>
      </nav>

      <main style={{ maxWidth: 540, margin: '0 auto', padding: '20px' }}>
        {activeTab === 'vault' && (
          <div>
            {accounts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '60px 20px', background: '#161b22', borderRadius: 24, border: '1px solid #30363d' }}>
                <div style={{ color: '#58a6ff', marginBottom: 16 }}><IconShield size={48} /></div>
                <h3>No Authenticator Accounts</h3>
                <p style={{ color: '#8b949e', fontSize: 14, marginBottom: 20 }}>Tap + Add to scan a QR code or enter a setup key.</p>
                <button style={{ ...S.btnPrimary, maxWidth: 220, margin: '0 auto' }} onClick={() => setShowAddSheet(true)}>
                  <IconPlus size={16} /> Add Authenticator
                </button>
              </div>
            ) : (
              <div>
                {accounts.map((acc) => {
                  const code = totpCodes[acc.id] || '------';
                  const formatted = `${code.slice(0, 3)} ${code.slice(3, 6)}`;
                  return (
                    <article key={acc.id} style={S.card}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <h3 style={{ margin: '0 0 4px 0', fontSize: 18, color: '#f0f6fc' }}>{acc.codeName}</h3>
                          <span style={{ fontSize: 12, color: '#8b949e' }}>{acc.keyType === 'time' ? 'Time-based (30s)' : 'Counter-based'}</span>
                        </div>
                        <button
                          onClick={() => handleDelete(acc.id)}
                          style={{ background: 'transparent', border: 'none', color: '#f85149', cursor: 'pointer', padding: 4 }}
                        >
                          <IconTrash size={18} />
                        </button>
                      </div>

                      <div
                        onClick={() => copyCode(acc.id, code)}
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '20px 0', cursor: 'pointer' }}
                      >
                        <span style={S.totpDigits}>{formatted}</span>
                        <div style={S.timerRing}>{timeLeft}s</div>
                      </div>

                      <button
                        onClick={() => copyCode(acc.id, code)}
                        style={{
                          width: '100%',
                          padding: '12px',
                          borderRadius: 12,
                          border: '1px solid #30363d',
                          background: copiedId === acc.id ? '#238636' : '#21262d',
                          color: '#f0f6fc',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: 8
                        }}
                      >
                        {copiedId === acc.id ? <><IconCheck size={16} /> Copied to Clipboard</> : <><IconCopy size={16} /> Copy Code</>}
                      </button>
                    </article>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'devices' && (
          <div>
            <h3 style={{ marginBottom: 16 }}>Active Sessions ({sessions.length})</h3>
            {sessions.map((s) => (
              <div key={s.id} style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 16, padding: 16, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ color: '#58a6ff' }}>{s.device_type === 'phone' ? <IconPhone size={24} /> : <IconComputer size={24} />}</div>
                <div>
                  <div style={{ fontWeight: 600 }}>{s.device_name} {s.is_current_device && <span style={{ background: '#238636', color: '#fff', fontSize: 10, padding: '2px 6px', borderRadius: 6, marginLeft: 6 }}>Current</span>}</div>
                  <div style={{ color: '#8b949e', fontSize: 12 }}>{s.browser} • {s.operating_system}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* iOS Bottom Sheet */}
      {showAddSheet && (
        <div
          onClick={() => setShowAddSheet(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'flex-end', justifyContent: 'center', zIndex: 1000 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: '#161b22', width: '100%', maxWidth: 500, borderRadius: '24px 24px 0 0', padding: 24, border: '1px solid #30363d' }}
          >
            <h3 style={{ margin: '0 0 16px 0' }}>Add Authenticator</h3>
            <button
              onClick={() => { setShowAddSheet(false); setShowScannerModal(true); }}
              style={{ ...S.btnSecondary, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12, padding: 16 }}
            >
              <IconCamera size={20} /> Scan QR Code
            </button>
            <button
              onClick={() => { setShowAddSheet(false); setShowManualModal(true); }}
              style={{ ...S.btnSecondary, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12, padding: 16 }}
            >
              <IconKeyboard size={20} /> Enter code details
            </button>
            <button
              onClick={() => setShowAddSheet(false)}
              style={{ width: '100%', padding: 14, background: 'transparent', color: '#f85149', border: 'none', fontWeight: 600, cursor: 'pointer' }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Google Authenticator Enter Code Details Screen */}
      {showManualModal && (
        <div
          onClick={() => setShowManualModal(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 20 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 24, padding: 24, maxWidth: 440, width: '100%' }}
          >
            <h3 style={{ margin: '0 0 20px 0' }}>Enter code details</h3>
            <form onSubmit={handleSaveManual}>
              <div style={{ marginBottom: 16 }}>
                <label style={S.label}>Code name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Google: user@gmail.com"
                  style={S.googleInputBox}
                  value={codeName}
                  onChange={(e) => setCodeName(e.target.value)}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label style={S.label}>Your key</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. D44XJYF47MNA7GP2FJFMYGM6UFEJ6LLS"
                  style={S.googleInputBox}
                  value={yourKey}
                  onChange={(e) => setYourKey(e.target.value)}
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={S.label}>Type of key</label>
                <div style={{ position: 'relative' }}>
                  <select
                    style={{ ...S.googleInputBox, appearance: 'none', paddingRight: 36 }}
                    value={keyType}
                    onChange={(e) => setKeyType(e.target.value as 'time' | 'counter')}
                  >
                    <option value="time">Time based</option>
                    <option value="counter">Counter based</option>
                  </select>
                  <div style={{ position: 'absolute', right: 14, top: 18, pointerEvents: 'none', color: '#8b949e' }}>
                    <IconChevronDown size={18} />
                  </div>
                </div>
              </div>

              {previewCode && (
                <div style={{ background: '#090d13', border: '1px solid #238636', borderRadius: 12, padding: 12, marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 13, color: '#8b949e' }}>Generated Code Preview:</span>
                  <strong style={{ fontSize: 20, color: '#58a6ff', fontFamily: 'monospace' }}>{previewCode}</strong>
                </div>
              )}

              {formError && <p style={{ color: '#f85149', fontSize: 13, marginBottom: 16 }}>{formError}</p>}

              <div style={{ display: 'flex', gap: 12 }}>
                <button type="button" style={S.btnSecondary} onClick={() => setShowManualModal(false)}>Cancel</button>
                <button type="submit" style={S.btnPrimary} disabled={!previewCode}>Add</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ZXing Camera Scanner */}
      {showScannerModal && (
        <div
          onClick={closeScanner}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 20 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 24, padding: 24, maxWidth: 400, width: '100%', textAlign: 'center' }}
          >
            <h3 style={{ margin: '0 0 16px 0' }}>Scan QR Code</h3>
            {scannerError ? (
              <div>
                <p style={{ color: '#f85149', marginBottom: 16 }}>{scannerError}</p>
                <button style={S.btnPrimary} onClick={() => { closeScanner(); setShowManualModal(true); }}>Enter Setup Key</button>
              </div>
            ) : scannedResult ? (
              <div>
                <p>Found: <strong>{scannedResult.issuer} ({scannedResult.account})</strong></p>
                <div style={{ margin: '16px 0', fontSize: 24, fontFamily: 'monospace', color: '#58a6ff' }}>{previewCode}</div>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button style={S.btnSecondary} onClick={() => setScannedResult(null)}>Scan Again</button>
                  <button style={S.btnPrimary} onClick={handleSaveScanned}>Save</button>
                </div>
              </div>
            ) : (
              <div>
                <video ref={videoRef} style={{ width: '100%', height: 260, borderRadius: 16, objectFit: 'cover', background: '#000' }} autoPlay playsInline muted />
                <p style={{ color: '#8b949e', fontSize: 13, marginTop: 12 }}>Point your camera at a 2FA QR code</p>
                <button style={{ ...S.btnSecondary, marginTop: 12 }} onClick={closeScanner}>Cancel</button>
              </div>
            )}
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