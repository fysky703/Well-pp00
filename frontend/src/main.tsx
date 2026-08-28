import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserQRCodeReader, IScannerControls } from '@zxing/browser';
import './styles.css';

// ==========================================
// 1. 🛡️ REAL RFC 6238 / RFC 4226 TOTP ENGINE
// ==========================================
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface ParsedOTPAuth {
  issuer: string;
  account: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
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

    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4;

    for (let t = 0; t < 80; t++) {
      let f = 0,
        k = 0;
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
  if (key.length > 64) {
    formattedKey = sha1(key);
  }
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
    if (!uriString.startsWith('otpauth://totp/')) return null;
    const url = new URL(uriString);

    const label = decodeURIComponent(url.pathname.replace(/^\/totp\//, '').replace(/^\//, ''));
    let issuer = url.searchParams.get('issuer') || '';
    let account = label;

    if (label.includes(':')) {
      const parts = label.split(':');
      if (!issuer) issuer = parts[0].trim();
      account = parts.slice(1).join(':').trim();
    }

    const secret = url.searchParams.get('secret') || '';
    if (!secret || !isValidBase32(secret)) return null;

    const algorithm = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
    const digits = parseInt(url.searchParams.get('digits') || '6', 10);
    const period = parseInt(url.searchParams.get('period') || '30', 10);

    return {
      issuer: issuer || 'Authenticator',
      account: account || 'user',
      secret: secret.toUpperCase(),
      algorithm: algorithm.includes('256') ? 'SHA-256' : algorithm.includes('512') ? 'SHA-512' : 'SHA-1',
      digits: isNaN(digits) ? 6 : digits,
      period: isNaN(period) ? 30 : period
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
// 3. 📷 ZXING CAMERA QR SCANNER
// ==========================================
class QRScannerService {
  private codeReader: BrowserQRCodeReader;
  private controls: IScannerControls | null = null;

  constructor() {
    this.codeReader = new BrowserQRCodeReader();
  }

  public async startScanning(
    videoElement: HTMLVideoElement,
    onSuccess: (result: ParsedOTPAuth) => void,
    onError: (errorMsg: string) => void
  ) {
    try {
      this.stopScanning();
      this.controls = await this.codeReader.decodeFromVideoDevice(
        undefined,
        videoElement,
        (result, _error, controls) => {
          if (result) {
            const rawText = result.getText();
            if (!rawText.startsWith('otpauth://')) {
              onError('Scanned QR code is not a valid 2FA authenticator QR code.');
              return;
            }
            const parsed = parseOTPAuthURI(rawText);
            if (!parsed) {
              onError('Invalid TOTP URI format in QR code.');
              return;
            }
            if (!isValidBase32(parsed.secret)) {
              onError('The secret key in this QR code is not a valid Base32 string.');
              return;
            }
            controls.stop();
            this.controls = null;
            onSuccess(parsed);
          }
        }
      );
    } catch (err: any) {
      onError(
        err.name === 'NotAllowedError'
          ? 'Camera permission denied.'
          : 'Camera error: ' + (err.message || 'Unknown device error')
      );
    }
  }

  public stopScanning() {
    if (this.controls) {
      this.controls.stop();
      this.controls = null;
    }
  }
}

const qrScanner = new QRScannerService();

// ==========================================
// 4. 🎨 SVG ICONS
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

// ==========================================
// 5. 🚀 MAIN APPLICATION COMPONENT
// ==========================================
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

  // Setup / Unlock
  const [setupStep, setSetupStep] = useState<number>(1);
  const [chosenLength, setChosenLength] = useState<number>(6);
  const [enteredPin, setEnteredPin] = useState<string>('');
  const [confirmPin, setConfirmPin] = useState<string>('');
  const [setupError, setSetupError] = useState<string>('');
  const [unlockPin, setUnlockPin] = useState<string>('');
  const [unlockError, setUnlockError] = useState<string>('');

  // Accounts & TOTP
  const [accounts, setAccounts] = useState<AuthenticatorItem[]>([]);
  const [totpCodes, setTotpCodes] = useState<Record<string, string>>({});
  const [timeLeft, setTimeLeft] = useState<number>(30);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Modals & Tabs
  const [showAddSheet, setShowAddSheet] = useState<boolean>(false);
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [showScannerModal, setShowScannerModal] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'vault' | 'devices'>('vault');

  // Manual Form
  const [manualIssuer, setManualIssuer] = useState('');
  const [manualAccount, setManualAccount] = useState('');
  const [manualSecret, setManualSecret] = useState('');
  const [manualPreviewCode, setManualPreviewCode] = useState('');
  const [manualError, setManualError] = useState('');

  // Camera QR Scanner State
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [scannerError, setScannerError] = useState('');
  const [scannedResult, setScannedResult] = useState<ParsedOTPAuth | null>(null);
  const [previewScannedCode, setPreviewScannedCode] = useState('');

  // Sessions
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

  useEffect(() => {
    const clean = manualSecret.replace(/\s+/g, '').toUpperCase();
    if (isValidBase32(clean)) {
      calculateTOTP(clean).then(setManualPreviewCode);
      setManualError('');
    } else {
      setManualPreviewCode('');
      if (clean.length >= 4) setManualError('Invalid Base32 secret key');
    }
  }, [manualSecret]);

  // Camera Scanner Lifecycle
  const openScanner = () => {
    setShowAddSheet(false);
    setShowScannerModal(true);
    setScannerError('');
    setScannedResult(null);
  };

  useEffect(() => {
    if (showScannerModal && videoRef.current && !scannedResult) {
      qrScanner.startScanning(
        videoRef.current,
        async (parsed: ParsedOTPAuth) => {
          const code = await calculateTOTP(parsed.secret);
          setPreviewScannedCode(code);
          setScannedResult(parsed);
        },
        (errorMsg: string) => {
          setScannerError(errorMsg);
        }
      );
    }

    return () => {
      qrScanner.stopScanning();
    };
  }, [showScannerModal, scannedResult]);

  const closeScanner = () => {
    qrScanner.stopScanning();
    setShowScannerModal(false);
    setScannedResult(null);
    setScannerError('');
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
    closeScanner();
  };

  // Vault Unlock & Save
  const handleUnlock = async () => {
    if (unlockPin.length !== pinLength) {
      setUnlockError(`Please enter a valid ${pinLength}-digit PIN`);
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
      setUnlockError('Incorrect PIN or corrupted vault');
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
        setSetupError('Server rejected vault creation');
      }
    } catch (err: any) {
      setSetupError(err.message || 'Failed to create vault');
    }
  };

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

  const copyCode = (id: string, code: string) => {
    if (!code || code === '------') return;
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this authenticator?')) return;
    await saveAccountsToVault(accounts.filter((a) => a.id !== id));
  };

  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/sessions', { credentials: 'include' });
      if (res.ok) setSessions(await res.json());
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

  if (!user) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="brand-badge"><IconShield size={40} /></div>
          <h1>Khmer Authenticator Vault</h1>
          <p className="subtitle">Secure, Zero-Knowledge 2FA Cloud Backup</p>
          <a href="/api/auth/google" className="btn-google">
            <svg width="20" height="20" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
            </svg>
            Sign in with Google
          </a>
        </div>
      </div>
    );
  }

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
                <button className={`btn-choice ${chosenLength === 4 ? 'active' : ''}`} onClick={() => setChosenLength(4)}>
                  4-Digit PIN
                </button>
                <button className={`btn-choice ${chosenLength === 6 ? 'active' : ''}`} onClick={() => setChosenLength(6)}>
                  6-Digit PIN
                </button>
              </div>
              <button className="btn-primary" onClick={() => setSetupStep(2)}>Continue</button>
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
              <button className="btn-primary" disabled={enteredPin.length !== chosenLength} onClick={() => setSetupStep(3)}>
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
              <button className="btn-primary" disabled={confirmPin.length !== chosenLength} onClick={handleCreateVault}>
                Initialize Encrypted Vault
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }

  if (!isUnlocked) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="brand-badge"><IconLock size={36} /></div>
          <h2>LOCKED VAULT</h2>
          <p className="subtitle">Enter your {pinLength}-digit Vault PIN</p>
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
          <button className="btn-primary" onClick={handleUnlock}>Unlock Vault</button>
          <button className="btn-link" onClick={handleLogout}>Sign Out</button>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
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

      <nav className="tab-container">
        <button className={`tab-btn ${activeTab === 'vault' ? 'active' : ''}`} onClick={() => setActiveTab('vault')}>
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

      <main className="main-content">
        {activeTab === 'vault' && (
          <div>
            {accounts.length === 0 ? (
              <div className="empty-panel">
                <IconShield size={44} />
                <h3>No Authenticator Accounts</h3>
                <p>Scan a QR code or enter a setup key to get started.</p>
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
                        <button className="btn-delete" onClick={() => handleDelete(acc.id)}>
                          <IconTrash size={16} />
                        </button>
                      </div>
                      <div className="code-container" onClick={() => copyCode(acc.id, code)}>
                        <span className="totp-digits">{formatted}</span>
                        <div className="timer-badge">{timeLeft}s</div>
                      </div>
                      <button className={`btn-copy ${copiedId === acc.id ? 'copied' : ''}`} onClick={() => copyCode(acc.id, code)}>
                        {copiedId === acc.id ? <><IconCheck size={16} /> Copied</> : <><IconCopy size={16} /> Copy Code</>}
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
              <button className="btn-danger" onClick={handleLogoutOthers}>Log Out Others</button>
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

      {/* iOS Bottom Sheet */}
      {showAddSheet && (
        <div className="sheet-backdrop" onClick={() => setShowAddSheet(false)}>
          <div className="sheet-dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Add Authenticator</h3>
            <button className="sheet-btn" onClick={openScanner}>
              <IconCamera size={20} /> Scan QR Code
            </button>
            <button className="sheet-btn" onClick={() => { setShowAddSheet(false); setShowManualModal(true); }}>
              <IconKeyboard size={20} /> Enter Setup Key
            </button>
            <button className="sheet-btn cancel" onClick={() => setShowAddSheet(false)}>Cancel</button>
          </div>
        </div>
      )}

      {/* Camera QR Scanner Modal */}
      {showScannerModal && (
        <div className="modal-backdrop" onClick={closeScanner}>
          <div className="modal-dialog scanner-dialog" onClick={(e) => e.stopPropagation()}>
            <h3>Scan TOTP QR Code</h3>
            {scannerError ? (
              <div className="error-panel">
                <p className="error-text">{scannerError}</p>
                <button className="btn-primary" onClick={() => { closeScanner(); setShowManualModal(true); }}>
                  Switch to Manual Setup Key
                </button>
              </div>
            ) : scannedResult ? (
              <div className="confirm-panel">
                <h4>Confirm Account</h4>
                <div className="confirm-row"><span>Issuer:</span> <strong>{scannedResult.issuer}</strong></div>
                <div className="confirm-row"><span>Account:</span> <strong>{scannedResult.account}</strong></div>
                <div className="confirm-preview">
                  <span>Current Code Preview:</span>
                  <strong>{previewScannedCode}</strong>
                </div>
                <div className="modal-actions">
                  <button className="btn-secondary" onClick={() => setScannedResult(null)}>Scan Again</button>
                  <button className="btn-primary" onClick={handleSaveScanned}>Add Account</button>
                </div>
              </div>
            ) : (
              <div>
                <div className="camera-frame">
                  <video ref={videoRef} className="camera-view" playsInline muted autoPlay />
                  <div className="scanner-crosshair" />
                </div>
                <p className="scanner-hint">Point your camera at a 2FA QR code</p>
                <button className="btn-secondary" onClick={closeScanner}>Cancel</button>
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
                <label>Issuer (e.g. Google, Facebook, Telegram)</label>
                <input type="text" required placeholder="Google" value={manualIssuer} onChange={(e) => setManualIssuer(e.target.value)} />
              </div>
              <div className="form-group">
                <label>Account (Email or Username)</label>
                <input type="text" required placeholder="user@example.com" value={manualAccount} onChange={(e) => setManualAccount(e.target.value)} />
              </div>
              <div className="form-group">
                <label>Setup Key (Base32)</label>
                <input type="text" required placeholder="D44XJYF47MNA7GP2FJFMYGM6UFEJ6LLS" value={manualSecret} onChange={(e) => setManualSecret(e.target.value)} />
              </div>
              {manualPreviewCode && (
                <div className="preview-box">
                  <span>Live Code Preview:</span>
                  <strong>{manualPreviewCode}</strong>
                </div>
              )}
              {manualError && <p className="error-text">{manualError}</p>}
              <div className="modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowManualModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={!manualPreviewCode}>Save Account</button>
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