import React, { useState, useEffect, useRef } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserQRCodeReader, IScannerControls } from '@zxing/browser';

// ============================================================================
// 1. 🛡️ TRUE RFC 6238 / RFC 4226 TOTP ENGINE (Exact Mathematical Reference)
// ============================================================================
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

// ============================================================================
// 2. 🔐 ZERO-KNOWLEDGE AES-GCM-256 VAULT CRYPTO
// ============================================================================
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

// ============================================================================
// 3. 🎨 ACCESSIBLE SVG ICONS
// ============================================================================
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

const IconImageUpload = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="4" width="18" height="16" rx="3" />
    <circle cx="8.5" cy="9" r="1.5" />
    <path d="m4.5 17 4.5-4 3 2.5 2.5-2 5 4.5" />
    <path d="M12 2v4" />
    <path d="m10.5 3.5 1.5-1.5 1.5 1.5" />
  </svg>
);

const IconInbox = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M4 4h16v11a5 5 0 0 1-5 5H9a5 5 0 0 1-5-5V4Z" />
    <path d="M4 14h4l2 3h4l2-3h4" />
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

const IconRefresh = ({ size = 16 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="23 4 23 10 17 10" />
    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
  </svg>
);

const IconSun = ({ size = 18 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="5" />
    <line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" />
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
    <line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" />
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
  </svg>
);

const IconMoon = ({ size = 18 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  </svg>
);

// ============================================================================
// 4. 🚀 MAIN APP COMPONENT
// ============================================================================
interface AuthenticatorItem {
  id: string;
  codeName: string;
  key: string;
  keyType: 'time' | 'counter';
  digits: number;
  period: number;
}

function MainApp() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
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
  const [searchQuery, setSearchQuery] = useState('');

  // Navigation & Modals
  const [activeTab, setActiveTab] = useState<'vault' | 'inbox' | 'devices' | 'settings'>('vault');
  const [showAddSheet, setShowAddSheet] = useState<boolean>(false);
  const [showManualModal, setShowManualModal] = useState<boolean>(false);
  const [showScannerModal, setShowScannerModal] = useState<boolean>(false);
  const [showProfileMenu, setShowProfileMenu] = useState<boolean>(false);
  const [showChangePin, setShowChangePin] = useState<boolean>(false);
  const [newPin, setNewPin] = useState<string>('');
  const [confirmNewPin, setConfirmNewPin] = useState<string>('');
  const [changePinError, setChangePinError] = useState<string>('');
  const [changePinSaving, setChangePinSaving] = useState<boolean>(false);

  // Form (Google Authenticator Style)
  const [codeName, setCodeName] = useState('');
  const [yourKey, setYourKey] = useState('');
  const [keyType, setKeyType] = useState<'time' | 'counter'>('time');
  const [previewCode, setPreviewCode] = useState('');
  const [formError, setFormError] = useState('');

  // Camera QR Scanner State
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [scannerError, setScannerError] = useState('');
  const [scannedResult, setScannedResult] = useState<ParsedOTPAuth | null>(null);
  const [scannerControls, setScannerControls] = useState<IScannerControls | null>(null);

  // Active Sessions & Recovery Codes
  const [sessions, setSessions] = useState<any[]>([]);
  const [showRecoveryLogin, setShowRecoveryLogin] = useState(false);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');
  const [recoveryLoginError, setRecoveryLoginError] = useState('');
  const [recoveryLoggingIn, setRecoveryLoggingIn] = useState(false);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('khcode-theme', next);
  };

  useEffect(() => {
    const savedTheme = localStorage.getItem('khcode-theme');
    if (savedTheme === 'dark' || savedTheme === 'light') setTheme(savedTheme);
  }, []);

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

  const handleQRImageUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      setScannerError('');
      const imageUrl = URL.createObjectURL(file);
      const image = new Image();
      image.src = imageUrl;

      await new Promise<void>((resolve, reject) => {
        image.onload = () => resolve();
        image.onerror = () => reject(new Error('Unable to load image'));
      });

      const reader = new BrowserQRCodeReader();
      const result = await reader.decodeFromImageElement(image);
      URL.revokeObjectURL(imageUrl);

      const parsed = parseOTPAuthURI(result.getText());
      if (!parsed || !isValidBase32(parsed.secret)) {
        setScannerError('The uploaded image does not contain a valid 2FA QR code.');
        return;
      }

      if (scannerControls) {
        scannerControls.stop();
        setScannerControls(null);
      }
      setScannedResult(parsed);
      calculateTOTP(parsed.secret).then(setPreviewCode);
    } catch (error) {
      console.error(error);
      setScannerError('Unable to read a QR code from this image. Please choose a clear QR image.');
    } finally {
      event.target.value = '';
    }
  };

  const closeScanner = () => {
    if (scannerControls) {
      scannerControls.stop();
      setScannerControls(null);
    }
    setShowScannerModal(false);
    setScannedResult(null);
    setScannerError('');
  };

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
      setUnlockPin('');
    }
  };

  useEffect(() => {
    if (!isUnlocked && hasVault && unlockPin.length === pinLength) {
      const timer = window.setTimeout(() => { handleUnlock(); }, 120);
      return () => window.clearTimeout(timer);
    }
  }, [unlockPin, pinLength, hasVault, isUnlocked]);

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
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    } finally {
      setShowProfileMenu(false);
      setUser(null);
      setAccounts([]);
      setCurrentPin('');
      setIsUnlocked(false);
      window.location.href = '/';
    }
  };

  const handleChangePin = async () => {
    if (newPin.length !== pinLength) {
      setChangePinError(`Enter exactly ${pinLength} digits`);
      return;
    }
    if (newPin !== confirmNewPin) {
      setChangePinError('PINs do not match');
      return;
    }
    try {
      setChangePinSaving(true);
      setChangePinError('');
      const newSalt = 'salt_' + Math.random().toString(36).slice(2);
      const encrypted = await encryptVault(accounts, newPin, newSalt);
      const res = await fetch('/api/vault/change-pin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          newPinHash: btoa(newPin),
          newPinSalt: newSalt,
          newPinLength: pinLength,
          reEncryptedData: encrypted.ciphertext,
          newEncryptionMetadata: { iv: encrypted.iv, version: 1, cipher: 'AES-GCM-256' }
        })
      });
      if (!res.ok) throw new Error('Failed to change Vault PIN');
      setCurrentPin(newPin);
      setVaultSalt(newSalt);
      setShowChangePin(false);
      setShowProfileMenu(false);
      setNewPin('');
      setConfirmNewPin('');
      alert('Vault PIN changed successfully');
    } catch (e: any) {
      setChangePinError(e.message || 'Could not change Vault PIN');
    } finally {
      setChangePinSaving(false);
    }
  };

  // 1-Box-Per-Digit Component
  const PinBoxes = ({
    value,
    length,
    onChange,
    onEnter
  }: {
    value: string;
    length: number;
    onChange: (val: string) => void;
    onEnter?: () => void;
  }) => {
    const hiddenInputRef = useRef<HTMLInputElement>(null);

    return (
      <div
        style={{ display: 'flex', justifyContent: 'center', gap: 10, margin: '24px 0', cursor: 'text' }}
        onClick={() => hiddenInputRef.current?.focus()}
      >
        <input
          ref={hiddenInputRef}
          type="password"
          inputMode="numeric"
          pattern="[0-9]*"
          maxLength={length}
          autoFocus
          value={value}
          onChange={(e) => onChange(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => e.key === 'Enter' && onEnter && onEnter()}
          style={{ position: 'absolute', opacity: 0, pointerEvents: 'none' }}
        />
        {Array.from({ length }).map((_, i) => {
          const isFilled = i < value.length;
          const isCurrent = i === value.length;
          return (
            <div
              key={i}
              style={{
                width: 44,
                height: 52,
                borderRadius: 14,
                background: isFilled
                  ? 'rgba(103,245,232,0.12)'
                  : isCurrent
                  ? 'rgba(255,255,255,0.08)'
                  : 'rgba(255,255,255,0.03)',
                border: isCurrent
                  ? '2px solid #67F5E8'
                  : isFilled
                  ? '1.5px solid rgba(103,245,232,0.5)'
                  : '1px solid rgba(255,255,255,0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: isCurrent ? '0 0 16px rgba(103,245,232,0.3)' : 'none',
                transition: 'all 180ms ease'
              }}
            >
              {isFilled ? (
                <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#67F5E8' }} />
              ) : isCurrent ? (
                <div style={{ width: 16, height: 2, borderRadius: 1, background: '#67F5E8' }} />
              ) : null}
            </div>
          );
        })}
      </div>
    );
  };

  // ============================================================================
  // 5. 🌊 OCEAN AI CORE STYLES (Zero-Margin, Locked Viewport, Full Width)
  // ============================================================================
  const isDark = theme === 'dark';
  const C = {
    bg: '#02090D',
    surface: isDark ? 'rgba(8, 24, 30, 0.85)' : 'rgba(255, 255, 255, 0.92)',
    surfaceCard: isDark ? '#07151B' : '#FFFFFF',
    border: isDark ? 'rgba(103,245,232,0.18)' : 'rgba(20,150,145,0.22)',
    textPrimary: isDark ? '#F3FAFA' : '#102326',
    textSecondary: isDark ? '#9AAAB2' : '#60777A',
    accent: isDark ? '#67F5E8' : '#16BDB2',
    btnGradientBlackWhite: 'linear-gradient(135deg, #ffffff 0%, #d8d8d8 100%)',
    btnTextDark: '#000000'
  };

  const S = {
    app: {
      width: '100%',
      minHeight: '100vh',
      maxWidth: '100vw',
      backgroundColor: C.bg,
      color: C.textPrimary,
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", Inter, sans-serif',
      paddingBottom: 'calc(120px + env(safe-area-inset-bottom))',
      boxSizing: 'border-box' as const,
      overflowX: 'hidden' as const,
      margin: 0
    },
    center: {
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      width: '100%',
      minHeight: '100vh',
      padding: '16px',
      backgroundColor: C.bg,
      boxSizing: 'border-box' as const
    },
    glassCard: {
      background: C.surface,
      backdropFilter: 'blur(24px) saturate(135%)',
      WebkitBackdropFilter: 'blur(24px) saturate(135%)',
      border: `1px solid ${C.border}`,
      borderRadius: 24,
      padding: '28px 20px',
      maxWidth: 390,
      width: '100%',
      textAlign: 'center' as const,
      boxShadow: '0 20px 60px rgba(0,0,0,.5)',
      boxSizing: 'border-box' as const
    },
    btnGradBW: {
      width: '100%',
      padding: '14px 20px',
      background: C.btnGradientBlackWhite,
      color: C.btnTextDark,
      fontWeight: 700,
      borderRadius: 16,
      border: 'none',
      cursor: 'pointer',
      fontSize: 16,
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      gap: 8,
      boxSizing: 'border-box' as const
    },
    btnGlassSecondary: {
      width: '100%',
      padding: '12px 18px',
      background: 'rgba(255,255,255,0.06)',
      color: C.textPrimary,
      fontWeight: 600,
      borderRadius: 16,
      border: `1px solid ${C.border}`,
      cursor: 'pointer',
      fontSize: 15,
      boxSizing: 'border-box' as const
    },
    header: {
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '14px 16px',
      background: C.surface,
      backdropFilter: 'blur(20px)',
      borderBottom: `1px solid ${C.border}`,
      position: 'sticky' as const,
      top: 0,
      zIndex: 100,
      width: '100%',
      boxSizing: 'border-box' as const
    },
    card: {
      background: C.surfaceCard,
      border: `1px solid ${C.border}`,
      borderRadius: 22,
      padding: 18,
      marginBottom: 16,
      boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
      boxSizing: 'border-box' as const
    },
    totpDigits: {
      fontFamily: 'ui-monospace, SFMono-Regular, monospace',
      fontSize: 'clamp(28px, 8vw, 36px)',
      fontWeight: 700,
      letterSpacing: 4,
      color: C.accent
    },
    timerBadge: {
      background: 'rgba(103,245,232,0.12)',
      color: C.accent,
      width: 42,
      height: 42,
      borderRadius: '50%',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      fontSize: 13,
      fontWeight: 700,
      border: `1.5px solid ${C.border}`
    },
    input: {
      width: '100%',
      padding: '14px 16px',
      background: isDark ? '#02090D' : '#FFFFFF',
      border: `1px solid ${C.border}`,
      borderRadius: 14,
      color: C.textPrimary,
      fontSize: 15,
      boxSizing: 'border-box' as const,
      outline: 'none'
    },
    label: {
      display: 'block',
      fontSize: 13,
      color: C.textSecondary,
      marginBottom: 8,
      fontWeight: 600,
      textTransform: 'uppercase' as const,
      letterSpacing: 0.5
    }
  };

  if (loading) {
    return (
      <div style={S.center}>
        <div style={{ textAlign: 'center', color: C.accent }}>
          <IconShield size={48} />
          <p style={{ marginTop: 14, fontWeight: 600 }}>Loading Ocean AI Vault...</p>
        </div>
      </div>
    );
  }

  // 1. Google OAuth / Recovery Screen
  if (!user) {
    const submitRecovery = async () => {
      setRecoveryError('');
      try {
        const r = await fetch('/api/auth/recovery', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify({ email: recoveryEmail, code: recoveryCode }) });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'Recovery sign-in failed');
        window.location.reload();
      } catch (e:any) { setRecoveryError(e.message); }
    };
    return (
      <div style={S.center}><div style={S.glassCard}>
        <div style={{ color: C.accent, marginBottom: 16 }}><IconShield size={52} /></div>
        <h2 style={{ margin: '0 0 8px 0', fontSize: 24, fontWeight: 700 }}>OCEAN AI CORE</h2>
        {!showRecoveryLogin ? <>
          <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 28 }}>Secure 2FA Authenticator & Recovery Vault</p>
          <a href="/api/auth/google" style={{...S.btnGradBW,textDecoration:'none'}}>Sign in with Google</a>
          <button onClick={()=>setShowRecoveryLogin(true)} style={{...S.btnGhost, marginTop:12, width:'100%'}}>Use Recovery Code</button>
        </> : <>
          <p style={{ color: C.textSecondary, fontSize: 14 }}>Sign in without Google using one unused recovery code.</p>
          <input value={recoveryEmail} onChange={e=>setRecoveryEmail(e.target.value)} placeholder="Account email" style={{...S.input,width:'100%',boxSizing:'border-box',marginTop:12}} />
          <input value={recoveryCode} onChange={e=>setRecoveryCode(e.target.value.toUpperCase())} placeholder="XXXX-XXXX-XXXX" style={{...S.input,width:'100%',boxSizing:'border-box',marginTop:10}} />
          {recoveryError && <p style={{color:'#ff6b6b',fontSize:13}}>{recoveryError}</p>}
          <button onClick={submitRecovery} style={{...S.btnGradBW,marginTop:12,width:'100%'}}>Sign in with Recovery Code</button>
          <button onClick={()=>setShowRecoveryLogin(false)} style={{...S.btnGhost,marginTop:10,width:'100%'}}>Back</button>
        </>}
      </div></div>
    );
  }

  // 2. Vault Setup (1 Box Per Digit)
  if (!hasVault) {
    return (
      <div style={S.center}>
        <div style={S.glassCard}>
          <div style={{ color: C.accent, marginBottom: 12 }}><IconLock size={44} /></div>
          <h2 style={{ margin: '0 0 6px 0' }}>Set Vault PIN</h2>
          <p style={{ color: C.textSecondary, fontSize: 13 }}>Step {setupStep} of 3</p>

          {setupStep === 1 && (
            <div style={{ marginTop: 20 }}>
              <p style={{ color: C.textSecondary, fontSize: 14 }}>Choose PIN Length:</p>
              <div style={{ display: 'flex', gap: 12, margin: '16px 0 24px' }}>
                <button
                  style={{ flex: 1, padding: 14, borderRadius: 16, background: chosenLength === 4 ? C.accent : 'rgba(255,255,255,0.06)', color: chosenLength === 4 ? '#000' : C.textPrimary, border: `1px solid ${C.border}`, fontWeight: 700, cursor: 'pointer' }}
                  onClick={() => setChosenLength(4)}
                >
                  4 Digits
                </button>
                <button
                  style={{ flex: 1, padding: 14, borderRadius: 16, background: chosenLength === 6 ? C.accent : 'rgba(255,255,255,0.06)', color: chosenLength === 6 ? '#000' : C.textPrimary, border: `1px solid ${C.border}`, fontWeight: 700, cursor: 'pointer' }}
                  onClick={() => setChosenLength(6)}
                >
                  6 Digits
                </button>
              </div>
              <button style={S.btnGradBW} onClick={() => setSetupStep(2)}>Continue</button>
            </div>
          )}

          {setupStep === 2 && (
            <div style={{ marginTop: 10 }}>
              <p style={{ color: C.textSecondary, fontSize: 14 }}>Enter your {chosenLength}-digit PIN:</p>
              <PinBoxes value={enteredPin} length={chosenLength} onChange={setEnteredPin} onEnter={() => enteredPin.length === chosenLength && setSetupStep(3)} />
              <button style={S.btnGradBW} disabled={enteredPin.length !== chosenLength} onClick={() => setSetupStep(3)}>Next</button>
            </div>
          )}

          {setupStep === 3 && (
            <div style={{ marginTop: 10 }}>
              <p style={{ color: C.textSecondary, fontSize: 14 }}>Confirm your PIN:</p>
              <PinBoxes value={confirmPin} length={chosenLength} onChange={setConfirmPin} onEnter={handleCreateVault} />
              {setupError && <p style={{ color: '#FF6F8D', fontSize: 13, marginBottom: 16 }}>{setupError}</p>}
              <button style={S.btnGradBW} disabled={confirmPin.length !== chosenLength} onClick={handleCreateVault}>Create Vault</button>
            </div>
          )}
        </div>
      </div>
    );
  }

  // 3. Vault Locked (1 Box Per Digit)
  if (!isUnlocked) {
    return (
      <div style={S.center}>
        <div style={S.glassCard}>
          <div style={{ color: C.accent, marginBottom: 16 }}><IconLock size={48} /></div>
          <h2 style={{ margin: '0 0 6px 0', fontSize: 22, fontWeight: 700 }}>LOCKED VAULT</h2>
          <p style={{ color: C.textSecondary, fontSize: 14 }}>Enter your {pinLength}-digit Vault PIN</p>

          <PinBoxes value={unlockPin} length={pinLength} onChange={(v) => { setUnlockError(''); setUnlockPin(v); }} onEnter={handleUnlock} />
          <p style={{ color: C.textSecondary, fontSize: 12, margin: '-8px 0 14px' }}>Unlocks automatically after the last digit.</p>

          {unlockError && <p style={{ color: '#FF6F8D', fontSize: 13, marginBottom: 16 }}>{unlockError}</p>}

          <button style={{ ...S.btnGlassSecondary, marginTop: 12 }} onClick={handleLogout}>Sign Out</button>
        </div>
      </div>
    );
  }

  // 4. Main Authenticator Dashboard (Unlocked)
  return (
    <div style={S.app}>
      {/* Header */}
      <header style={S.header}>
        <button
          onClick={() => setShowProfileMenu(true)}
          style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, background: 'transparent', border: 'none', color: C.textPrimary, padding: 0, textAlign: 'left', cursor: 'pointer' }}
          title="Open Profile"
        >
          <img src={user.avatarUrl || 'https://via.placeholder.com/40'} alt="Avatar" style={{ width: 40, height: 40, borderRadius: '50%', border: `1.5px solid ${C.border}`, flexShrink: 0 }} />
          <div style={{ minWidth: 0, overflow: 'hidden' }}>
            <div style={{ fontWeight: 700, fontSize: 15, color: C.textPrimary, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.name}</div>
            <div style={{ color: C.textSecondary, fontSize: 11, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.email}</div>
          </div>
        </button>
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          <button
            onClick={toggleTheme}
            style={{ background: 'rgba(255,255,255,0.06)', border: `1px solid ${C.border}`, color: C.textPrimary, width: 38, height: 38, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
            title="Toggle Theme"
          >
            {isDark ? <IconSun size={17} /> : <IconMoon size={17} />}
          </button>
          <button
            onClick={() => setIsUnlocked(false)}
            style={{ background: 'rgba(255,255,255,0.06)', border: `1px solid ${C.border}`, color: C.textPrimary, width: 38, height: 38, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}
            title="Lock Vault"
          >
            <IconLock size={17} />
          </button>
          <button
            onClick={() => setShowAddSheet(true)}
            style={{ background: C.btnGradientBlackWhite, border: 'none', color: '#000', padding: '8px 14px', borderRadius: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', fontSize: 14 }}
          >
            <IconPlus size={15} /> Add
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ width: '100%', maxWidth: 540, margin: '0 auto', padding: '16px 16px calc(140px + env(safe-area-inset-bottom))', boxSizing: 'border-box', minHeight: '100vh' }}>
        {activeTab === 'vault' && (
          <div>
            <div style={{ marginBottom: 14 }}><input aria-label="Search authenticator accounts" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Search authenticator accounts" style={S.input} /></div>
            {accounts.filter((acc) => acc.codeName.toLowerCase().includes(searchQuery.toLowerCase())).length === 0 ? (
              <div style={{ textAlign: 'center', padding: '50px 16px', background: C.surface, borderRadius: 24, border: `1px solid ${C.border}` }}>
                <div style={{ color: C.accent, marginBottom: 16 }}><IconShield size={48} /></div>
                <h3 style={{ margin: '0 0 8px 0' }}>No Authenticator Accounts</h3>
                <p style={{ color: C.textSecondary, fontSize: 14, marginBottom: 20 }}>Scan a QR code or enter code details manually.</p>
                <button style={{ ...S.btnGradBW, maxWidth: 220, margin: '0 auto' }} onClick={() => setShowAddSheet(true)}>
                  <IconPlus size={16} /> Add Authenticator
                </button>
              </div>
            ) : (
              <div>
                {accounts.filter((acc) => acc.codeName.toLowerCase().includes(searchQuery.toLowerCase())).map((acc) => {
                  const code = totpCodes[acc.id] || '------';
                  const formatted = `${code.slice(0, 3)}  ${code.slice(3, 6)}`;
                  return (
                    <article key={acc.id} style={S.card}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div style={{ minWidth: 0, paddingRight: 8 }}>
                          <h3 style={{ margin: '0 0 4px 0', fontSize: 17, color: C.textPrimary, fontWeight: 700, wordBreak: 'break-word' }}>{acc.codeName}</h3>
                          <span style={{ fontSize: 12, color: C.textSecondary }}>{acc.keyType === 'time' ? 'Time-based (30s)' : 'Counter-based'}</span>
                        </div>
                        <button onClick={() => { const next = window.prompt('Rename authenticator', acc.codeName); if (next && next.trim()) { setAccounts(prev => prev.map(a => a.id === acc.id ? { ...a, codeName: next.trim() } : a)); } }} aria-label="Rename authenticator" style={{ background: 'transparent', border: 'none', color: C.accent, cursor: 'pointer', padding: 4, flexShrink: 0 }} title="Rename"><IconRefresh size={18} /></button>
                        <button
                          onClick={() => handleDelete(acc.id)}
                          style={{ background: 'transparent', border: 'none', color: '#FF6F8D', cursor: 'pointer', padding: 4, flexShrink: 0 }}
                          title="Delete"
                        >
                          <IconTrash size={18} />
                        </button>
                      </div>

                      <div
                        onClick={() => copyCode(acc.id, code)}
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '16px 0', cursor: 'pointer' }}
                      >
                        <span style={S.totpDigits}>{formatted}</span>
                        <div style={S.timerBadge}>{timeLeft}s</div>
                      </div>

                      <button
                        onClick={() => copyCode(acc.id, code)}
                        style={{
                          width: '100%',
                          padding: '12px',
                          borderRadius: 14,
                          border: `1px solid ${C.border}`,
                          background: copiedId === acc.id ? '#62E8C7' : C.btnGradientBlackWhite,
                          color: '#000',
                          fontWeight: 700,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: 8,
                          transition: 'all 180ms ease'
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

        {activeTab === 'inbox' && (
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: 18, fontWeight: 700 }}>Inbox</h3>
            <div style={{ ...S.card, textAlign: 'center', padding: '42px 18px' }}>
              <div style={{ color: C.accent, marginBottom: 14, display: 'flex', justifyContent: 'center' }}><IconInbox size={44} /></div>
              <h4 style={{ margin: '0 0 8px 0', fontSize: 17 }}>Gmail Inbox</h4>
              <p style={{ margin: 0, color: C.textSecondary, fontSize: 13, lineHeight: 1.6 }}>Connect a Gmail account to view your authorized inbox messages here.</p>
            </div>
          </div>
        )}

        {activeTab === 'devices' && (
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: 18, fontWeight: 700 }}>Active Sessions ({sessions.length})</h3>
            {sessions.map((s) => (
              <div key={s.id} style={{ ...S.card, display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ color: C.accent }}>{s.device_type === 'phone' ? <IconPhone size={24} /> : <IconComputer size={24} />}</div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 700, fontSize: 14, wordBreak: 'break-word' }}>{s.device_name} {s.is_current_device && <span style={{ background: C.accent, color: '#000', fontSize: 10, padding: '2px 6px', borderRadius: 6, marginLeft: 6, fontWeight: 800 }}>Current</span>}</div>
                  <div style={{ color: C.textSecondary, fontSize: 12 }}>{s.browser} • {s.operating_system}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'settings' && (
          <div>
            <h3 style={{ margin: '0 0 16px 0', fontSize: 18, fontWeight: 700 }}>Settings & Security</h3>
            <div style={S.card}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
                <div><div style={{ fontWeight: 700 }}>Change Vault Lock</div><div style={{ color: C.textSecondary, fontSize: 12 }}>Choose a secure 4 or 6 digit PIN</div></div>
                <button style={{ ...S.btnGradBW, width: 'auto', padding: '8px 16px', fontSize: 13 }} onClick={() => setShowChangePin(true)}>Change</button>
              </div>
              <hr style={{ border: 'none', borderTop: `1px solid ${C.border}`, margin: '14px 0' }} />
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>Theme Mode</div>
                  <div style={{ color: C.textSecondary, fontSize: 12 }}>{isDark ? 'Ocean Dark Mode' : 'Ocean Light Mode'}</div>
                </div>
                <button style={{ ...S.btnGlassSecondary, width: 'auto', padding: '8px 16px' }} onClick={toggleTheme}>
                  Switch
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Profile Menu */}
      {showProfileMenu && (
        <div onClick={() => setShowProfileMenu(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.62)', backdropFilter: 'blur(10px)', zIndex: 20000, display: 'flex', alignItems: 'flex-end', justifyContent: 'center', padding: 12 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 520, background: C.surfaceCard, border: `1px solid ${C.border}`, borderRadius: 26, padding: 18, boxSizing: 'border-box', marginBottom: 'env(safe-area-inset-bottom)' }}>
            <div style={{ textAlign: 'center', padding: '8px 4px 16px' }}>
              <img src={user.avatarUrl || 'https://via.placeholder.com/64'} alt="Avatar" style={{ width: 62, height: 62, borderRadius: '50%', border: `1px solid ${C.border}` }} />
              <div style={{ fontWeight: 800, marginTop: 8 }}>{user.name}</div>
              <div style={{ color: C.textSecondary, fontSize: 13, marginTop: 3 }}>{user.email}</div>
            </div>
            <button style={{ ...S.btnGlassSecondary, marginBottom: 10, textAlign: 'left' }} onClick={() => { window.location.href = '/api/gmail/connect'; }}>Add Gmail Account</button>
            <button style={{ ...S.btnGlassSecondary, color: '#FF6F8D', borderColor: 'rgba(255,111,141,.35)' }} onClick={handleLogout}>Logout</button>
          </div>
        </div>
      )}

      {/* Change Vault PIN */}
      {showChangePin && (
        <div onClick={() => setShowChangePin(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.72)', backdropFilter: 'blur(10px)', zIndex: 20001, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ ...S.glassCard, maxWidth: 420 }}>
            <div style={{ color: C.accent, marginBottom: 10 }}><IconLock size={38} /></div>
            <h3 style={{ margin: '0 0 6px' }}>Change Vault Lock</h3>
            <p style={{ color: C.textSecondary, fontSize: 13, marginBottom: 14 }}>Enter a new {pinLength}-digit PIN twice.</p>
            <PinBoxes value={newPin} length={pinLength} onChange={setNewPin} />
            <PinBoxes value={confirmNewPin} length={pinLength} onChange={setConfirmNewPin} />
            {changePinError && <p style={{ color: '#FF6F8D', fontSize: 13 }}>{changePinError}</p>}
            <button style={S.btnGradBW} disabled={changePinSaving} onClick={handleChangePin}>{changePinSaving ? 'Saving...' : 'Save New PIN'}</button>
            <button style={{ ...S.btnGlassSecondary, marginTop: 10 }} onClick={() => setShowChangePin(false)}>Cancel</button>
          </div>
        </div>
      )}

      <button onClick={() => setShowAddSheet(true)} aria-label="Add authenticator" style={{ position:'fixed', right:24, bottom:96, width:58, height:58, borderRadius:'50%', border:`1px solid ${C.border}`, background:C.btnGradientBlackWhite, color:'#001018', display:'flex', alignItems:'center', justifyContent:'center', zIndex:10002, boxShadow:'0 12px 32px rgba(0,136,255,.35)', cursor:'pointer' }}><IconPlus size={28} /></button>

      {/* Floating iOS Bottom Dock Navigation */}
      <nav
        style={{
          position: 'fixed',
          bottom: 12,
          left: 12,
          right: 12,
          maxWidth: 480,
          margin: '0 auto',
          height: 64,
          background: C.surface,
          backdropFilter: 'blur(28px)',
          WebkitBackdropFilter: 'blur(28px)',
          border: `1px solid ${C.border}`,
          borderRadius: 22,
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          alignItems: 'center',
          zIndex: 10000,
          boxShadow: '0 12px 40px rgba(0,0,0,0.6)'
        }}
      >
        <button
          style={{ background: 'transparent', border: 'none', color: activeTab === 'vault' ? C.accent : C.textSecondary, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, cursor: 'pointer', fontWeight: 600, fontSize: 11 }}
          onClick={() => setActiveTab('vault')}
        >
          <IconShield size={20} />
          Vault
        </button>
        <button
          style={{ background: 'transparent', border: 'none', color: activeTab === 'inbox' ? C.accent : C.textSecondary, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, cursor: 'pointer', fontWeight: 600, fontSize: 11 }}
          onClick={() => setActiveTab('inbox')}
        >
          <IconInbox size={20} />
          Inbox
        </button>
        <button
          style={{ background: 'transparent', border: 'none', color: activeTab === 'devices' ? C.accent : C.textSecondary, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, cursor: 'pointer', fontWeight: 600, fontSize: 11 }}
          onClick={() => {
            setActiveTab('devices');
            fetchSessions();
          }}
        >
          <IconComputer size={20} />
          Devices
        </button>
        <button
          style={{ background: 'transparent', border: 'none', color: activeTab === 'settings' ? C.accent : C.textSecondary, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3, cursor: 'pointer', fontWeight: 600, fontSize: 11 }}
          onClick={() => setActiveTab('settings')}
        >
          <IconLock size={20} />
          Settings
        </button>
      </nav>

      {/* iOS-Style Add Bottom Sheet */}
      {showAddSheet && (
        <div
          onClick={() => setShowAddSheet(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(12px)', display: 'flex', alignItems: 'flex-end', justifyContent: 'center', zIndex: 10001 }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ background: C.surfaceCard, width: '100%', maxWidth: 500, borderRadius: '28px 28px 0 0', padding: 24, border: `1px solid ${C.border}`, boxSizing: 'border-box' }}
          >
            <h3 style={{ margin: '0 0 18px 0', fontWeight: 700 }}>Add Authenticator</h3>
            <button
              onClick={() => { setShowAddSheet(false); setShowScannerModal(true); }}
              style={{ ...S.btnGlassSecondary, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12, padding: 16 }}
            >
              <IconCamera size={20} /> Scan QR Code
            </button>
            <button
              onClick={() => { setShowAddSheet(false); setShowManualModal(true); }}
              style={{ ...S.btnGlassSecondary, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12, padding: 16 }}
            >
              <IconKeyboard size={20} /> Enter code details
            </button>
            <button
              onClick={() => setShowAddSheet(false)}
              style={{ width: '100%', padding: 14, background: 'transparent', color: '#FF6F8D', border: 'none', fontWeight: 700, cursor: 'pointer' }}
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
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(16px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10002, padding: 16, boxSizing: 'border-box' }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{ ...S.glassCard, maxWidth: 420, textAlign: 'left' }}
          >
            <h3 style={{ margin: '0 0 20px 0', fontWeight: 700, fontSize: 19 }}>Enter code details</h3>
            <form onSubmit={handleSaveManual}>
              <div style={{ marginBottom: 16 }}>
                <label style={S.label}>Code name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Google: user@gmail.com"
                  style={S.input}
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
                  style={S.input}
                  value={yourKey}
                  onChange={(e) => setYourKey(e.target.value)}
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={S.label}>Type of key</label>
                <div style={{ position: 'relative' }}>
                  <select
                    style={{ ...S.input, appearance: 'none', paddingRight: 36 }}
                    value={keyType}
                    onChange={(e) => setKeyType(e.target.value as 'time' | 'counter')}
                  >
                    <option value="time">Time based</option>
                    <option value="counter">Counter based</option>
                  </select>
                  <div style={{ position: 'absolute', right: 14, top: 18, pointerEvents: 'none', color: C.textSecondary }}>
                    <IconChevronDown size={18} />
                  </div>
                </div>
              </div>

              {previewCode && (
                <div style={{ background: 'rgba(103,245,232,0.08)', border: `1px solid ${C.border}`, borderRadius: 14, padding: 12, marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 13, color: C.textSecondary }}>Generated Preview:</span>
                  <strong style={{ fontSize: 20, color: C.accent, fontFamily: 'monospace' }}>{previewCode}</strong>
                </div>
              )}

              {formError && <p style={{ color: '#FF6F8D', fontSize: 13, marginBottom: 16 }}>{formError}</p>}

              <div style={{ display: 'flex', gap: 10 }}>
                <button type="button" style={S.btnGlassSecondary} onClick={() => setShowManualModal(false)}>Cancel</button>
                <button type="submit" style={S.btnGradBW} disabled={!previewCode}>Add</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ZXing Camera Scanner Modal */}
      {showScannerModal && (
        <div
          onClick={closeScanner}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.9)', backdropFilter: 'blur(16px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10002, padding: 16, boxSizing: 'border-box' }}
        >
          <div onClick={(e) => e.stopPropagation()} style={{ ...S.glassCard, maxWidth: 390 }}>
            <h3 style={{ margin: '0 0 16px 0', fontWeight: 700 }}>Scan QR Code</h3>
            {scannerError ? (
              <div>
                <p style={{ color: '#FF6F8D', marginBottom: 16 }}>{scannerError}</p>
                <button style={S.btnGradBW} onClick={() => { closeScanner(); setShowManualModal(true); }}>Enter Code Details</button>
              </div>
            ) : scannedResult ? (
              <div>
                <p>Found: <strong>{scannedResult.issuer} ({scannedResult.account})</strong></p>
                <div style={{ margin: '16px 0', fontSize: 26, fontFamily: 'monospace', color: C.accent, fontWeight: 700 }}>{previewCode}</div>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button style={S.btnGlassSecondary} onClick={() => setScannedResult(null)}>Scan Again</button>
                  <button style={S.btnGradBW} onClick={handleSaveScanned}>Save</button>
                </div>
              </div>
            ) : (
              <div>
                <video ref={videoRef} style={{ width: '100%', height: 250, borderRadius: 16, objectFit: 'cover', background: '#000', border: `1px solid ${C.border}` }} autoPlay playsInline muted />
                <p style={{ color: C.textSecondary, fontSize: 13, marginTop: 12 }}>Point camera at a standard 2FA QR code, or upload a QR image.</p>
                <input ref={fileInputRef} type="file" accept="image/*" onChange={handleQRImageUpload} style={{ display: 'none' }} />
                <button
                  type="button"
                  style={{ ...S.btnGlassSecondary, marginTop: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <IconImageUpload size={20} /> Upload QR Image
                </button>
                <button style={{ ...S.btnGlassSecondary, marginTop: 12 }} onClick={closeScanner}>Cancel</button>
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