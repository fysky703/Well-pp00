/**
 * RFC 6238 / RFC 4226 Standard TOTP Engine
 * Uses Web Crypto API (SubtleCrypto) for hardware-accelerated HMAC-SHA1
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Validates whether a string is a valid Base32 encoded secret.
 */
export function isValidBase32(secret: string): boolean {
  const clean = secret.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || clean.length < 4) return false;
  for (let i = 0; i < clean.length; i++) {
    if (!BASE32_ALPHABET.includes(clean[i])) {
      return false;
    }
  }
  return true;
}

/**
 * Decodes a Base32 string into a raw Uint8Array byte buffer.
 */
export function base32ToBytes(base32: string): Uint8Array {
  const clean = base32.toUpperCase().replace(/[\s=-]/g, '');
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  return bytes;
}

/**
 * Calculates RFC 6238 TOTP 6-digit passcode.
 * Guaranteed to match Google Authenticator, 1Password, and Authy for identical secrets & timestamps.
 */
export async function calculateTOTP(
  secret: string,
  period = 30,
  digits = 6,
  algorithm = 'SHA-1',
  timestamp = Date.now()
): Promise<string> {
  const keyBytes = base32ToBytes(secret);
  if (keyBytes.length === 0) return '------';

  // 1. Time step count (8-byte integer in network byte order / big-endian)
  const epoch = Math.floor(timestamp / 1000);
  const counter = Math.floor(epoch / period);

  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, 0, false);
  view.setUint32(4, counter, false);

  // 2. Import Key for Web Crypto HMAC
  const hashName = algorithm.toUpperCase() === 'SHA-256' ? 'SHA-256' : algorithm.toUpperCase() === 'SHA-512' ? 'SHA-512' : 'SHA-1';
  
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: hashName } },
    false,
    ['sign']
  );

  // 3. Generate HMAC Signature
  const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, buffer);
  const hash = new Uint8Array(signature);

  // 4. Dynamic Truncation (RFC 4226 Section 5.4)
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Calculates remaining seconds in the current global TOTP period window.
 */
export function getRemainingSeconds(period = 30, timestamp = Date.now()): number {
  const epoch = Math.floor(timestamp / 1000);
  return period - (epoch % period);
}

/**
 * Parses otpauth://totp/ URI according to Key Uri Format specification.
 */
export interface ParsedOTPAuth {
  issuer: string;
  account: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
}

export function parseOTPAuthURI(uriString: string): ParsedOTPAuth | null {
  try {
    if (!uriString.startsWith('otpauth://totp/')) return null;
    const url = new URL(uriString);
    
    // Path extraction: /Issuer:Account or /Account
    let label = decodeURIComponent(url.pathname.replace(/^\/totp\//, '').replace(/^\//, ''));
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