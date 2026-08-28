/**
 * RFC 6238 / RFC 4226 Standard TOTP Algorithm
 * Exact mathematical implementation matching Google Authenticator
 */

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function isValidBase32(secret: string): boolean {
  const clean = secret.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || clean.length < 4) return false;
  for (let i = 0; i < clean.length; i++) {
    if (!BASE32_CHARS.includes(clean[i])) {
      return false;
    }
  }
  return true;
}

/**
 * Robust RFC 4648 Base32 Decoder
 */
export function base32ToBytes(base32: string): Uint8Array {
  const clean = base32.toUpperCase().replace(/[\s=-]/g, '');
  let length = clean.length;
  let bits = 0;
  let value = 0;
  let index = 0;
  
  // Base32 gives 5 bits per character
  const bytes = new Uint8Array(Math.floor((length * 5) / 8));

  for (let i = 0; i < length; i++) {
    const val = BASE32_CHARS.indexOf(clean[i]);
    if (val === -1) continue;

    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bytes[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return bytes;
}

/**
 * Generates Real RFC 6238 TOTP 6-digit Code
 */
export async function calculateTOTP(
  secret: string,
  period = 30,
  digits = 6,
  algorithm = 'SHA-1',
  timestamp = Date.now()
): Promise<string> {
  try {
    const keyBytes = base32ToBytes(secret);
    if (keyBytes.length === 0) return '------';

    // 1. Calculate time step
    const epoch = Math.floor(timestamp / 1000);
    const counter = Math.floor(epoch / period);

    // 2. Prepare 8-byte big-endian counter buffer
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(0, 0, false);
    view.setUint32(4, counter, false);

    // 3. HMAC using Web Crypto API
    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: 'SHA-1' } },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, buffer);
    const hmac = new Uint8Array(signature);

    // 4. Dynamic Truncation
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const code = binary % Math.pow(10, digits);
    return code.toString().padStart(digits, '0');
  } catch (err) {
    console.error('TOTP Generation Error:', err);
    return '------';
  }
}

export function getRemainingSeconds(period = 30, timestamp = Date.now()): number {
  const epoch = Math.floor(timestamp / 1000);
  return period - (epoch % period);
}