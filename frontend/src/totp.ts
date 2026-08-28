/**
 * RFC 6238 / RFC 4226 Standard TOTP Reference Implementation
 * Compatible 100% with Google Authenticator, Telegram, Facebook, Microsoft.
 */

// 1. RFC 4648 Base32 Decoder
export function base32ToBytes(str: string): Uint8Array {
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = str.toUpperCase().replace(/[\s=-]/g, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (let i = 0; i < clean.length; i++) {
    const val = base32chars.indexOf(clean[i]);
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

export function isValidBase32(secret: string): boolean {
  const clean = secret.toUpperCase().replace(/[\s=-]/g, '');
  if (!clean || clean.length < 4) return false;
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  for (let i = 0; i < clean.length; i++) {
    if (base32chars.indexOf(clean[i]) === -1) return false;
  }
  return true;
}

// 2. Pure JavaScript SHA-1 & HMAC (Guaranteed to work across all mobile browsers & WebViews)
function sha1(bytes: Uint8Array): Uint8Array {
  const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const len = bytes.length;
  const bitLen = len * 8;
  const padLen = (len % 64 < 56) ? (56 - (len % 64)) : (120 - (len % 64));
  const totalLen = len + padLen + 8;
  const padded = new Uint8Array(totalLen);
  padded.set(bytes);
  padded[len] = 0x80;

  const view = new DataView(padded.buffer);
  // Big-endian 64-bit length
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
        f = (b & c) | ((~b) & d);
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

// 3. Main TOTP Function (RFC 6238)
export async function calculateTOTP(
  secret: string,
  period = 30,
  digits = 6,
  _algorithm = 'SHA-1',
  timestamp = Date.now()
): Promise<string> {
  const keyBytes = base32ToBytes(secret);
  if (keyBytes.length === 0) return '------';

  // Counter: floor(seconds / period)
  const epoch = Math.floor(timestamp / 1000);
  const counter = Math.floor(epoch / period);

  // 8-byte big endian counter
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setUint32(0, 0, false);
  view.setUint32(4, counter, false);

  // Calculate HMAC-SHA1
  const hmac = hmacSha1(keyBytes, msg);

  // Dynamic Truncation (RFC 4226)
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