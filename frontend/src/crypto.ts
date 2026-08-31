/**
 * Zero-Knowledge Vault Encryption
 * Derives a 256-bit AES key from user's PIN via PBKDF2 (100,000 iterations).
 * Data is encrypted with AES-GCM with a unique 12-byte IV per sync.
 */

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

export async function encryptVault(data: any, pin: string, salt: string): Promise<{ ciphertext: string; iv: string }> {
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
    iv: btoa(String.fromCharCode(...iv))
  };
}

export async function decryptVault(ciphertextBase64: string, ivBase64: string, pin: string, salt: string): Promise<any> {
  const key = await deriveKeyFromPin(pin, salt);
  const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
  const data = new Uint8Array(atob(ciphertextBase64).split('').map(c => c.charCodeAt(0)));

  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}