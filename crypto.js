/* ============================================================
 * Password-derived encryption for the ASA portal.
 *
 * Pattern: PBKDF2(password, salt, 600000, SHA-256) → AES-GCM key
 *          → encrypt(secrets JSON) → ciphertext stored in vault.json
 *
 * Security: anyone with vault.json can attempt offline brute force.
 * Strength = password strength. Pick long, unique passphrases.
 * ============================================================ */

const KDF_ITERATIONS = 600000;

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToB64(bytes) {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(password, saltBytes) {
  const material = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: KDF_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptJSON(obj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(obj))
  );
  return {
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ct: bytesToB64(ct),
    iter: KDF_ITERATIONS,
  };
}

async function decryptJSON(blob, password) {
  const salt = b64ToBytes(blob.salt);
  const iv = b64ToBytes(blob.iv);
  const ct = b64ToBytes(blob.ct);
  const key = await deriveKey(password, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(dec.decode(pt));
  } catch (e) {
    return null; // wrong password — auth tag mismatch
  }
}

// expose
window.AsaCrypto = { encryptJSON, decryptJSON };
