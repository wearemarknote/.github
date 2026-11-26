// The share viewer: AES-GCM under a key derived with HKDF, and a password
// stretched with PBKDF2, which the fixture manifest does not declare.
export async function open(keyBytes, iv, ciphertext) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
}

export async function stretch(password, salt) {
  const base = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, base, 256);
}
