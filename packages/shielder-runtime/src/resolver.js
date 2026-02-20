// resolver.js
// @shielderx/runtime - Node.js version

const { decryptWithKey } = require("./crypto");

function resolveSecret(placeholder) {
  if (!placeholder) return placeholder;

  try {
    // Get globals (same as React Native)
    const key = global.__SHIELDER_KEY__ ?? null;
    const store = global.__SHIELDER_STORE__ ?? null;

    if (!key || !store) {
      console.error('[ShielderX] Missing key or store in globals');
      return placeholder;
    }

    // Find the encrypted entry
    const entry = (store.secrets || []).find(s => s.placeholder === placeholder);
    
    if (!entry) {
      console.error('[ShielderX] No entry found for:', placeholder);
      return placeholder;
    }

    // Check if disabled
    if (entry.disabled) {
      return placeholder;
    }

    // Decrypt
    const decrypted = decryptWithKey(key, entry.encrypted);
    return decrypted;
  } catch (e) {
    console.error('[ShielderX] Decryption error:', e.message);
    return placeholder;
  }
}

module.exports = { resolveSecret };