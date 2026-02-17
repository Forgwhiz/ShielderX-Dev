// resolver.js - FIXED VERSION
// @shielderx/react-native-runtime

const { decryptWithKey } = require("./crypto");

function resolveSecret(placeholder) {
  if (!placeholder) return placeholder;

  try {
    // Get globals
    const key = global.__SHIELDER_KEY__ ?? null;
    const store = global.__SHIELDER_STORE__ ?? null;

    // Debug logging
    console.log('[ShielderX] resolveSecret called with:', placeholder);
    console.log('[ShielderX] Key exists:', !!key);
    console.log('[ShielderX] Store exists:', !!store);

    if (!key || !store) {
      console.error('[ShielderX] MISSING KEY OR STORE');
      console.error('[ShielderX] Key:', key ? 'EXISTS' : 'NULL');
      console.error('[ShielderX] Store:', store ? 'EXISTS' : 'NULL');
      return placeholder;
    }

    // Find the encrypted entry
    const entry = (store.secrets || []).find(s => s.placeholder === placeholder);
    
    if (!entry) {
      console.error('[ShielderX] No entry found for placeholder:', placeholder);
      console.error('[ShielderX] Available placeholders:', store.secrets?.map(s => s.placeholder) || []);
      return placeholder;
    }

    console.log('[ShielderX] Found entry for:', placeholder);
    console.log('[ShielderX] Entry structure:', JSON.stringify(entry, null, 2));

    // Decrypt
    const decrypted = decryptWithKey(key, entry.encrypted);
    console.log('[ShielderX] Decryption successful:', decrypted ? 'YES' : 'NO');
    
    return decrypted;
  } catch (e) {
    console.error('[ShielderX] Decryption error:', e);
    console.error('[ShielderX] Error stack:', e.stack);
    return placeholder;
  }
}

module.exports = { resolveSecret };
