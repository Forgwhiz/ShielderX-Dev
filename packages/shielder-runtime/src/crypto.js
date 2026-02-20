// crypto.js
// @shielderx/runtime - Node.js version

const crypto = require("crypto");

/**
 * Decrypt using AES-256-CBC (same as React Native)
 * @param {string} keyBase64 - Base64 encoded key
 * @param {object} payload - {iv: base64, data: base64}
 * @returns {string} Decrypted plaintext
 */
function decryptWithKey(keyBase64, payload) {
  try {
    // Convert base64 to buffers
    const key = Buffer.from(keyBase64, 'base64');
    const iv = Buffer.from(payload.iv, 'base64');
    const data = Buffer.from(payload.data, 'base64');

    // Decrypt using AES-256-CBC (matching React Native)
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  } catch (error) {
    console.error('[ShielderX] Decryption failed:', error.message);
    throw error;
  }
}

module.exports = { decryptWithKey };