// crypto.js
// @shielderx/react-native-runtime

const CryptoJS = require("crypto-js");

function decryptWithKey(keyBase64, payload) {
  console.log('[ShielderX Crypto] Starting decryption...');
  console.log('[ShielderX Crypto] Key length:', keyBase64 ? keyBase64.length : 0);
  console.log('[ShielderX Crypto] Payload:', JSON.stringify(payload));

  try {
    const key = CryptoJS.enc.Base64.parse(keyBase64);
    const iv = CryptoJS.enc.Base64.parse(payload.iv);

    const decrypted = CryptoJS.AES.decrypt(
      { ciphertext: CryptoJS.enc.Base64.parse(payload.data) },
      key,
      {
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );

    const result = decrypted.toString(CryptoJS.enc.Utf8);
    console.log('[ShielderX Crypto] Decryption result length:', result.length);
    
    return result;
  } catch (error) {
    console.error('[ShielderX Crypto] Decryption failed:', error);
    throw error;
  }
}

module.exports = { decryptWithKey };