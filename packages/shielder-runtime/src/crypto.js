const crypto = require("crypto");
const { ShielderRuntimeError } = require("./errors");

function decryptPayload(payload, key) {
  try {
    const iv = Buffer.from(payload.iv, "hex");
    const tag = Buffer.from(payload.tag, "hex");
    const encrypted = Buffer.from(payload.data, "hex");

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);

    return decrypted.toString("utf8");
  } catch {
    throw new ShielderRuntimeError("Failed to decrypt secret.");
  }
}

module.exports = { decryptPayload };
