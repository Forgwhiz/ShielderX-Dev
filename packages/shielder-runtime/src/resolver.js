const { loadProjectKey } = require("./key-loader");
const { loadSecretStore } = require("./store-loader");
const { decryptPayload } = require("./crypto");
const {
  ShielderRuntimeError,
  ShielderSecretNotFoundError
} = require("./errors");

function resolveSecret(placeholder) {
  if (!placeholder || typeof placeholder !== "string") {
    throw new ShielderRuntimeError("Invalid secret placeholder.");
  }

  const key = loadProjectKey();
  const store = loadSecretStore();

  if (!Array.isArray(store.secrets)) {
    throw new ShielderRuntimeError("Invalid secret store format.");
  }

  const entry = store.secrets.find(
    s => s.placeholder === placeholder
  );

  if (!entry) {
    throw new ShielderSecretNotFoundError(placeholder);
  }

  if (entry.disabled) {
    throw new ShielderRuntimeError(
      `Secret is disabled: ${placeholder}`
    );
  }

  return decryptPayload(entry.encrypted, key);
}

module.exports = { resolveSecret };
