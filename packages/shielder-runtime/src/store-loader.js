const fs = require("fs");
const path = require("path");
const {
  ShielderRuntimeError,
  ShielderStoreNotFoundError
} = require("./errors");

function loadSecretStore(baseDir = process.cwd()) {
  const storePath = path.join(baseDir, ".ai-secret-guard.json");

  if (!fs.existsSync(storePath)) {
    throw new ShielderStoreNotFoundError();
  }

  let data;
  try {
    data = JSON.parse(fs.readFileSync(storePath, "utf8"));
  } catch {
    throw new ShielderRuntimeError(
      "Invalid secret store format (JSON parse failed)."
    );
  }

  // ---- STRICT SCHEMA VALIDATION ----
  if (
    typeof data !== "object" ||
    data === null ||
    !Array.isArray(data.secrets)
  ) {
    throw new ShielderRuntimeError(
      "Invalid secret store format (missing secrets array)."
    );
  }

  return data;
}

module.exports = { loadSecretStore };
