/*********************************
 * ⚠️ SECURITY GUARANTEE
 * This extension MUST NEVER decrypt secrets.
 * Runtime decryption is handled ONLY by @shielder/runtime.
 *
 * EXCEPTION:
 * - Temporary in-memory decrypt is allowed ONLY for key rotation.
 *********************************/

const vscode = require("vscode");
const path = require("path");
const crypto = require("crypto");

let shielderStatusBar;

/*********************************
 * CONSTANTS
 *********************************/
const ALGORITHM = "aes-256-gcm";
const PROJECT_KEY_FILE = ".shielder.key";
const SECRET_FILE = ".ai-secret-guard.json";

const RECOVERY_FILE = ".shielder.recovery";

const RUNTIME_FILE = "shielderx.runtime.js";
const METRO_CONFIG_FILE = "metro.config.js";

/*********************************
 * REGEX RULES
 *********************************/
const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PHONE_REGEX = /^\+?\d[\d\s-]{7,14}\d$/;
const API_KEY_REGEX = /^(sk_live_|sk_test_|AIzaSy)[A-Za-z0-9_-]+$/;

const STRING_ASSIGN_REGEX =
  /\b(const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*["'`]([^"'`]+)["'`]/g;

const STRING_LITERAL_REGEX = /["'`]([^"'`\n]+)["'`]/g;

const SHIELDER_PROTECT_CALL_REGEX =
  /ShielderX\.protect\(\s*["'`]([^"'`]+)["'`]\s*\)/g;


  const RESOLVE_SECRET_REGEX =
  /resolveSecret\(\s*["'`]<SECRET_[A-Z0-9]+>["'`]\s*\)/;

const HARD_EXCLUDED_FILES = new Set([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.json",
  "podfile.lock",
  "Podfile.lock",
   "README.md",
   "shielderx.runtime.js",
   "metro.config.js",
  "Info.plist" // optional: iOS metadata
]);


  const internalFsOps = new Set();

const SHIELDER_INTERNAL_FILES = new Set([
  PROJECT_KEY_FILE, // .shielder.key
  SECRET_FILE,  // .ai-secret-guard.json
  RECOVERY_FILE   ,
  RUNTIME_FILE,
  METRO_CONFIG_FILE       
]);

/*********************************
 * FINGERPRINT (DAY 9.3)
 *********************************/

function findResolveSecretRange(document, position) {
  const line = document.lineAt(position.line);
  const text = line.text;

  const regex =
    /resolveSecret\(\s*["'`]<SECRET_[A-Z0-9]+>["'`]\s*\)/g;

  let match;
  while ((match = regex.exec(text))) {
    const start = match.index;
    const end = start + match[0].length;

    if (
      position.character >= start &&
      position.character <= end
    ) {
      return new vscode.Range(
        position.line,
        start,
        position.line,
        end
      );
    }
  }
  return null;
}


function isLikelyKey(value) {
  if (!value) return false;

  // minimum length you want to support
  if (value.length < 7) return false;

  // ❌ Clearly human-readable → skip
  if (/^[a-zA-Z\s]+$/.test(value)) return false;       // plain words
  if (/^[A-Z_]+$/.test(value)) return false;           // APP_START
  if (/^[a-z]+(-[a-z]+)+$/.test(value)) return false;  // kebab-case
  if (/^[a-zA-Z_]+$/.test(value)) return false;        // identifiers
  if (/^[\p{Emoji}\s:]+$/u.test(value)) return false; // emoji / log text

  // ✅ Everything else is considered a key
  return true;
}



function shouldSkipScanFile(uri) {
  const fsPath = uri.fsPath;
  const fileName = path.basename(fsPath);

  // 🚫 Skip dot folders anywhere (.git, .vscode, .expo, etc.)
  if (fsPath.includes(`${path.sep}.`)) {
    return true;
  }

  if (SHIELDER_INTERNAL_FILES.has(fileName)) return true;
  if (HARD_EXCLUDED_FILES.has(fileName)) return true;

  return false;
}



async function generateProjectFingerprint(workspaceFolder) {
  const rootPath = workspaceFolder.uri.fsPath;

  let pkgName = "unknown";
  try {
    const pkgUri = vscode.Uri.joinPath(workspaceFolder.uri, "package.json");
    const pkg = JSON.parse(
      (await vscode.workspace.fs.readFile(pkgUri)).toString()
    );
    pkgName = pkg.name || "unknown";
  } catch { }

  const stat = await vscode.workspace.fs.stat(workspaceFolder.uri);
  const created = stat.ctime.toString();

  const salt = crypto
    .createHash("sha256")
    .update(`shielderx:${workspaceFolder.uri.fsPath}`)
    .digest("hex")
    .slice(0, 32);

  const raw = `${rootPath}|${pkgName}|${created}|${salt}`;

  return crypto.createHash("sha256").update(raw).digest("hex");
}

async function packageJsonHas(ws, pkgName) {
  try {
    const pkgUri = vscode.Uri.joinPath(ws.uri, "package.json");
    const raw = await vscode.workspace.fs.readFile(pkgUri);
    const pkg = JSON.parse(raw.toString());

    return Boolean(
      (pkg.dependencies && pkg.dependencies[pkgName]) ||
      (pkg.devDependencies && pkg.devDependencies[pkgName])
    );
  } catch {
    return false;
  }
}




const PLATFORMS = [
 {
  id: "react-native",
  supportsRuntime: true,
  detect: async (ws) =>
    (await packageJsonHas(ws, "react-native")) ||
    (await packageJsonHas(ws, "expo")) ||
    (await isExpoProject(ws)) ||              // ✅ REQUIRED
    (await fileExists(ws, "app.json")) ||
    (await fileExists(ws, "expo-env.d.ts")) ||
    (await fileExists(ws, "ios")) ||
    (await fileExists(ws, "android"))
},
  {
    id: "flutter",
    supportsRuntime: true,
    detect: async (ws) => await fileExists(ws, "pubspec.yaml")
  },
 
  // Java
  {
    id: "java",
    supportsRuntime: false,
    detect: async (ws) =>
      await fileExists(ws, "pom.xml") ||
      await fileExists(ws, "build.gradle")
  },

  // Python
  {
    id: "python",
    supportsRuntime: false,
    detect: async (ws) =>
      await fileExists(ws, "requirements.txt") ||
      await fileExists(ws, "pyproject.toml")
  },

  // Go
  {
    id: "go",
    supportsRuntime: false,
    detect: async (ws) => await fileExists(ws, "go.mod")
  },

  // PHP
  {
    id: "php",
    supportsRuntime: false,
    detect: async (ws) => await fileExists(ws, "composer.json")
  },

  // C#
  {
    id: "dotnet",
    supportsRuntime: false,
    detect: async (ws) => await fileExists(ws, "*.csproj")
  },
  {
    id: "backend",
    supportsRuntime: false,
    detect: async (ws) =>
      await fileExists(ws, "pom.xml") ||
      await fileExists(ws, "build.gradle") ||
      await fileExists(ws, "requirements.txt") ||
      await fileExists(ws, "go.mod") ||
      await fileExists(ws, "composer.json") ||
      await fileExists(ws, "*.csproj")
  },
   { // JavaScript / TypeScript (frontend + Node backend)
    id: "javascript",
    supportsRuntime: true,
    detect: async (ws) => await fileExists(ws, "package.json")
  },
];


async function detectPlatform(ws) {
  for (const p of PLATFORMS) {
    if (await p.detect(ws)) return p;
  }
  return null;
}



function getRuntimeImport(platform) {
  if (!platform) return null;

  if (platform.id === "react-native") {
    return '@shielderx/react-native-runtime';
  }

  if (platform.supportsRuntime) {
    return '@shielderx/runtime';
  }

  return null;
}



/*********************************
 * KEY MANAGEMENT
 *********************************/
// async function ensureProjectKey(workspaceFolder) {
//   const uri = vscode.Uri.joinPath(workspaceFolder.uri, PROJECT_KEY_FILE);
//   try {
//     await vscode.workspace.fs.readFile(uri);
//     vscode.window.showInformationMessage("🔑 Project key already exists");
//   } catch {
//     const key = crypto.randomBytes(32);
//     await vscode.workspace.fs.writeFile(uri, key);
//     vscode.window.showWarningMessage(
//       "🔐 Project key generated. Backup `.shielder.key`. Losing it = losing secrets."
//     );
//   }
// }

async function isProjectAlreadyProtected(ws) {
  // Check if any source file has resolveSecret() calls
  // This survives even if ALL ShielderX files are deleted
  try {
    const files = await vscode.workspace.findFiles(
      "**/*.{js,ts,jsx,tsx}",
      "{**/node_modules/**,**/.vscode/**,**/.expo/**}",
      20 // only check first 20 files for speed
    );

    for (const file of files) {
      if (shouldSkipScanFile(file)) continue;
      const content = (await vscode.workspace.fs.readFile(file)).toString();
      if (/<SECRET_[A-Z0-9]+>/.test(content)) {
        return true; // Found a placeholder → project IS protected
      }
    }
  } catch {}

  return false;
}

// New logic 
async function ensureProjectKey(workspaceFolder, extensionContext) {
  const uri = vscode.Uri.joinPath(workspaceFolder.uri, PROJECT_KEY_FILE);

  try {
    await vscode.workspace.fs.readFile(uri);
    return; // Key exists, nothing to do
  } catch {
    // Key doesn't exist - this machine is creating it = OWNER
    const key = crypto.randomBytes(32);
    const header = Buffer.from("SHIELDER_KEY_v1\n", "utf8");
    const payload = Buffer.concat([header, key]);

    // Save to project file
    await vscode.workspace.fs.writeFile(uri, payload);

    // ✅ Save to globalState (OWNER ONLY - only runs on first creation)
    await saveKeyToGlobalState(workspaceFolder, key, extensionContext);

    vscode.window.showWarningMessage(
      "🔐 Project key generated. You are the recovery owner."
    );
  }
}

async function saveKeyToGlobalState(ws, key, extensionContext) {
  try {
    const fingerprint = await generateProjectFingerprint(ws);

    // Get project name
    let projectName = path.basename(ws.uri.fsPath);
    try {
      const pkg = JSON.parse(
        (await vscode.workspace.fs.readFile(
          vscode.Uri.joinPath(ws.uri, "package.json")
        )).toString()
      );
      projectName = pkg.name || projectName;
    } catch {}

    // Storage key is unique per project
    const storageKey = `shielderx-key-${fingerprint.slice(0, 16)}`;

    const storageValue = JSON.stringify({
      key: key.toString("base64"),
      project: projectName,
      projectPath: ws.uri.fsPath,
      owner: {
        user: require("os").userInfo().username,
        host: require("os").hostname(),
        savedAt: new Date().toISOString()
      }
    });

    await extensionContext.globalState.update(storageKey, storageValue);
    console.log(`[ShielderX] Key backed up as owner: ${storageKey}`);
  } catch (e) {
    console.warn("[ShielderX] Could not save to globalState:", e.message);
  }
}

async function isOwner(ws, extensionContext) {
  const fingerprint = await generateProjectFingerprint(ws);
  const storageKey = `shielderx-key-${fingerprint.slice(0, 16)}`;
  const stored = extensionContext.globalState.get(storageKey);
  return !!stored;
}


async function getKeyFromGlobalState(ws, extensionContext) {
  const fingerprint = await generateProjectFingerprint(ws);
  const storageKey = `shielderx-key-${fingerprint.slice(0, 16)}`;
  const stored = extensionContext.globalState.get(storageKey);
  if (!stored) return null;

  try {
    const parsed = JSON.parse(stored);
    return Buffer.from(parsed.key, "base64");
  } catch {
    return null;
  }
}

async function generateRecovery(ws, extensionContext) {

  const hasKey      = await fileExists(ws, PROJECT_KEY_FILE);
  const hasStore    = await fileExists(ws, SECRET_FILE);
  const hasRuntime  = await fileExists(ws, RUNTIME_FILE);
  const hasMetro    = await fileExists(ws, METRO_CONFIG_FILE);
  const hasRecovery = await fileExists(ws, RECOVERY_FILE);

  const missing = [
    !hasKey      && ".shielder.key",
    !hasStore    && ".ai-secret-guard.json",
    !hasRuntime  && RUNTIME_FILE,
    !hasMetro    && METRO_CONFIG_FILE,
    !hasRecovery && ".shielder.recovery"
  ].filter(Boolean);

  // ─────────────────────────────────────────────
  // CASE 1: Nothing missing → just refresh recovery
  // ─────────────────────────────────────────────
  if (missing.length === 0) {
    await writeRecoveryFile(ws, extensionContext);
    vscode.window.showInformationMessage("✅ ShielderX: Recovery file refreshed!");
    return;
  }

  // ─────────────────────────────────────────────
  // CASE 2: Key exists → rebuild missing files
  // ─────────────────────────────────────────────
  if (hasKey) {
    const confirm = await vscode.window.showWarningMessage(
      `⚠️ ShielderX: ${missing.length} file(s) missing!\n\n` +
      `${missing.map(f => `• ${f}`).join('\n')}\n\n` +
      `Key found. Regenerate missing files?`,
      { modal: true },
      "Regenerate",
      "Cancel"
    );
    if (confirm !== "Regenerate") return;

    await rebuildMissingFiles(ws, extensionContext, {
      hasStore, hasRuntime, hasMetro, hasRecovery
    });
    return;
  }

  // ─────────────────────────────────────────────
  // CASE 3: Key missing → check if owner
  // ─────────────────────────────────────────────
  const ownerKey = await getKeyFromGlobalState(ws, extensionContext);

  if (ownerKey) {
    const confirm = await vscode.window.showWarningMessage(
      `⚠️ ShielderX: Files missing!\n\n` +
      `${missing.map(f => `• ${f}`).join('\n')}\n\n` +
      `You are the recovery owner. Restore all files?`,
      { modal: true },
      "Restore All",
      "Cancel"
    );
    if (confirm !== "Restore All") return;

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "ShielderX: Restoring files...",
      cancellable: false
    }, async (progress) => {

      // 1. Restore key file first
      progress.report({ message: "Restoring .shielder.key...", increment: 15 });
      const keyUri = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);
      markInternalOp(keyUri);
      await vscode.workspace.fs.writeFile(keyUri, Buffer.concat([
        Buffer.from("SHIELDER_KEY_v1\n"),
        ownerKey
      ]));
      unmarkInternalOp(keyUri);

      // 2. Rebuild all other missing files
      await rebuildMissingFiles(ws, extensionContext, {
        hasStore, hasRuntime, hasMetro, hasRecovery
      }, progress);
    });

    // vscode.window.showInformationMessage(
    //   `✅ ShielderX: All files restored!\n\nPush to Git so teammates can pull.`,
    //   { modal: true },
    //   "OK"
    // );

  } else {
    // Not owner - get owner info from store if available
    let ownerInfo = "the developer who ran the first scan";
    if (hasStore) {
      try {
        const existingStore = await loadSecretFile(ws, { createIfMissing: false });
        if (existingStore?.data?.owner?.user) {
          ownerInfo = `${existingStore.data.owner.user} on ${existingStore.data.owner.host}`;
        }
      } catch {}
    }

    vscode.window.showErrorMessage(
      `❌ ShielderX: Cannot recover on this machine.\n\n` +
      `This machine is not the recovery owner.\n\n` +
      `Ask ${ownerInfo} to:\n` +
      `1. Run "ShielderX: Generate Recovery"\n` +
      `2. Push the restored files\n\n` +
      `Then pull the changes here.`,
      { modal: true },
      "OK"
    );
  }
}


async function rebuildMissingFiles(ws, extensionContext, state, progress) {
  const { hasStore, hasRuntime, hasMetro, hasRecovery } = state;

  if (!hasStore) {
    progress?.report({ message: "Restoring .ai-secret-guard.json...", increment: 20 });

    const fingerprint = await generateProjectFingerprint(ws);

    // ✅ FIX: Load existing store first if it somehow partially exists
    // otherwise build fresh one with owner from getCurrentActor()
    let existingOwner = null;
    try {
      const existing = await loadSecretFile(ws, { createIfMissing: false });
      existingOwner = existing?.data?.owner || null;
    } catch {}

    const freshStore = {
      version: 2,
      mode: "project",
      fingerprint,
      secrets: [],
      owner: existingOwner || getCurrentActor()  // ✅ FIXED
    };

    const storeUri = vscode.Uri.joinPath(ws.uri, SECRET_FILE);
    markInternalOp(storeUri);
    await vscode.workspace.fs.writeFile(
      storeUri,
      Buffer.from(JSON.stringify(freshStore, null, 2))
    );
    unmarkInternalOp(storeUri);
  }

  if (!hasRuntime) {
    progress?.report({ message: "Restoring runtime file...", increment: 20 });
    await ensureShielderRuntimeBootstrap(ws, extensionContext);
  }

  if (!hasMetro) {
    progress?.report({ message: "Restoring metro.config.js...", increment: 20 });
    await ensureMetroConfig(ws);
  }

  progress?.report({ message: "Writing .shielder.recovery...", increment: 20 });
  await writeRecoveryFile(ws, extensionContext);

  vscode.window.showInformationMessage(
    `✅ ShielderX: All files restored!\n\nRun: npm start -- --reset-cache`
  );
}



async function writeRecoveryFile(ws, extensionContext) {
  const key = await getProjectKey(ws);
  const store = await loadSecretFile(ws, { createIfMissing: false });
  if (!store) return;

  const keyHash = sha256(
    await vscode.workspace.fs.readFile(
      vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE)
    )
  );
  const storeHash = sha256(Buffer.from(JSON.stringify(store.data)));

  let runtimeContent = null;
  let metroContent = null;
  try {
    runtimeContent = (await vscode.workspace.fs.readFile(
      vscode.Uri.joinPath(ws.uri, RUNTIME_FILE)
    )).toString();
  } catch {}
  try {
    metroContent = (await vscode.workspace.fs.readFile(
      vscode.Uri.joinPath(ws.uri, METRO_CONFIG_FILE)
    )).toString();
  } catch {}

  const payload = JSON.stringify({
    projectKey: key.toString("base64"),
    store: store.data,
    hashes: { key: keyHash, store: storeHash },
    runtimeContent,
    metroContent
  });

  const fingerprint = await generateProjectFingerprint(ws);
  const masterKey = crypto.scryptSync(fingerprint, "shielder-recovery", 32);
  const encrypted = encryptWithKey(masterKey, payload);

  const fileContent = JSON.stringify({ version: 2, encrypted }, null, 2);

  // ── Write to project file ──
  const recoveryUri = vscode.Uri.joinPath(ws.uri, RECOVERY_FILE);
  markInternalOp(recoveryUri);
  await vscode.workspace.fs.writeFile(recoveryUri, Buffer.from(fileContent));
  unmarkInternalOp(recoveryUri);

  // ✅ NEW: ALSO save copy + hash to globalState
  if (extensionContext) {
    try {
      const recoveryHash = sha256(Buffer.from(fileContent));
      const storageKey = `shielderx-recovery-${fingerprint.slice(0, 16)}`;

      await extensionContext.globalState.update(storageKey, JSON.stringify({
        content: fileContent,        // Full recovery content
        hash: recoveryHash,          // Hash for tamper detection
        savedAt: new Date().toISOString()
      }));
    } catch (e) {
      console.warn("[ShielderX] Could not save recovery to globalState:", e.message);
    }
  }
}


async function restoreFromRecovery(ws) {
  suspendAutoRestore(800);

  const recoveryUri = vscode.Uri.joinPath(ws.uri, RECOVERY_FILE);

  // ✅ FIX 1: Safe read with null check
  let raw;
  try {
    const content = (await vscode.workspace.fs.readFile(recoveryUri)).toString();
    if (!content || !content.trim()) return; // Empty file - nothing to restore
    raw = JSON.parse(content);
  } catch {
    return; // Corrupted or missing - silently skip
  }

  if (!raw?.encrypted) return; // No encrypted data

  let snapshot;
  try {
    const fingerprint = await generateProjectFingerprint(ws);
    const masterKey = crypto.scryptSync(fingerprint, "shielder-recovery", 32);
    const decrypted = decryptWithKey(masterKey, raw.encrypted);
    snapshot = JSON.parse(decrypted);
  } catch {
    return; // Cannot decrypt
  }

  if (!snapshot) return;

  // ✅ FIX 3: Restore key
  if (snapshot.projectKey) {
    const keyUri = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);
    markInternalOp(keyUri);
    await vscode.workspace.fs.writeFile(
      keyUri,
      Buffer.concat([
        Buffer.from("SHIELDER_KEY_v1\n"),
        Buffer.from(snapshot.projectKey, "base64")
      ])
    );
    unmarkInternalOp(keyUri);
  }

  // ✅ FIX 3: Restore store
  if (snapshot.store) {
    const storeUri = vscode.Uri.joinPath(ws.uri, SECRET_FILE);
    markInternalOp(storeUri);
    await vscode.workspace.fs.writeFile(
      storeUri,
      Buffer.from(JSON.stringify(snapshot.store, null, 2))
    );
    unmarkInternalOp(storeUri);
  }

  // ✅ FIX 3: Restore runtime file
  if (snapshot.runtimeContent) {
    const runtimeUri = vscode.Uri.joinPath(ws.uri, RUNTIME_FILE);
    markInternalOp(runtimeUri);
    await vscode.workspace.fs.writeFile(
      runtimeUri,
      Buffer.from(snapshot.runtimeContent)
    );
    unmarkInternalOp(runtimeUri);
  }

  // ✅ FIX 3: Restore metro config
  if (snapshot.metroContent) {
    const metroUri = vscode.Uri.joinPath(ws.uri, METRO_CONFIG_FILE);
    markInternalOp(metroUri);
    await vscode.workspace.fs.writeFile(
      metroUri,
      Buffer.from(snapshot.metroContent)
    );
    unmarkInternalOp(metroUri);
  }

  // Re-write recovery file
  await writeRecoveryFile(ws, extensionContext);
}



async function getProjectKey(workspaceFolder) {
  const uri = vscode.Uri.joinPath(workspaceFolder.uri, PROJECT_KEY_FILE);
  const raw = await vscode.workspace.fs.readFile(uri);

  const header = Buffer.from("SHIELDER_KEY_v1\n", "utf8");

  // Validate header
  if (!raw.slice(0, header.length).equals(header)) {
    throw new Error("Invalid or corrupted Shielder key file");
  }

  // Return only the real key bytes
  return raw.slice(header.length);
}


/*********************************
 * ENCRYPT / DECRYPT HELPERS
 *********************************/

// extension.js (inside the extension process)
const CryptoJS = require("crypto-js");

// helper: convert a Node Buffer -> CryptoJS WordArray
function wordArrayFromBuffer(buf) {
  // CryptoJS accepts typed arrays; create WordArray from bytes
  const words = [];
  for (let i = 0; i < buf.length; i += 4) {
    words.push(
      ((buf[i] || 0) << 24) |
      ((buf[i + 1] || 0) << 16) |
      ((buf[i + 2] || 0) << 8) |
      ((buf[i + 3] || 0))
    );
  }
  return CryptoJS.lib.WordArray.create(words, buf.length);
}

function encryptWithKey(keyBuffer, plaintext) {
  // keyBuffer is the 32-byte Buffer returned by getProjectKey(...)
  const keyWA = wordArrayFromBuffer(keyBuffer);

  const ivWA = CryptoJS.lib.WordArray.random(16); // 16 bytes IV
  const encrypted = CryptoJS.AES.encrypt(
    plaintext,
    keyWA,
    { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
  );

  // ciphertext as raw WordArray -> base64
  const ciphertextBase64 = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
  const ivBase64 = CryptoJS.enc.Base64.stringify(ivWA);

  return { iv: ivBase64, data: ciphertextBase64 };
}


function decryptWithKey(key, payload) {
  const iv = Buffer.from(payload.iv, "base64");
  const data = Buffer.from(payload.data, "base64");

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

  const decrypted = Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}




function hashValue(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}


/*********************************
 * SECRET STORE
 *********************************/
// Replace the old loadSecretFile with this new version
async function loadSecretFile(workspaceFolder, options = { createIfMissing: true }) {
  const uri = vscode.Uri.joinPath(workspaceFolder.uri, SECRET_FILE);

  try {
    const data = JSON.parse(
      (await vscode.workspace.fs.readFile(uri)).toString()
    );
    return { uri, data };
  } catch {
    if (!options.createIfMissing) {
      return null; // IMPORTANT: no auto-create
    }

    const fingerprint = await generateProjectFingerprint(workspaceFolder);
    const fresh = {
      version: 2,
      mode: null,
      fingerprint,
      secrets: []
    };

    await vscode.workspace.fs.writeFile(
      uri,
      Buffer.from(JSON.stringify(fresh, null, 2))
    );

    return { uri, data: fresh };
  }
}

async function setMachineKey(extensionContext, key) {
  await extensionContext.secrets.store("shielder.machineKey", key);
}

// async function deleteMachineKey(context) {
//   await context.secrets.delete("shielder.machineKey");
// }


// --- helper: read protection mode (workspace config > package.json > null) ---
async function getProtectionMode(ws) {
  const store = await loadSecretFile(ws, { createIfMissing: false });
  if (!store) return null;

  return store.data.mode ?? null;
}


// --- helper: quick check whether @shielder/runtime is listed in package.json ---
async function isRuntimeInstalled(ws) {
  try {
    const pkgUri = vscode.Uri.joinPath(ws.uri, "package.json");
    const pkgText = (await vscode.workspace.fs.readFile(pkgUri)).toString();
    const pkg = JSON.parse(pkgText);
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    return !!deps["@shielderx/runtime"];
  } catch {
    return false;
  }
}

// --- helper: UI to prompt user to install runtime (very small webview) ---
function openInstallRuntimeWebview(ws) {
  const panel = vscode.window.createWebviewPanel(
    "shielderInstallRuntime",
    "Shielder — Install Runtime",
    vscode.ViewColumn.Active,
    { enableScripts: true }
  );

  panel.webview.html = `
  <!doctype html>
  <html>
    <body style="font-family: system-ui, -apple-system; padding:20px;">
      <h2>Install @shielderx/runtime</h2>
      <p>This project doesn't include <code>@shielderx/runtime</code>. To enable runtime resolution (resolveSecret) install the package and try again.</p>
      <p>Run <code>npm install @shielderx/runtime</code> or add it to your project dependencies.</p>
      <div style="margin-top:18px;">
        <button onclick="install()">I installed it</button>
        <button onclick="close()">Close</button>
      </div>
      <script>
        const vscode = acquireVsCodeApi();
        function install(){ vscode.postMessage({ type: 'installed' }); }
        function close(){ vscode.postMessage({ type: 'close' }); }
      </script>
    </body>
  </html>`;

  panel.webview.onDidReceiveMessage(msg => {
    if (msg.type === "installed") {
      panel.dispose();
      // no automatic scan — user will be prompted by warning view next
    }
    if (msg.type === "close") {
      panel.dispose();
    }
  });
}


async function getOrCreateMachineKey(extensionContext) {
  let stored = await extensionContext.secrets.get("shielder.machineKey");

  if (!stored) {
    const key = crypto.randomBytes(32).toString("hex");
    await extensionContext.secrets.store("shielder.machineKey", key);
    return Buffer.from(key, "hex");
  }

  return Buffer.from(stored, "hex");
}


function isIgnoredContext(line) {
  if (!line || !line.trim()) return false;

  const trimmed = line.trim();

  return (
    // 🔕 Console / logs
    trimmed.includes("console.log") ||
    trimmed.includes("console.error") ||
    trimmed.includes("console.warn") ||

    // 🔕 Alerts
    trimmed.includes("alert(") ||

    // 🔕 React / RN UI
    trimmed.includes("<Text") ||
    trimmed.includes("Text>") ||

    // 🚫 IMPORT / EXPORT / REQUIRE
    trimmed.startsWith("import ") ||
    trimmed.startsWith("export ") ||
    trimmed.includes(" from ") ||
    trimmed.startsWith("require(")
  );
}


/*********************************
 * DETECTION
 *********************************/
function detect(line) {
  if (!line || !line.trim()) return [];

  // 🚫 NEVER scan protected lines
  if (line.includes("resolveSecret(")) return [];

  if (isIgnoredContext(line)) return [];

  STRING_ASSIGN_REGEX.lastIndex = 0;
  STRING_LITERAL_REGEX.lastIndex = 0;

  const found = [];
  const seen = new Set();
  let m;

  // ─────────────────────────
  // 1️⃣ ASSIGNMENTS
  // ─────────────────────────
  while ((m = STRING_ASSIGN_REGEX.exec(line))) {
    const variable = m[2];
    const value = m[3];

    // 🚫 Skip placeholders
    if (isSecretPlaceholderValue(value)) continue;

    let type = null;
    if (EMAIL_REGEX.test(value)) type = "email";
    else if (PHONE_REGEX.test(value)) type = "phone";
    else if (API_KEY_REGEX.test(value)) type = "apiKey";
    else if (isLikelyKey(value)) type = "genericKey";
    else continue;

    found.push({ value, type, variable });
    seen.add(value);
  }

  // ─────────────────────────
  // 2️⃣ INLINE STRINGS
  // ─────────────────────────
  while ((m = STRING_LITERAL_REGEX.exec(line))) {
    const value = m[1];

    // 🚫 Skip placeholders
    if (isSecretPlaceholderValue(value)) continue;

    if (seen.has(value)) continue;

    let type = null;
    if (EMAIL_REGEX.test(value)) type = "email";
    else if (PHONE_REGEX.test(value)) type = "phone";
    else if (API_KEY_REGEX.test(value)) type = "apiKey";
    else if (isLikelyKey(value)) type = "genericKey";
    else continue;

    found.push({ value, type, variable: null });
    seen.add(value);
  }

  return found;
}

let suspendAutoRestoreUntil = 0;


function suspendAutoRestore(ms = 500) {
  suspendAutoRestoreUntil = Date.now() + ms;
}


/*********************************
 * EXTENSION
 *********************************/

// function setupProtectionWatchers(extensionContext) {
//   const ws = vscode.workspace.workspaceFolders?.[0];
//   if (!ws) return;

// const keyWatcher = vscode.workspace.createFileSystemWatcher(
//     new vscode.RelativePattern(ws, PROJECT_KEY_FILE)
//   );

//     const recoveryWatcher = vscode.workspace.createFileSystemWatcher(
//     new vscode.RelativePattern(ws, RECOVERY_FILE)
//   );

//   const storeWatcher = vscode.workspace.createFileSystemWatcher(
//     new vscode.RelativePattern(ws, SECRET_FILE)
//   );

//   // ✅ NEW: Watch runtime file
//   const runtimeWatcher = vscode.workspace.createFileSystemWatcher(
//     new vscode.RelativePattern(ws, RUNTIME_FILE)
//   );

//   // ✅ NEW: Watch metro config
//   const metroWatcher = vscode.workspace.createFileSystemWatcher(
//     new vscode.RelativePattern(ws, METRO_CONFIG_FILE)
//   );

//   const delayedVerify = async () => {
//     await new Promise(r => setTimeout(r, 50));
//     await verifyAndRestore(ws);
//   };

//   // Edits → restore from recovery
//   keyWatcher.onDidChange(uri => {
//     if (isInternalOp(uri)) return;
//     delayedVerify();
//   });

//   storeWatcher.onDidChange(uri => {
//     if (isInternalOp(uri)) return;
//     delayedVerify();
//   });

//   // ✅ NEW: Runtime tampered → restore
//   runtimeWatcher.onDidChange(uri => {
//     if (isInternalOp(uri)) return;
//     delayedVerify();
//   });

//   // ✅ NEW: Metro config tampered → restore
//   metroWatcher.onDidChange(uri => {
//     if (isInternalOp(uri)) return;
//     delayedVerify();
//   });

//   // Deletes → immediate restore
//   keyWatcher.onDidDelete(uri => {
//     if (isInternalOp(uri)) return;
//     verifyAndRestore(ws);
//   });

//   storeWatcher.onDidDelete(uri => {
//     if (isInternalOp(uri)) return;
//     verifyAndRestore(ws);
//   });

//   // ✅ NEW: Runtime deleted → immediate restore
//   runtimeWatcher.onDidDelete(uri => {
//     if (isInternalOp(uri)) return;
//     verifyAndRestore(ws);
//   });

//   // ✅ NEW: Metro config deleted → immediate restore
//   metroWatcher.onDidDelete(uri => {
//     if (isInternalOp(uri)) return;
//     verifyAndRestore(ws);
//   });

//   // Poll fallback (guarantee)
//   const interval = setInterval(() => {
//     verifyAndRestore(ws).catch(() => {});
//   }, 2000);

//   extensionContext.subscriptions.push(
//     keyWatcher,
//     storeWatcher,
//     recoveryWatcher,  // ✅ NEW
//     runtimeWatcher,   // ✅ NEW
//     metroWatcher,     // ✅ NEW
//     { dispose: () => clearInterval(interval) }
//   );

// }

function setupProtectionWatchers(extensionContext) {
  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) return;

  const keyWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(ws, PROJECT_KEY_FILE)
  );
  const storeWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(ws, SECRET_FILE)
  );
  // ✅ NEW: Watch recovery file
  const recoveryWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(ws, RECOVERY_FILE)
  );
  // ✅ NEW: Watch runtime file
  const runtimeWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(ws, RUNTIME_FILE)
  );
  // ✅ NEW: Watch metro config
  const metroWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(ws, METRO_CONFIG_FILE)
  );

  const delayedVerify = async () => {
    await new Promise(r => setTimeout(r, 50));
    await verifyAndRestore(ws);
  };

  // Watch all files for edit
  [keyWatcher, storeWatcher, recoveryWatcher, runtimeWatcher, metroWatcher]
    .forEach(w => w.onDidChange(uri => {
      if (isInternalOp(uri)) return;
      delayedVerify();
    }));

  // Watch all files for delete
  [keyWatcher, storeWatcher, recoveryWatcher, runtimeWatcher, metroWatcher]
    .forEach(w => w.onDidDelete(uri => {
      if (isInternalOp(uri)) return;
      verifyAndRestore(ws);
    }));

  // Poll fallback every 2 seconds
  const interval = setInterval(() => {
    verifyAndRestore(ws).catch(() => {});
  }, 2000);

  extensionContext.subscriptions.push(
    keyWatcher,
    storeWatcher,
    recoveryWatcher,  // ✅ NEW
    runtimeWatcher,   // ✅ NEW
    metroWatcher,     // ✅ NEW
    { dispose: () => clearInterval(interval) }
  );
}

async function fileExists(ws, relativePath) {
  try {
    // Support glob-like patterns (e.g. *.csproj)
    if (relativePath.includes("*")) {
      const files = await vscode.workspace.findFiles(
        new vscode.RelativePattern(ws, relativePath),
        "**/node_modules/**",
        1
      );
      return files.length > 0;
    }

    await vscode.workspace.fs.stat(
      vscode.Uri.joinPath(ws.uri, relativePath)
    );
    return true;
  } catch {
    return false;
  }
}

async function verifyAndRestore(ws) {
  if (Date.now() < suspendAutoRestoreUntil) return;

  const recoveryUri = vscode.Uri.joinPath(ws.uri, RECOVERY_FILE);
  const keyUri      = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);
  const storeUri    = vscode.Uri.joinPath(ws.uri, SECRET_FILE);
  const runtimeUri  = vscode.Uri.joinPath(ws.uri, RUNTIME_FILE);
  const metroUri    = vscode.Uri.joinPath(ws.uri, METRO_CONFIG_FILE);

  const fingerprint = await generateProjectFingerprint(ws);
  const storageKey = `shielderx-recovery-${fingerprint.slice(0, 16)}`;

  // ✅ Load globalState backup (source of truth)
  let globalBackup = null;
  try {
    const stored = extensionContext?.globalState?.get(storageKey);
    if (stored) globalBackup = JSON.parse(stored);
  } catch {}

  // ── Check .shielder.recovery ──
  let recoveryOk = false;
  let recoveryContent = null;

  try {
    recoveryContent = (await vscode.workspace.fs.readFile(recoveryUri)).toString();

    if (globalBackup) {
      // ✅ Compare hash with globalState copy
      const currentHash = sha256(Buffer.from(recoveryContent));
      if (currentHash !== globalBackup.hash) {
        // Tampered! Restore from globalState
        console.log("[ShielderX] Recovery file tampered → restoring from globalState");
        markInternalOp(recoveryUri);
        await vscode.workspace.fs.writeFile(recoveryUri, Buffer.from(globalBackup.content));
        unmarkInternalOp(recoveryUri);
        recoveryContent = globalBackup.content;
      }
    }

    recoveryOk = true;
  } catch {
    // Recovery file deleted!
    if (globalBackup) {
      // Restore from globalState
      console.log("[ShielderX] Recovery file deleted → restoring from globalState");
      markInternalOp(recoveryUri);
      await vscode.workspace.fs.writeFile(recoveryUri, Buffer.from(globalBackup.content));
      unmarkInternalOp(recoveryUri);
      recoveryContent = globalBackup.content;
      recoveryOk = true;
    }
  }

  // No recovery anywhere → nothing to enforce
  if (!recoveryOk || !recoveryContent) return;

  // Decrypt snapshot
  let snapshot;
  try {
    const raw = JSON.parse(recoveryContent);
    const masterKey = crypto.scryptSync(fingerprint, "shielder-recovery", 32);
    snapshot = JSON.parse(decryptWithKey(masterKey, raw.encrypted));
  } catch {
    return;
  }

  if (!snapshot) return;

  // ── Check each file individually ──

  // Check .shielder.key
  let keyBuf;
  try { keyBuf = await vscode.workspace.fs.readFile(keyUri); } catch {}
  const keyOk = keyBuf && sha256(keyBuf) === snapshot.hashes.key;

  // Check .ai-secret-guard.json
  let storeBuf;
  try { storeBuf = await vscode.workspace.fs.readFile(storeUri); } catch {}
  const storeOk = storeBuf && sha256(storeBuf) === snapshot.hashes.store;

  // Check runtime
  let runtimeOk = true;
  if (snapshot.runtimeContent) {
    try {
      const runtimeBuf = await vscode.workspace.fs.readFile(runtimeUri);
      runtimeOk = sha256(runtimeBuf) === sha256(Buffer.from(snapshot.runtimeContent));
    } catch { runtimeOk = false; }
  }

  // Check metro
  let metroOk = true;
  if (snapshot.metroContent) {
    try {
      const metroBuf = await vscode.workspace.fs.readFile(metroUri);
      metroOk = sha256(metroBuf) === sha256(Buffer.from(snapshot.metroContent));
    } catch { metroOk = false; }
  }

  // ── Restore only what's missing/tampered ──
  suspendAutoRestore(800);

  if (!keyOk && snapshot.projectKey) {
    markInternalOp(keyUri);
    await vscode.workspace.fs.writeFile(keyUri, Buffer.concat([
      Buffer.from("SHIELDER_KEY_v1\n"),
      Buffer.from(snapshot.projectKey, "base64")
    ]));
    unmarkInternalOp(keyUri);
  }

  if (!storeOk && snapshot.store) {
    markInternalOp(storeUri);
    await vscode.workspace.fs.writeFile(storeUri,
      Buffer.from(JSON.stringify(snapshot.store, null, 2))
    );
    unmarkInternalOp(storeUri);
  }

  if (!runtimeOk && snapshot.runtimeContent) {
    markInternalOp(runtimeUri);
    await vscode.workspace.fs.writeFile(runtimeUri,
      Buffer.from(snapshot.runtimeContent)
    );
    unmarkInternalOp(runtimeUri);
  }

  if (!metroOk && snapshot.metroContent) {
    markInternalOp(metroUri);
    await vscode.workspace.fs.writeFile(metroUri,
      Buffer.from(snapshot.metroContent)
    );
    unmarkInternalOp(metroUri);
  }
}



let blockingDialogActive = false;


function handleManagedFileOpen(editor) {
  if (!editor) return;

  const file = editor.document.fileName;
  const fileName = path.basename(file);

  const isProtected =
    file.endsWith(PROJECT_KEY_FILE) ||
    file.endsWith(SECRET_FILE) ||
    file.endsWith(RUNTIME_FILE) ||       // ✅ NEW
    file.endsWith(METRO_CONFIG_FILE);    // ✅ NEW

  if (isProtected) {
    if (blockingDialogActive) return;
    blockingDialogActive = true;

    vscode.window.showWarningMessage(
      `🔒 Protected file detected\n\nFile: ${fileName}\n\nThis file is managed by ShielderX.\nManual editing is not allowed and changes will be reverted automatically.`,
      { modal: true },
      "OK"
    ).then(() => {
      blockingDialogActive = false;
      vscode.commands.executeCommand("workbench.action.closeActiveEditor");
    });
  }
}


async function loadExistingSecretFile(ws) {
  const uri = vscode.Uri.joinPath(ws.uri, ".ai-secret-guard.json");

  const raw = await vscode.workspace.fs.readFile(uri);
  return {
    uri,
    data: JSON.parse(raw.toString())
  };
}


async function handleShielderProtectCall(editor, lineNumber, lineText) {
    SHIELDER_PROTECT_CALL_REGEX.lastIndex = 0;
 if (!lineText.includes("ShielderX.protect(")) return;
  if (!lineText.includes(")")) return;
  let match;
  while ((match = SHIELDER_PROTECT_CALL_REGEX.exec(lineText))) {
    const fullCall = match[0];
    const value = match[1];

    // 🚫 Prevent double handling
    if (lineText.includes("resolveSecret(")) return;

    const confirm = await vscode.window.showWarningMessage(
      `🔐 Protect this value?\n\n"${value}"`,
      { modal: true },
      "Protect"
    );

    if (confirm !== "Protect") return;

    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) return;

   await ensureProjectKey(ws, extensionContext);
    const store = await loadSecretFile(ws);
    const key = await getProjectKey(ws);

    const id = crypto.randomBytes(4).toString("hex");
    const placeholder = `<SECRET_${id.toUpperCase()}>`;
    const encrypted = encryptWithKey(key, value);

    await editor.edit(edit => {
      edit.replace(
        new vscode.Range(
          lineNumber,
          lineText.indexOf(fullCall),
          lineNumber,
          lineText.indexOf(fullCall) + fullCall.length
        ),
        `resolveSecret("${placeholder}")`
      );
    });

    store.data.secrets.push({
      id,
      type: "inline-protect",
      hash: hashValue(value),
      file: path.relative(
        ws.uri.fsPath,
        editor.document.uri.fsPath
      ),
      line: lineNumber + 1,
      placeholder,
      variable: null,
      encrypted,
      disabled: false
    });

    await vscode.workspace.fs.writeFile(
      store.uri,
      Buffer.from(JSON.stringify(store.data, null, 2))
    );
await writeRecoveryFile(ws, extensionContext);

    vscode.window.showInformationMessage(
      "🔐 Value protected successfully."
    );
  }
}

function findStringLiteralRange(document, position) {
  const line = document.lineAt(position.line);
  const text = line.text;

  const regex = /(["'`])([^"'`]+)\1/g;
  let match;

  while ((match = regex.exec(text))) {
    const start = match.index;
    const end = start + match[0].length;

    if (
      position.character >= start &&
      position.character <= end
    ) {
      return {
        range: new vscode.Range(
          position.line,
          start,
          position.line,
          end
        ),
        value: match[2] // without quotes
      };
    }
  }

  return null;
}


function isSecretPlaceholder(value) {
  return /^<SECRET_[A-Z0-9]+>$/.test(value);
}

function isWrappedStringLiteral(text) {
  if (!text || text.length < 2) return false;

  const first = text[0];
  const last = text[text.length - 1];

  if (first !== last) return false;
  if (!['"', "'", '`'].includes(first)) return false;

  // ensure last quote is not escaped
  let backslashes = 0;
  for (let i = text.length - 2; i >= 0 && text[i] === '\\'; i--) {
    backslashes++;
  }
  return backslashes % 2 === 0;
}

let extensionContext;

function updateShielderStatus(mode, owner) {
  if (!shielderStatusBar) return;

  // 🔓 Not protected
  if (!mode) {
    shielderStatusBar.text = "🔓 Shielder: Not Protected(Recovery Owner: NA)";
    shielderStatusBar.tooltip = "Project is not protected by Shielder";
    return;
  }

  // 🔐 Base text
  let text =
    mode === "machine"
      ? "🔐 Shielder: Machine Key"
      : "🔐 Shielder: Project Key";

  // 👤 Owner info (only for project mode)
  if (mode === "project" && owner?.user) {
    text += ` (Recovery Owner: ${owner.user})`;

    const claimedAt = owner.claimedAt
      ? new Date(owner.claimedAt).toLocaleString()
      : "Unknown time";

    shielderStatusBar.tooltip =
      `Recovery owner: ${owner.user}\n` +
      `Host: ${owner.host || "Unknown"}\n` +
      `Claimed at: ${claimedAt}`;
  } else {
    shielderStatusBar.tooltip =
      mode === "machine"
        ? "Secrets are protected using a machine-specific key"
        : "Secrets are protected using a project key";
  }

  shielderStatusBar.text = text;
}


async function detectPackageManager(ws) {
  const fs = vscode.workspace.fs;

  const has = async (file) => {
    try {
      await fs.stat(vscode.Uri.joinPath(ws.uri, file));
      return true;
    } catch {
      return false;
    }
  };

  if (await has("yarn.lock")) return "yarn";
  if (await has("pnpm-lock.yaml")) return "pnpm";
  if (await has("package-lock.json")) return "npm";

  return "npm"; // default fallback
}

async function ensureShielderRuntime(ws, store) {
  // 🛑 Guard 0: store or mode missing → NEVER install runtime
  if (!store?.data?.mode) return;

  const platform = await detectPlatform(ws);
  if (!platform) return;

  // 🛑 Guard 1: backend / unsupported platforms
  if (!platform.supportsRuntime) {
    if (!store.data.backendNoticeShown) {
      vscode.window.showInformationMessage(
        `Shielder detected a ${platform.id.toUpperCase()} project.\n\n` +
        `Runtime secret decryption for ${platform.id} requires a ` +
        `platform-specific Shielder library, which is not available yet.\n\n` +
        `Scan & protection will work, but secrets cannot be resolved at runtime.\n\n` +
        `Support is coming soon.`,
        { modal: true }
      );

      store.data.backendNoticeShown = true;

      markInternalOp(store.uri);
      await vscode.workspace.fs.writeFile(
        store.uri,
        Buffer.from(JSON.stringify(store.data, null, 2))
      );
      unmarkInternalOp(store.uri);
    }
    return;
  }

  // 🛑 Guard 2: runtime already installed for this platform
  if (store.data.runtime) {
    if (store.data.runtime.id === platform.id) {
      return; // same platform → ok
    }
    // ⚠️ Platform changed (e.g. JS → RN)
    delete store.data.runtime;
  }

  // 🧠 Decide package manager
  const pm = await detectPackageManager(ws);

  // 📦 Install correct runtime
  if (platform.id === "react-native") {
    await runInstall(pm, "@shielderx/react-native-runtime");

    // 🔥 CRITICAL: create RN bootstrap file
    await ensureShielderRuntimeBootstrap(ws);
  } 
  else if (platform.id === "flutter") {
    await runInstall(pm, "shielder_runtime"); // uses terminal like others
  } 
  else {
    // JS / TS / Web / Node
    await runInstall(pm, "@shielderx/runtime");
  }

  // 💾 Persist runtime state
  store.data.runtime = {
    id: platform.id,
    installedAt: new Date().toISOString()
  };

  markInternalOp(store.uri);
  await vscode.workspace.fs.writeFile(
    store.uri,
    Buffer.from(JSON.stringify(store.data, null, 2))
  );
  unmarkInternalOp(store.uri);
}



function openBackendDocs(platformId) {
  vscode.env.openExternal(
    vscode.Uri.parse(
      `https://github.com/your-org/shielder/docs/backend/${platformId}.md`
    )
  );
}


async function ensureShielderRuntimeBootstrap(ws, extensionContext) {
  const runtimeUri = vscode.Uri.joinPath(ws.uri, "shielderx.runtime.js");

  const storeData = await loadSecretFile(ws, { createIfMissing: false });
  
  if (!storeData || !storeData.data) {
    vscode.window.showErrorMessage('ShielderX: No store data available');
    return;
  }

  let key = null;

  if (storeData.data.mode === "project") {
    const projectKey = await getProjectKey(ws);
    key = projectKey.toString("base64");
  }

  if (storeData.data.mode === "machine") {
    const machineKey = await getOrCreateMachineKey(extensionContext);
    key = machineKey.toString("base64");
  }

  // 🔐 Level 2 obfuscation for key
  const keyCharCodes = [];
  for (let i = 0; i < key.length; i++) {
    keyCharCodes.push(key.charCodeAt(i));
  }
  
  const xorKey = 0x5A;
  const obfuscatedCodes = keyCharCodes.map(code => code ^ xorKey);
  
  const chunks = [];
  const chunkSize = 8;
  for (let i = 0; i < obfuscatedCodes.length; i += chunkSize) {
    chunks.push(obfuscatedCodes.slice(i, i + chunkSize));
  }

  // 🔥 NO EMBEDDED STORE - Load from JSON file only
  const content = `// AUTO-GENERATED BY SHIELDER — DO NOT EDIT
// ShielderX Runtime Bootstrap (Level 2 Security)

(function () {
  if (global.__SHIELDER_INITIALIZED__) {
    console.warn('[ShielderX] Already initialized');
    return;
  }

  // Load store from .ai-secret-guard.json
  let store = null;
  try {
    store = require('./.ai-secret-guard.json');
    console.log('[ShielderX] Store loaded from .ai-secret-guard.json');
  } catch (e) {
    console.error('[ShielderX] CRITICAL: Could not load .ai-secret-guard.json');
    console.error('[ShielderX] Error:', e.message);
    console.error('[ShielderX] Make sure metro.config.js includes JSON files');
    // Don't fallback - fail clearly so developer knows there's an issue
    return;
  }

  // 🔐 Obfuscated key reconstruction
  const _k = ${JSON.stringify(chunks)};
  const _x = 0x5A;
  const _d = (c) => c.map(n => n ^ _x).map(n => String.fromCharCode(n)).join('');
  const key = _k.map(_d).join('');

  global.__SHIELDER_STORE__ = store;
  global.__SHIELDER_KEY__ = key;
  global.__SHIELDER_INITIALIZED__ = true;

  if (typeof __DEV__ !== 'undefined' && __DEV__) {
    console.log('[ShielderX] Runtime initialized');
    console.log('[ShielderX] Key present:', !!global.__SHIELDER_KEY__);
    console.log('[ShielderX] Store present:', !!global.__SHIELDER_STORE__);
    console.log('[ShielderX] Secret count:', store?.secrets?.length || 0);
  }
})();
`;

  markInternalOp(runtimeUri);
  await vscode.workspace.fs.writeFile(runtimeUri, Buffer.from(content));
  unmarkInternalOp(runtimeUri);

  vscode.window.showInformationMessage('✓ ShielderX runtime bootstrap generated');
}

async function ensureMetroConfig(ws) {
  const metroConfigUri = vscode.Uri.joinPath(ws.uri, "metro.config.js");
  
  let configContent = '';
  let configExists = false;
  
  try {
    configContent = (await vscode.workspace.fs.readFile(metroConfigUri)).toString();
    configExists = true;
  } catch {
    // File doesn't exist
  }

  // Check if already has ShielderX config
  if (configContent.includes('ShielderX') || configContent.includes('.ai-secret-guard.json')) {
    return; // Already configured
  }

  let newConfig;

  if (!configExists || configContent.trim().length === 0) {
    // Create new config
    newConfig = `// Metro configuration for React Native
// ShielderX: Ensure .ai-secret-guard.json is included in bundle
const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Include .ai-secret-guard.json in bundle
config.resolver.assetExts.push('json');

module.exports = config;
`;
  } else {
    // Append to existing config
    newConfig = configContent + `

// ShielderX: Ensure .ai-secret-guard.json is included in bundle
// (Added automatically by ShielderX extension)
if (config.resolver && config.resolver.assetExts) {
  config.resolver.assetExts.push('json');
}
`;
  }

  await vscode.workspace.fs.writeFile(metroConfigUri, Buffer.from(newConfig));
  
  vscode.window.showInformationMessage(
    '✓ Metro config updated to include .ai-secret-guard.json'
  );
}

async function isExpoProject(ws) {
  try {
    const pkgUri = vscode.Uri.joinPath(ws.uri, "package.json");
    const pkg = JSON.parse(
      (await vscode.workspace.fs.readFile(pkgUri)).toString()
    );

    return (
      typeof pkg.main === "string" &&
      pkg.main.includes("expo/AppEntry")
    );
  } catch {
    return false;
  }
}


async function runInstall(pm, pkg) {
  const terminal = vscode.window.createTerminal("Shielder Setup");
  terminal.show();

  if (pm === "yarn") {
    terminal.sendText(`yarn add ${pkg}`);
  } else if (pm === "pnpm") {
    terminal.sendText(`pnpm add ${pkg}`);
  } else {
    terminal.sendText(`npm install ${pkg}`);
  }
}




function activate(context) {
 extensionContext = context;
  console.log("[Shielder] Extension activated");






  shielderStatusBar = vscode.window.createStatusBarItem(
  vscode.StatusBarAlignment.Right,
  100
);

shielderStatusBar.tooltip = "Shielder protection mode";
shielderStatusBar.command = "shielder.showProtectionInfo"; // optional
shielderStatusBar.show();

extensionContext.subscriptions.push(shielderStatusBar);

setupProtectionWatchers(extensionContext);
  // also run once on activation
  handleWorkspaceOpen(extensionContext);



  extensionContext.subscriptions.push(
  vscode.commands.registerCommand("shielder.showProtectionInfo", async () => {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) return;

    const store = await loadSecretFile(ws, { createIfMissing: false });

    if (!store || !store.data?.mode) {
      await vscode.window.showInformationMessage(
        "🔓 Shielder is not protecting this project yet.",
        { modal: true },
        "OK"
      );
      return;
    }

      vscode.window.showInformationMessage(
      `🔐 Shielder is using ${store.data.mode === "machine"
        ? "Machine-based protection"
        : "Project-based protection"
      }.`
    );

    const mode = store.data.mode;

    const message =
      mode === "machine"
        ? "🔐 Shielder Protection Mode: MACHINE"
        : "🔐 Shielder Protection Mode: PROJECT";

    await vscode.window.showInformationMessage(
      message,
      { modal: true },
      "OK"
    );
  })
);



  extensionContext.subscriptions.push(
  vscode.commands.registerCommand(
    "shielder.revertSelectionInline",
    async (uri, range) => {
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) return;

      const editor = await vscode.window.showTextDocument(uri);
      const lineText = editor.document.lineAt(range.start.line).text;

      // 🔍 Extract placeholder
      const match = lineText.match(/<SECRET_[A-Z0-9]+>/);
      if (!match) {
        vscode.window.showWarningMessage(
          "No protected secret found at cursor."
        );
        return;
      }

      const placeholder = match[0];

    const store = await loadSecretFile(ws);

let key;
if (store.data.mode === "project") {
  key = await getProjectKey(ws);
} else {
  key = await getOrCreateMachineKey(extensionContext);
}



      const secret = store.data.secrets.find(
        s => s.placeholder === placeholder && !s.disabled
      );

      if (!secret) {
        vscode.window.showWarningMessage(
          "Secret not found in store."
        );
        return;
      }

      const confirm = await vscode.window.showWarningMessage(
        "🔓 Revert this protected value back to plaintext?",
        { modal: true },
        "Revert"
      );

      if (confirm !== "Revert") return;

      const plaintext = decryptWithKey(key, secret.encrypted);

      await editor.edit(edit => {
        edit.replace(range, `"${plaintext}"`);
      });

      // Mark as disabled (do NOT delete history)
      secret.disabled = true;

     suspendAutoRestore(800);
markInternalOp(store.uri);
await vscode.workspace.fs.writeFile(
  store.uri,
  Buffer.from(JSON.stringify(store.data, null, 2))
);
unmarkInternalOp(store.uri);


      vscode.window.showInformationMessage(
        "🔓 Value reverted successfully."
      );
    }
  )
);

  extensionContext.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      await handleWorkspaceOpen(extensionContext);
    })
  );


extensionContext.subscriptions.push(
  vscode.commands.registerCommand("shielder.generateRecovery", async () => {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) {
      vscode.window.showErrorMessage("ShielderX: No workspace open");
      return;
    }
    await generateRecovery(ws, extensionContext);
  })
);

extensionContext.subscriptions.push(
  vscode.workspace.onDidChangeTextDocument(async event => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    if (event.document !== editor.document) return;

    for (const change of event.contentChanges) {
      // 🔕 Ignore normal typing
      const text = change.text;
      const isCompletion =
        text.includes("\n") || text.includes(";");

      if (!isCompletion) continue;

      const lineNumber =
        text.includes("\n")
          ? change.range.start.line
          : change.range.end.line;

      const lineText =
        editor.document.lineAt(lineNumber).text;

      await handleShielderProtectCall(
        editor,
        lineNumber,
        lineText
      );
    }
  })
);




  // ─────────────────────────────
// BLOCK MANAGED FILES ON OPEN
// ─────────────────────────────
// Block managed files on open / focus

extensionContext.subscriptions.push(
  vscode.languages.registerCodeActionsProvider(
    ["javascript", "typescript", "javascriptreact", "typescriptreact", "json"],
    {
provideCodeActions(document, range) {
  const actions = [];
  const position = range.start;
  const lineText = document.lineAt(position.line).text;

  // ─────────────────────────────
  // 🔓 REVERT (cursor OR selection)
  // ─────────────────────────────
  const secretRange = findResolveSecretRange(document, position);
  if (secretRange) {
    const revertAction = new vscode.CodeAction(
      "🔓 Revert protected value",
      vscode.CodeActionKind.QuickFix
    );

    revertAction.command = {
      command: "shielder.revertSelectionInline",
      title: "Revert protected value",
      arguments: [document.uri, secretRange]
    };

    actions.push(revertAction);
  }

  // ─────────────────────────────
  // 🔐 PROTECT (selection OR cursor)
  // ─────────────────────────────
  let protectRange = null;
  let protectValue = null;

  // 1️⃣ Selection-based
  if (!range.isEmpty) {
    protectRange = range;
    protectValue = document.getText(range).trim();
  } 
  // 2️⃣ Cursor-based
  else {
    const found = findStringLiteralRange(document, position);
    if (found) {
      protectRange = found.range;
      protectValue = found.value;
    }
  }

  if (protectRange && protectValue && protectValue.length >= 4) {
    // Ignore noisy contexts
    if (!isIgnoredContext(lineText) && !protectValue.includes("resolveSecret(")) {

       if (isSecretPlaceholder(protectValue)) {
    return actions.length ? actions : undefined;
  }

   if (isIgnoredContext(lineText)) {
    return actions.length ? actions : undefined;
  }

  // 🚫 Already inside resolveSecret
  if (lineText.includes("resolveSecret(")) {
    return actions.length ? actions : undefined;
  }

      const protectAction = new vscode.CodeAction(
        "🔐 Protect with Shielder",
        vscode.CodeActionKind.QuickFix
      );

      protectAction.command = {
        command: "shielder.protectSelectionInline",
        title: "Protect with Shielder",
        arguments: [
          document.uri,
          protectRange,
          protectValue
        ]
      };

      actions.push(protectAction);
    }
  }

  return actions.length ? actions : undefined;
}


    },
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix]
    }
  )
);


extensionContext.subscriptions.push(
  vscode.commands.registerCommand(
    "shielder.protectSelectionInline",
    async (uri, range, value) => {
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) return;

    await ensureProjectKey(ws, extensionContext);
      const store = await loadSecretFile(ws);

      let key;
      if (store.data.mode === "project") {
       await ensureProjectKey(ws, extensionContext);
        key = await getProjectKey(ws);
      } else {
        key = await getOrCreateMachineKey(extensionContext);
      }

      const editor = await vscode.window.showTextDocument(uri);

      const id = crypto.randomBytes(4).toString("hex");
      const placeholder = `<SECRET_${id.toUpperCase()}>`;

      // ─────────────────────────────
      // 🔁 Normalize replacement range
      // ─────────────────────────────
      let finalRange = range;
      let finalValue = value;

      // If selection does NOT wrap a full string literal,
      // expand to the full string literal at cursor
      if (!isWrappedStringLiteral(value)) {
        const found = findStringLiteralRange(
          editor.document,
          range.start
        );
        if (found) {
          finalRange = found.range;
          finalValue = found.value;
        }
      }

      // ─────────────────────────────
      // 🔐 Normalize VALUE (strip quotes)
      // ─────────────────────────────
      let normalizedValue = finalValue;

      if (
        (normalizedValue.startsWith('"') && normalizedValue.endsWith('"')) ||
        (normalizedValue.startsWith("'") && normalizedValue.endsWith("'"))
      ) {
        normalizedValue = normalizedValue.slice(1, -1);
      }

      // Encrypt ONLY the normalized value
      const encrypted = encryptWithKey(key, normalizedValue);

      // ─────────────────────────────
      // ✍️ Replace source code
      // ─────────────────────────────
      await editor.edit(edit => {
        edit.replace(
          finalRange,
          `resolveSecret("${placeholder}")`
        );
      });

      // ─────────────────────────────
      // 💾 Store metadata
      // ─────────────────────────────
      store.data.secrets.push({
        id,
        type: "manual",
        hash: hashValue(normalizedValue),
        file: path.relative(ws.uri.fsPath, uri.fsPath),
        line: finalRange.start.line + 1,
        placeholder,
        variable: null,
        encrypted,
        disabled: false
      });

      // Store write is trusted
      suspendAutoRestore(800);
      markInternalOp(store.uri);
      await vscode.workspace.fs.writeFile(
        store.uri,
        Buffer.from(JSON.stringify(store.data, null, 2))
      );
      unmarkInternalOp(store.uri);

      // 🔐 Update recovery snapshot
      await writeRecoveryFile(ws, extensionContext);

      vscode.window.showInformationMessage("🔐 Value protected.");
    }
  )
);



extensionContext.subscriptions.push(
  vscode.workspace.onDidOpenTextDocument(doc => {
    const editor = vscode.window.visibleTextEditors.find(
      e => e.document === doc
    );
    handleManagedFileOpen(editor);
  })
);

extensionContext.subscriptions.push(
  vscode.window.onDidChangeActiveTextEditor(editor => {
    handleManagedFileOpen(editor);
  })
);

extensionContext.subscriptions.push(
 vscode.commands.registerCommand("shielder.revertProject", async () => {
  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) return;

  const state = await getProtectionState(extensionContext, ws);

  if (!state.protected) {
    if (!state.store || !state.mode) {
      // ✅ FIX: Check if project is actually protected before showing onboarding
      const alreadyProtected = await isProjectAlreadyProtected(ws);

      if (alreadyProtected) {
        vscode.window.showWarningMessage(
          "⚠️ ShielderX files are missing! Run 'ShielderX: Generate Recovery' first.",
          "Generate Recovery"
        ).then(choice => {
          if (choice === "Generate Recovery") {
            vscode.commands.executeCommand("shielder.generateRecovery");
          }
        });
        return;
      }

      openOnOpenWarning(ws);
      return;
    }

    vscode.window.showWarningMessage("🔐 Project is not fully protected yet.");
    return;
  }

  openRevertConfirm(extensionContext, ws);
})
);



  extensionContext.subscriptions.push(
    vscode.commands.registerCommand("shielder.exportKey", async () => {
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) {
        vscode.window.showWarningMessage("No workspace open");
        return;
      }

      openExportKeyConfirm(ws);
    })
  );


extensionContext.subscriptions.push(
 vscode.commands.registerCommand("shielder.manageSecrets", async () => {
  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) return;

  const state = await getProtectionState(extensionContext, ws);

  if (!state.protected) {
    if (!state.store || !state.mode) {
      // ✅ FIX: Check if project is actually protected before showing onboarding
      const alreadyProtected = await isProjectAlreadyProtected(ws);

      if (alreadyProtected) {
        vscode.window.showWarningMessage(
          "⚠️ ShielderX files are missing! Run 'ShielderX: Generate Recovery' first.",
          "Generate Recovery"
        ).then(choice => {
          if (choice === "Generate Recovery") {
            vscode.commands.executeCommand("shielder.generateRecovery");
          }
        });
        return;
      }

      openOnOpenWarning(ws);
      return;
    }

    vscode.window.showWarningMessage("🔐 Project is not fully protected yet.");
    return;
  }

  openManageSecrets(ws);
})
);

  /* -------- SCAN PROJECT -------- */

// ---------- Replace all existing shielder.scan handlers with this single implementation ----------
extensionContext.subscriptions.push(
  vscode.commands.registerCommand("shielder.scan", async () => {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) {
      vscode.window.showWarningMessage("⚠️ No workspace folder open.");
      return;
    }

  // 1️⃣ Always load/create store
    const store = await loadSecretFile(ws);

    console.log("[Shielder] store mode:", store?.data?.mode, "secrets:", (store?.data?.secrets||[]).length);


    // 2️⃣ Mode must exist
    if (!store.data.mode) {
      openOnOpenWarning(ws);
      return;
    }

const platform = await detectPlatform(ws);
const runtimeImport = getRuntimeImport(platform);


    if (!store.data.owner) {
  store.data.owner = getCurrentActor();
}

    // 3️⃣ Resolve key
    let key;
    if (store.data.mode === "project") {
     await ensureProjectKey(ws, extensionContext);
      key = await getProjectKey(ws);
    } else {
      // ✅ MACHINE MODE → SILENT
      key = await getOrCreateMachineKey(extensionContext);
    }

    if (!Buffer.isBuffer(key) || key.length !== 32) {
      vscode.window.showErrorMessage("Invalid encryption key.");
      return;
    }

    await ensureMetroConfig(ws);

//  await ensureShielderRuntime(ws, store);

   const files = await vscode.workspace.findFiles(
  "**/*.{js,ts,jsx,tsx}",
  "{**/node_modules/**,**/.vscode/**,**/.expo/**}"
);

console.log("[Shielder] found files:", files.length);
for (const f of files.slice(0,20)) { console.log("[Shielder] ->", f.fsPath); }


    let updatedFiles = 0;
    let detectedAny = false;

    for (const file of files) {
      if (shouldSkipScanFile(file)) continue;

      const original = (await vscode.workspace.fs.readFile(file)).toString();
      const lines = original.split("\n");
      let changed = false;

      for (let i = 0; i < lines.length; i++) {
        if (i < 5) console.log(`[Shielder] scanning ${file.fsPath} line ${i+1}: ${lines[i].slice(0,200)}`);

        const found = detect(lines[i]);

        if (found.length) console.log(`[Shielder] detect() -> `, found);


        
        if (!found.length) continue;

        for (const s of found) {
          detectedAny = true;

          const hash = hashValue(s.value);
          const existing = store.data.secrets.find(e => e.hash === hash);

          const placeholder =
            existing?.placeholder ??
            `<SECRET_${crypto.randomBytes(4).toString("hex").toUpperCase()}>`;

          if (lines[i].includes("resolveSecret(")) continue;

          const encrypted =
            existing?.encrypted ?? encryptWithKey(key, s.value);

          lines[i] = lines[i]
            .replace(`"${s.value}"`, `resolveSecret("${placeholder}")`)
            .replace(`'${s.value}'`, `resolveSecret("${placeholder}")`);

          store.data.secrets.push({
            id: crypto.randomBytes(4).toString("hex"),
            type: s.type,
            hash,
            file: path.relative(ws.uri.fsPath, file.fsPath),
            line: i + 1,
            placeholder,
            variable: s.variable,
            encrypted,
            disabled: false
          });

          changed = true;
        }
      }

if (changed) {
  // ✅ FIX: Only add imports to JS/JSX/TS/TSX files, NOT config files
  const fileName = path.basename(file.fsPath);
  const isSourceFile = /\.(js|jsx|ts|tsx)$/.test(fileName);
  const isConfigFile = fileName.includes('config') || 
                       fileName.includes('metro.') || 
                       fileName.includes('babel.');
  
  if (runtimeImport && !original.includes(runtimeImport) && isSourceFile && !isConfigFile) {
    // 1) ensure runtime API import is present (will be second)
    if (!original.includes(`import { resolveSecret } from "${runtimeImport}"`)) {
      lines.unshift(`import { resolveSecret } from "${runtimeImport}";`);
    }

    // 2) then ensure bootstrap import is the very first line (so it runs before anything)
    if (platform.id === "react-native") {
      if (!original.includes('import "./shielderx.runtime"')) {
        // put bootstrap BEFORE the runtime API import
        lines.unshift('import "./shielderx.runtime";');
      }
    }
  }


       suspendAutoRestore(800);
markInternalOp(file);
await vscode.workspace.fs.writeFile(
  file,
  Buffer.from(lines.join("\n"))
);
unmarkInternalOp(file);


        updatedFiles++;
      }
    }

    if (!detectedAny) {
      vscode.window.showInformationMessage("ℹ️ No secrets detected");
      return;
    }

   suspendAutoRestore(800);
markInternalOp(store.uri);
await vscode.workspace.fs.writeFile(
  store.uri,
  Buffer.from(JSON.stringify(store.data, null, 2))
);
unmarkInternalOp(store.uri);

await ensureShielderRuntime(ws, store);

    await writeRecoveryFile(ws, extensionContext);
    updateShielderStatus(store.data.mode,  store.data.owner);

    vscode.window.showInformationMessage(
      `🔐 Secrets protected: ${updatedFiles} files updated`
    );
  })
);
}


function getCurrentActor() {
  const os = require("os");

  return {
    user: os.userInfo().username,
    host: os.hostname(),
    platform: process.platform,
    claimedAt: new Date().toISOString()
  };
}



function openShielderIncidentWebview(type) {
  const panel = vscode.window.createWebviewPanel(
    "shielderIncident",
    "ShielderX — Security Notice",
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  panel.webview.html = getShielderIncidentHTML(type);
}

let manageSecretsActive = false;



function openManageSecrets(ws) {
  manageSecretsActive = true;

  const panel = vscode.window.createWebviewPanel(
    "shielderManageSecrets",
    "Shielder — Manage Secrets",
    vscode.ViewColumn.One,
    { enableScripts: true }
  );

  panel.webview.html = getManageSecretsHTML();

  // ─────────────────────────────
  // 🔍 Helper: find current line dynamically
  // ─────────────────────────────

  panel.onDidDispose(() => {
  manageSecretsActive = false;
});


async function findCurrentLine(ws, secret) {
  try {
    const fileUri = vscode.Uri.joinPath(ws.uri, secret.file);
    const lines = (await vscode.workspace.fs.readFile(fileUri))
      .toString()
      .split("\n");

    // Enabled → search by placeholder
    if (!secret.disabled) {
      const target = `resolveSecret("${secret.placeholder}")`;
      const index = lines.findIndex(l => l.includes(target));
      return index === -1 ? null : index + 1;
    }

    // Disabled → search by variable name
    if (secret.variable) {
      const regex = new RegExp(
        `\\b(const|let|var)\\s+${secret.variable}\\s*=`
      );
      const index = lines.findIndex(l => regex.test(l));
      return index === -1 ? null : index + 1;
    }

    return null;
  } catch {
    return null;
  }
}



  // ─────────────────────────────
  // 🧱 Helper: build UI payload (SINGLE source of truth)
  // ─────────────────────────────
  async function buildSecretsForUI(ws, store) {
  const sorted = [...store.data.secrets].sort((a, b) =>
    a.disabled === b.disabled ? 0 : a.disabled ? 1 : -1
  );

  const result = [];

  for (const s of sorted) {
    const line = await findCurrentLine(ws, s);

    result.push({
      id: s.id,
      file: s.file,
      line: line ?? "—",
      placeholder: s.placeholder,
      disabled: s.disabled,
      length: typeof s.encrypted === "string"
  ? s.encrypted.length
  : s.encrypted?.data
    ? Math.floor(s.encrypted.data.length / 2)
    : 8

    });
  }

  return result;
}


  panel.webview.onDidReceiveMessage(async msg => {
const store = await loadSecretFile(ws);
let key;
if (store.data.mode === "project") {
  key = await getProjectKey(ws);
} else {
  key = await getOrCreateMachineKey(extensionContext);
}


    // ─────────────────────────────
    // 📥 INITIAL LOAD
    // ─────────────────────────────
    if (msg.type === "load") {
      const secretsForUI = await buildSecretsForUI(ws, store);

      panel.webview.postMessage({
        type: "render",
        secrets: secretsForUI
      });
    }

    // ─────────────────────────────
    // 👁 SHOW SECRET VALUE
    // ─────────────────────────────
    if (msg.type === "show") {
      const s = store.data.secrets.find(x => x.id === msg.id);
      if (!s) return;

      const value = decryptWithKey(key, s.encrypted);

      panel.webview.postMessage({
        type: "reveal",
        id: s.id,
        value
      });
    }

    // ─────────────────────────────
    // 💾 SAVE EDITED VALUE
    // ─────────────────────────────
    if (msg.type === "save") {
      const s = store.data.secrets.find(x => x.id === msg.id);
      if (!s) return;

      s.encrypted = encryptWithKey(key, msg.value);

     suspendAutoRestore(800);
markInternalOp(store.uri);
await vscode.workspace.fs.writeFile(
  store.uri,
  Buffer.from(JSON.stringify(store.data, null, 2))
);
unmarkInternalOp(store.uri);

    }

    // ─────────────────────────────
    // 🔁 TOGGLE ENABLE / DISABLE
    // ─────────────────────────────
   if (msg.type === "toggle") {
  const s = store.data.secrets.find(x => x.id === msg.id);
  if (!s) return;

  const fileUri = vscode.Uri.joinPath(ws.uri, s.file);
  let lines;

  try {
    lines = (await vscode.workspace.fs.readFile(fileUri))
      .toString()
      .split("\n");
  } catch {
    vscode.window.showErrorMessage(`Cannot open ${s.file}`);
    return;
  }

  const placeholderCall = `resolveSecret("${s.placeholder}")`;

  // ───────── DISABLE ─────────
  if (!s.disabled) {
    const idx = lines.findIndex(l => l.includes(placeholderCall));
    if (idx === -1) {
      vscode.window.showErrorMessage(
        `Cannot disable: placeholder not found in ${s.file}`
      );
      return;
    }

    const plaintext = decryptWithKey(key, s.encrypted);

    lines[idx] = lines[idx].replace(
      placeholderCall,
      `"${plaintext}"`
    );

    s.disabled = true;
  }

  // ───────── ENABLE ─────────
  else {
    const plaintext = decryptWithKey(key, s.encrypted);

    const idx = lines.findIndex(l => l.includes(`"${plaintext}"`));
    if (idx === -1) {
      vscode.window.showErrorMessage(
        `Cannot enable: plaintext not found in ${s.file}`
      );
      return;
    }

    lines[idx] = lines[idx].replace(
      `"${plaintext}"`,
      placeholderCall
    );

    s.disabled = false;
  }

  // ✍️ Write source file (trusted operation)
  markInternalOp(fileUri);
  await vscode.workspace.fs.writeFile(
    fileUri,
    Buffer.from(lines.join("\n"))
  );
  unmarkInternalOp(fileUri);

  // 💾 Save store (trusted)
  markInternalOp(store.uri);
  await vscode.workspace.fs.writeFile(
    store.uri,
    Buffer.from(JSON.stringify(store.data, null, 2))
  );
  unmarkInternalOp(store.uri);

  // 🔐 CRITICAL: Update recovery snapshot so auto-restore agrees
  await writeRecoveryFile(ws, extensionContext);

  // 🔁 Re-render UI
  const secretsForUI = await buildSecretsForUI(ws, store);
  panel.webview.postMessage({
    type: "render",
    secrets: secretsForUI
  });
}

  });
}


async function fullyRevertProtection(ws) {
  // 🛑 Stop auto-restore during revert
  suspendAutoRestore(2000);

  const recoveryUri = vscode.Uri.joinPath(ws.uri, RECOVERY_FILE);
  const keyUri = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);
  const storeUri = vscode.Uri.joinPath(ws.uri, SECRET_FILE);

  // 1️⃣ Delete recovery FIRST
  try {
    markInternalOp(recoveryUri);
    await vscode.workspace.fs.delete(recoveryUri);
  } catch {}
  finally {
    unmarkInternalOp(recoveryUri);
  }

  // 2️⃣ Delete project key
  try {
    markInternalOp(keyUri);
    await vscode.workspace.fs.delete(keyUri);
  } catch {}
  finally {
    unmarkInternalOp(keyUri);
  }

  // 3️⃣ Delete secret store
  try {
    markInternalOp(storeUri);
    await vscode.workspace.fs.delete(storeUri);
  } catch {}
  finally {
    unmarkInternalOp(storeUri);
  }
}


function getShielderIncidentHTML(type) {
  let title = "";
  let message = "";

  switch (type) {
    case "key-deleted":
      title = "Shielder Key Deleted";
      message = `
        <p>The <code>.shielder.key</code> file was deleted.</p>
        <p>This key is required to decrypt all protected secrets.</p>
        <p><strong>Without this key, secrets cannot be recovered.</strong></p>
        <p>If you have a backup, restore it immediately.</p>
      `;
      break;

    case "key-modified":
      title = "Shielder Key Modified";
      message = `
        <p>The <code>.shielder.key</code> file was modified manually.</p>
        <p>This may cause decryption failures or corrupted secrets.</p>
        <p>Restore the original key if possible.</p>
      `;
      break;

    case "store-deleted":
      title = "Secret Store Deleted";
      message = `
        <p>The <code>.ai-secret-guard.json</code> file was deleted.</p>
        <p>This file tracks protected secrets and placeholders.</p>
        <p>Protection state is now lost.</p>
      `;
      break;

    case "store-modified":
      title = "Secret Store Modified";
      message = `
        <p>The secret store was edited outside Shielder.</p>
        <p>This may corrupt secret mappings or placeholders.</p>
        <p>Proceed carefully.</p>
      `;
      break;
  }

  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<style>
  body {
    margin: 0;
    padding: 0;
    background: #0f1115;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    color: #e6e6eb;
  }
  .card {
    max-width: 640px;
    margin: 48px auto;
    background: #161a22;
    border-radius: 14px;
    padding: 28px;
    box-shadow: 0 20px 40px rgba(0,0,0,.45);
  }
  h1 {
    margin-top: 0;
    font-size: 20px;
  }
  p {
    line-height: 1.6;
    color: #cfd3ff;
  }
  code {
    background: #222634;
    padding: 3px 6px;
    border-radius: 6px;
    color: #9aa4ff;
  }
  .btn {
    margin-top: 24px;
    padding: 10px 18px;
    border-radius: 10px;
    border: none;
    background: linear-gradient(135deg, #6e7bff, #8f9bff);
    color: #0f1115;
    font-weight: 600;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="card">
    <h1>${title}</h1>
    ${message}
    <button class="btn" onclick="window.close()">OK</button>
  </div>
</body>
</html>
`;
}


function getManageSecretsHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />

<style>

/* Make Disable button match Proceed button (soft red) */
.btn-toggle[data-disabled="false"] {
  background: #d16969 !important;
  border: none !important;
  color: white !important;
  box-shadow: 0 6px 18px rgba(0,0,0,0.35) !important;
  border-radius: 8px !important;
  font-weight: 500;
}


/* Add breathing room between VALUE and STATUS */
td:nth-child(4) {
  padding-right: 16px !important;   /* Value column */
}

td:nth-child(5) {
  padding-left: 12px !important;    /* Status column */
}


/* ----- GENERAL LAYOUT ----- */

body {
  font-family: var(--vscode-font-family);
  color: var(--vscode-editor-foreground);
  background: radial-gradient(
      ellipse at top,
      rgba(0,0,0,0.55),
      rgba(0,0,0,0.85)
  );
  margin: 0;
  padding: 28px;
  display: flex;
  justify-content: center;
}

.container {
  width: 100%;
  max-width: 950px;
  background: var(--vscode-editor-background);
  padding: 26px 28px;
  border-radius: 16px;
  box-shadow:
    0 30px 90px rgba(0,0,0,0.75),
    inset 0 1px 0 rgba(255,255,255,0.04);
  border: 1px solid rgba(255,200,0,0.18);
}

/* ----- HEADER ----- */

h2 {
  margin: 0 0 6px;
  font-size: 20px;
  font-weight: 600;
}

.info-note {
  font-size: 12px;
  color: var(--vscode-descriptionForeground);
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 6px;
  opacity: 0.85;
}

/* ----- TABLE ----- */

table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  margin-top: 10px;
  background: rgba(255,255,255,0.02);
  border-radius: 12px;
  overflow: hidden;
}

th {
  background: rgba(255,255,255,0.04);
  padding: 10px 8px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid rgba(255,255,255,0.06);
}

td {
  padding: 9px 8px;
  border-bottom: 1px solid rgba(255,255,255,0.05);
  font-size: 13px;
}

.placeholder {
  font-family: monospace;
  font-size: 12px;
  opacity: 0.9;
}

/* Input field */
input {
  width: 100%;
  padding: 6px;
  font-size: 12px;
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.09);
  border-radius: 6px;
  color: var(--vscode-editor-foreground);
}

/* ----- BUTTONS ----- */

button {
  cursor: pointer;
  border-radius: 8px;
  border: 1px solid var(--vscode-editorGroup-border);
  padding: 5px 12px;
  font-size: 12px;
  background: rgba(255,255,255,0.05);
  color: var(--vscode-editor-foreground);
  transition: opacity 0.15s ease, transform 0.05s ease;
}

button:active {
  transform: scale(0.97);
}

.btn-show {
  border-color: rgba(255,255,255,0.18);
}

.btn-toggle {
  background: rgba(255,200,0,0.12);
  border-color: rgba(255,200,0,0.25);
}

/* Status color */
.status-enabled {
  color: #89d185;
  font-weight: 600;
}
.status-disabled {
  color: #d16969;
  font-weight: 600;
}

/* ----- MODAL OVERLAY ----- */

.overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.55);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}

.overlay.hidden {
  display: none !important;
}

.confirm-box {
  background: var(--vscode-editor-background);
  color: var(--vscode-editor-foreground);
  width: 420px;
  padding: 26px;
  border-radius: 14px;
  text-align: center;
  box-shadow:
    0 30px 80px rgba(0,0,0,0.75),
    inset 0 1px 0 rgba(255,255,255,0.04);
  border: 1px solid rgba(255,200,0,0.22);
}

.confirm-box .icon {
  font-size: 34px;
  margin-bottom: 8px;
}

.confirm-box h3 {
  margin: 8px 0;
  font-weight: 600;
}

.confirm-box p {
  font-size: 13px;
  line-height: 1.55;
  opacity: 0.9;
}

.confirm-box .actions {
  margin-top: 20px;
  display: flex;
  justify-content: center;
  gap: 12px;
}

.confirm-box button {
  padding: 7px 16px;
  font-size: 13px;
  border-radius: 8px;
}

.confirm-box .danger {
  background: #d16969;
  border: none;
  color: white;
  box-shadow: 0 6px 18px rgba(0,0,0,0.45);
}

</style>
</head>

<body>

<div class="container">

  <h2>Manage Secrets</h2>

  <div class="info-note">
    ℹ️ Line numbers are shown only when protection is enabled.
  </div>

  <table>
    <thead>
      <tr>
        <th style="width:14%">File</th>
        <th style="width:6%">Line</th>
        <th style="width:26%">Placeholder</th>
        <th style="width:22%">Value</th>
        <th style="width:10%">Status</th>
        <th style="width:14%">Action</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
</div>


<!-- MODAL -->
<div id="confirm-overlay" class="overlay hidden">
  <div class="confirm-box">
    <div class="icon">⚠️</div>
    <h3>Shielder AI Warning</h3>
    <p>
      This will remove protection and restore the secret into source code.
      <br><br>AI tools may be able to read it.
    </p>

    <div class="actions">
      <button id="confirm-cancel">Cancel</button>
      <button id="confirm-proceed" class="danger">Proceed</button>
    </div>
  </div>
</div>


<script>
/* --------------------------
   YOUR ORIGINAL JS — UNTOUCHED
---------------------------*/

let pendingToggleId = null;

function showConfirm(id) {
  pendingToggleId = id;
  document.getElementById("confirm-overlay").classList.remove("hidden");
}

function hideConfirm() {
  pendingToggleId = null;
  document.getElementById("confirm-overlay").classList.add("hidden");
}

document.getElementById("confirm-cancel").onclick = hideConfirm;

document.getElementById("confirm-proceed").onclick = () => {
  vscode.postMessage({
    type: "toggle",
    id: pendingToggleId
  });
  hideConfirm();
};

const vscode = acquireVsCodeApi();
vscode.postMessage({ type: "load" });

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function mask(len) {
  return "•".repeat(Math.max(len || 8, 4));
}

window.addEventListener("message", event => {
  if (event.data.type !== "render") return;

  const tbody = document.getElementById("rows");
  tbody.innerHTML = "";

  event.data.secrets.forEach(s => {
    const tr = document.createElement("tr");

    tr.innerHTML = \`
      <td>\${s.file || "-"}</td>
      <td>\${s.line ?? "-"}</td>
      <td><code class="placeholder">\${escapeHtml(s.placeholder)}</code></td>
      <td>
        <input
          type="password"
          id="val-\${s.id}"
          data-length="\${s.length || 8}"
          value="\${mask(s.length)}"
          readonly
        />
      </td>
      <td class="\${s.disabled ? "status-disabled" : "status-enabled"}">
        \${s.disabled ? "DISABLED" : "ENABLED"}
      </td>
      <td>
        <button class="btn-show" data-id="\${s.id}">Show</button>
        <button
          class="btn-toggle"
          data-id="\${s.id}"
          data-disabled="\${s.disabled}"
        >
          \${s.disabled ? "Enable" : "Disable"}
        </button>
      </td>
    \`;

    tbody.appendChild(tr);
  });
});

window.addEventListener("message", event => {
  if (event.data.type === "reveal") {
    const input = document.getElementById("val-" + event.data.id);
    input.type = "text";
    input.value = event.data.value;
    input.setAttribute("data-length", event.data.value.length);

    const btn = document.querySelector(
      '.btn-show[data-id="' + event.data.id + '"]'
    );
    if (btn) btn.innerText = "Hide";
  }
});

document.addEventListener("click", event => {
  const showBtn = event.target.closest(".btn-show");
  if (showBtn) {
    const id = showBtn.dataset.id;
    const input = document.getElementById("val-" + id);

    if (showBtn.innerText === "Show") {
      vscode.postMessage({ type: "show", id });
    } else {
      input.type = "password";
      input.value = mask(input.dataset.length);
      showBtn.innerText = "Show";
    }
    return;
  }

  const toggleBtn = event.target.closest(".btn-toggle");
  if (toggleBtn) {
    const id = toggleBtn.dataset.id;
    const disabled = toggleBtn.dataset.disabled === "true";

    if (!disabled) {
      showConfirm(id);
      return;
    }

    vscode.postMessage({ type: "toggle", id });
  }
});
</script>

</body>
</html>
`;
}







function openExportKeyConfirm(ws) {
  const panel = vscode.window.createWebviewPanel(
    "shielderExportKey",
    "Shielder — Export Project Key",
    vscode.ViewColumn.Active,
    { enableScripts: true }
  );

  panel.webview.html = getExportKeyHTML();

  panel.webview.onDidReceiveMessage(async msg => {
    if (msg.type === "cancel") {
      panel.dispose();
      return;
    }

    if (msg.type === "confirm") {
      panel.dispose();
      await exportProjectKey(ws);
    }

  });
}


function getExportKeyHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<style>
  body {
    font-family: var(--vscode-font-family);
    color: var(--vscode-editor-foreground);
    padding: 24px;
  }
  .container {
    max-width: 520px;
    margin: auto;
  }
  h2 {
    margin-top: 0;
    font-weight: 600;
  }
  .warning {
    background: var(--vscode-inputValidation-warningBackground);
    border: 1px solid var(--vscode-inputValidation-warningBorder);
    padding: 14px;
    border-radius: 6px;
    margin: 16px 0;
  }
  .warning p {
    margin: 6px 0;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    margin-top: 24px;
  }
  button {
    padding: 6px 14px;
    font-size: 13px;
    cursor: pointer;
  }
  .primary {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none;
  }
  .secondary {
    background: transparent;
    color: var(--vscode-editor-foreground);
    border: 1px solid var(--vscode-editorGroup-border);
  }
</style>
</head>
<body>
<div class="container">
  <h2>🔐 Export Project Key</h2>

  <div class="warning">
    <p><strong>This key can decrypt all secrets in this project.</strong></p>
    <p>Anyone with this file can access sensitive data.</p>
    <p>Store it securely (password manager, vault, CI secrets).</p>
  </div>

  <div class="actions">
    <button class="secondary" onclick="cancel()">Cancel</button>
    <button class="primary" onclick="confirm()">Export Key</button>
  </div>
</div>

<script>
  const vscode = acquireVsCodeApi();
  function cancel() {
    vscode.postMessage({ type: "cancel" });
  }
  function confirm() {
    vscode.postMessage({ type: "confirm" });
  }
</script>
</body>
</html>`;
}

async function handleWorkspaceOpen(extensionContext) {
  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) return;

  // ─────────────────────────────
  // 🔁 AUTO-VERIFY / RECOVERY
  // ─────────────────────────────
  const recoveryUri = vscode.Uri.joinPath(ws.uri, RECOVERY_FILE);

  try {
    await vscode.workspace.fs.stat(recoveryUri);
    await verifyAndRestore(ws);
  } catch {
    // no recovery yet → continue
  }

  // ─────────────────────────────
  // 🔔 NORMAL ONBOARDING FLOW
  // ─────────────────────────────
  const store = await loadSecretFile(ws, { createIfMissing: false });

  if (!store || !store.data?.mode) {
    // ✅ FIX: Check source files BEFORE showing fresh install popup
    const alreadyProtected = await isProjectAlreadyProtected(ws);

    if (alreadyProtected) {
      // Project IS protected but ShielderX files are missing
      // Show recovery warning instead of fresh install popup
      updateShielderStatus(null, null);
      vscode.window.showWarningMessage(
        "⚠️ ShielderX: Protected project detected but config files are missing!\n\n" +
        "Run 'ShielderX: Generate Recovery' to restore all files.",
        "Generate Recovery",
        "Dismiss"
      ).then(choice => {
        if (choice === "Generate Recovery") {
          vscode.commands.executeCommand("shielder.generateRecovery");
        }
      });
      return;
    }

    // Truly a fresh project → show onboarding
    updateShielderStatus(null, null);
    openOnOpenWarning(ws);
    return;
  }

  if (store.data.mode === "machine") {
    await getOrCreateMachineKey(extensionContext);
  }

  updateShielderStatus(store.data.mode, store.data.owner);
}





function isSecretPlaceholderValue(value) {
  return /^<SECRET_[A-Z0-9]+>$/.test(value);
}




let onOpenWarningPanel = null;

function openOnOpenWarning(ws, options = {}) {

   if (onOpenWarningPanel) {
    onOpenWarningPanel.reveal();
    return;
  }


  onOpenWarningPanel = vscode.window.createWebviewPanel(
    "shielderOnOpenWarning",
    "Shielder — Security Warning",
    vscode.ViewColumn.Active,
    { enableScripts: true }
  );

  onOpenWarningPanel.webview.html = getOnOpenWarningHTML();

  onOpenWarningPanel.onDidDispose(() => {
    onOpenWarningPanel = null;
  });

 onOpenWarningPanel.webview.onDidReceiveMessage(async msg => {

  if (msg.type === "protect-default") {
    onOpenWarningPanel.dispose();

    // set mode = project
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) return;

    const store =
      (await loadSecretFile(ws, { createIfMissing: false })) ??
      (await loadSecretFile(ws)); // create now

    store.data.mode = "project";

    await vscode.workspace.fs.writeFile(
      store.uri,
      Buffer.from(JSON.stringify(store.data, null, 2))
    );
    
updateShielderStatus("project");
    vscode.commands.executeCommand("shielder.scan");
    return;
  }

  if (msg.type === "protect-machine") {
    onOpenWarningPanel.dispose();

    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) return;

    const store =
      (await loadSecretFile(ws, { createIfMissing: false })) ??
      (await loadSecretFile(ws)); // create now

    store.data.mode = "machine";

    await vscode.workspace.fs.writeFile(
      store.uri,
      Buffer.from(JSON.stringify(store.data, null, 2))
    );
updateShielderStatus("machine");

     vscode.commands.executeCommand("shielder.scan");
    // do NOT scan yet – machine key must be generated first
   // openGenerateMachineKey(extensionContext);
    return;
  }

  if (msg.type === "ignore") {
    onOpenWarningPanel.dispose();
    return;
  }
});


}

function getOnOpenWarningHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<style>
  body {
    margin: 0;
    font-family: var(--vscode-font-family);
    background: radial-gradient(
      ellipse at center,
      rgba(0,0,0,0.6),
      rgba(0,0,0,0.85)
    );
    color: var(--vscode-editor-foreground);
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .action-group {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .info-icon {
    cursor: pointer;
    font-size: 13px;
    color: #9da5b4;
    border: 1px solid #3c3c3c;
    border-radius: 50%;
    width: 16px;
    height: 16px;
    line-height: 14px;
    text-align: center;
  }

  .info-icon:hover {
    color: #ffffff;
    background: #3c3c3c;
  }

  .tooltip {
    position: absolute;
    max-width: 320px;
    background: #1e1e1e;
    color: #d4d4d4;
    border: 1px solid #3c3c3c;
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 12px;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  }

  .hidden {
    display: none;
  }

  .card {
    width: 560px;
    background: var(--vscode-editor-background);
    border-radius: 16px;
    padding: 30px 30px 26px;
    box-shadow:
      0 30px 90px rgba(0,0,0,0.8),
      inset 0 1px 0 rgba(255,255,255,0.04);
    border: 1px solid rgba(255, 200, 0, 0.28);
  }

  .header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 14px;
  }

  .icon {
    font-size: 24px;
  }

  h2 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
  }

  .subtle {
    font-size: 12px;
    color: var(--vscode-descriptionForeground);
    margin-top: 4px;
  }

  .warning-box {
    margin-top: 18px;
    background: linear-gradient(
      180deg,
      rgba(255, 200, 0, 0.18),
      rgba(255, 200, 0, 0.08)
    );
    border: 1px solid rgba(255, 200, 0, 0.35);
    border-radius: 12px;
    padding: 18px;
    font-size: 13px;
    line-height: 1.55;
  }

  .warning-box strong {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
  }

  .trust {
    margin-top: 14px;
    font-size: 12px;
    color: var(--vscode-descriptionForeground);
    display: grid;
    gap: 6px;
  }

  .trust span {
    display: flex;
    gap: 6px;
    align-items: center;
  }

  .divider {
    height: 1px;
    background: rgba(255,255,255,0.06);
    margin: 20px 0;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
  }

  .danger {
    background: #d16969;
    color: white;
    box-shadow: 0 6px 18px rgba(0,0,0,0.45);
  }

  button {
    padding: 9px 18px;
    font-size: 13px;
    border-radius: 9px;
    cursor: pointer;
    border: none;
    transition: transform 0.05s ease, opacity 0.1s ease;
  }

  button:active {
    transform: scale(0.98);
  }

  .secondary {
    background: transparent;
    color: var(--vscode-editor-foreground);
    border: 1px solid var(--vscode-editorGroup-border);
    opacity: 0.85;
  }

  .primary {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    box-shadow: 0 6px 20px rgba(0,0,0,0.4);
  }
</style>
</head>

<body>
  <div class="card">
    <div class="header">
      <div class="icon">🔐</div>
      <div>
        <h2>ShielderX</h2>
        <div class="subtle">Proactive protection before AI tools access code</div>
      </div>
    </div>

    <div class="warning-box">
      <strong>This project may contain sensitive secrets.</strong>
      AI coding assistants can read source files before protection is enabled.
      Shielder replaces secrets with secure placeholders to prevent accidental exposure.
    </div>

    <div class="trust">
      <span>✔ Secrets stay local — nothing is sent to the cloud</span>
      <span>✔ Protection is fully reversible at any time</span>
      <span>✔ Works silently with your existing workflow</span>
    </div>

    <div class="divider"></div>

    <div class="actions">
      <div class="action-group">
        <button class="primary" onclick="protectDefault()">
          Protect (Project Key)
        </button>
        <span class="info-icon" data-info="project-key">ⓘ</span>
      </div>

      <div class="action-group">
        <button class="danger" onclick="protectMachine()">
          Protect (Machine Key)
        </button>
        <span class="info-icon" data-info="machine-key">ⓘ</span>
      </div>

    </div>

    <div id="info-tooltip" class="tooltip hidden"></div>
  </div>

<script>
  const vscode = acquireVsCodeApi();

  function ignore() {
    vscode.postMessage({ type: "ignore" });
  }

  function protectDefault() {
    vscode.postMessage({ type: "protect-default" });
  }

  function protectMachine() {
    vscode.postMessage({ type: "protect-machine" });
  }

  // ─────────────────────────────
  // INFO TOOLTIP LOGIC (ADDED)
  // ─────────────────────────────
  const tooltip = document.getElementById("info-tooltip");


   const INFO_TEXT = {
    "project-key":
      "<b>Project Key</b><br><br>" +
      "• A shared key is saved in the project<br>" +
      "• Team members can decrypt automatically after pull<br>" +
      "• Best for shared repositories<br><br>" +
      "⚠️ Losing the key means secrets cannot be recovered",

    "machine-key":
      "<b>Machine Key</b><br><br>" +
      "• Key is stored only on this machine<br>" +
      "• Nothing is committed to Git<br>" +
      "• Each developer initializes locally<br><br>" +
      "🔒 Most secure option for AI protection"
  };

  document.querySelectorAll(".info-icon").forEach(icon => {
    icon.addEventListener("click", e => {
      e.stopPropagation();
      const key = icon.dataset.info;
      tooltip.innerHTML = INFO_TEXT[key];

      const rect = icon.getBoundingClientRect();
      tooltip.style.top = rect.bottom + 6 + "px";
      tooltip.style.left = rect.left + "px";

      tooltip.classList.remove("hidden");
    });
  });

  document.addEventListener("click", () => {
    tooltip.classList.add("hidden");
  });

 

</script>
</body>
</html>`;
}

/*

  Revert Project logic

*/


async function runUninstall(pm, pkg) {
  const terminal = vscode.window.createTerminal("Shielder Cleanup");
  terminal.show();

  if (pm === "yarn") {
    terminal.sendText(`yarn remove ${pkg}`);
  } else if (pm === "pnpm") {
    terminal.sendText(`pnpm remove ${pkg}`);
  } else {
    terminal.sendText(`npm uninstall ${pkg}`);
  }
}



async function revertProject(extensionContext, ws) {
  // 🛑 Stop auto-restore during full revert
  suspendAutoRestore(3000);

  const storeUri = vscode.Uri.joinPath(ws.uri, SECRET_FILE);
  const keyUri = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);
  const recoveryUri = vscode.Uri.joinPath(ws.uri, RECOVERY_FILE);

  let store;

  // 1️⃣ Load store (if missing, still attempt cleanup)
  try {
    const raw = await vscode.workspace.fs.readFile(storeUri);
    store = JSON.parse(raw.toString());
  } catch {
    store = { secrets: [] };
  }

  // 2️⃣ Load key (only if needed)
  let key;
  try {
    const storeData = await loadSecretFile(ws, { createIfMissing: false });
    if (storeData?.data?.mode === "project") {
      key = await getProjectKey(ws);
    } else if (storeData?.data?.mode === "machine") {
      key = await getOrCreateMachineKey(extensionContext);
    }
  } catch {
    key = null;
  }

  // 3️⃣ Group secrets by file
  const secretsByFile = new Map();
  for (const s of store.secrets || []) {
    if (!secretsByFile.has(s.file)) {
      secretsByFile.set(s.file, []);
    }
    secretsByFile.get(s.file).push(s);
  }

  // 4️⃣ Revert all affected source files
  for (const [relativePath, secrets] of secretsByFile.entries()) {
    const fileUri = vscode.Uri.joinPath(ws.uri, relativePath);
    let content;

    try {
      content = (await vscode.workspace.fs.readFile(fileUri)).toString();
    } catch {
      continue;
    }

    // 4a️⃣ Replace known placeholders with plaintext
    for (const s of secrets) {
      if (!key) continue;

      let plaintext;
      try {
        plaintext = decryptWithKey(key, s.encrypted);
      } catch {
        continue;
      }

      const knownPattern = new RegExp(
        `resolveSecret\\s*\\(\\s*["']${s.placeholder}["']\\s*\\)`,
        "g"
      );

      content = content.replace(knownPattern, `"${plaintext}"`);
    }

    // 4b️⃣ FINAL SAFETY NET — remove any unresolved placeholders
    content = content.replace(
      /resolveSecret\s*\(\s*["']<SECRET_[A-Z0-9]+>["']\s*\)/g,
      '""'
    );

    // 4c️⃣ Remove ANY Shielder runtime import if no resolveSecret remains
    if (!content.includes("resolveSecret(")) {
      content = content.replace(
        /import\s+\{\s*resolveSecret\s*\}\s+from\s+["']@shielder[^"']*["'];?\s*\n?/g,
        ""
      );

      // Remove old runtime import name
      content = content.replace(
        /import\s+["']\.\/shielderx\.runtime["'];?\s*\n?/g,
        ""
      );

      // Remove new hidden runtime import name
      content = content.replace(
        /import\s+["']\.\/\.shielderx\.runtime["'];?\s*\n?/g,
        ""
      );
    }

    // 4d️⃣ Write reverted file safely
    markInternalOp(fileUri);
    await vscode.workspace.fs.writeFile(
      fileUri,
      Buffer.from(content)
    );
    unmarkInternalOp(fileUri);
  }

  // 5️⃣ Delete recovery FIRST (source of truth)
  try {
    markInternalOp(recoveryUri);
    await vscode.workspace.fs.delete(recoveryUri);
  } catch {}
  finally {
    unmarkInternalOp(recoveryUri);
  }

  // 6️⃣ Delete project key
  try {
    markInternalOp(keyUri);
    await vscode.workspace.fs.delete(keyUri);
  } catch {}
  finally {
    unmarkInternalOp(keyUri);
  }

  // 7️⃣ Delete secret store
  try {
    markInternalOp(storeUri);
    await vscode.workspace.fs.delete(storeUri);
  } catch {}
  finally {
    unmarkInternalOp(storeUri);
  }

  // 8️⃣ Close all editors (avoid stale buffers)
  await vscode.commands.executeCommand("workbench.action.closeAllEditors");

  // 9️⃣ Runtime & dependency cleanup
  const platform = await detectPlatform(ws);
  const pm = await detectPackageManager(ws);

 if (platform?.id === "react-native") {
  // Remove ALL generated bootstrap files (old and new names)
  const runtimeFiles = [
    vscode.Uri.joinPath(ws.uri, "shielderx.runtime.js"),
    vscode.Uri.joinPath(ws.uri, ".shielderx.runtime.js"),
    vscode.Uri.joinPath(ws.uri, "metro.config.js")
  ];
  for (const f of runtimeFiles) {
    try { await vscode.workspace.fs.delete(f); } catch {}
  }

  // Uninstall RN runtime package
  await runUninstall(pm, "@shielderx/react-native-runtime");
}

if (platform?.supportsRuntime && platform?.id !== "react-native") {
  await runUninstall(pm, "@shielderx/runtime");
}

  // ✅ FIX: Clear globalState recovery backup on revert
  try {
    const fingerprint = await generateProjectFingerprint(ws);
    const recoveryStorageKey = `shielderx-recovery-${fingerprint.slice(0, 16)}`;
    const keyStorageKey = `shielderx-key-${fingerprint.slice(0, 16)}`;
    await extensionContext.globalState.update(recoveryStorageKey, undefined);
    await extensionContext.globalState.update(keyStorageKey, undefined);
  } catch {}

  // 🔚 Final UI cleanup
  updateShielderStatus(null);
  vscode.window.showInformationMessage(
    "🔓 Shielder protection removed. All secrets restored and protection fully disabled."
  );
}


async function removeDependency(ws, pkgName) {
  try {
    const pkgUri = vscode.Uri.joinPath(ws.uri, "package.json");
    const raw = await vscode.workspace.fs.readFile(pkgUri);
    const pkg = JSON.parse(raw.toString());

    let changed = false;

    if (pkg.dependencies?.[pkgName]) {
      delete pkg.dependencies[pkgName];
      changed = true;
    }

    if (pkg.devDependencies?.[pkgName]) {
      delete pkg.devDependencies[pkgName];
      changed = true;
    }

    if (changed) {
      await vscode.workspace.fs.writeFile(
        pkgUri,
        Buffer.from(JSON.stringify(pkg, null, 2))
      );
    }
  } catch {
    // ignore if package.json missing or malformed
  }
}



function openRevertConfirm(extensionContext, ws) {
  const panel = vscode.window.createWebviewPanel(
    "shielderRevertConfirm",
    "Shielder — Revert Protection",
    vscode.ViewColumn.Active,
    { enableScripts: true }
  );

  panel.webview.html = getRevertConfirmHTML();

  panel.webview.onDidReceiveMessage(async msg => {
    if (msg.type === "cancel") {
      panel.dispose();
      return;
    }

    if (msg.type === "revert") {
      panel.dispose();
      await revertProject(extensionContext, ws);
    }
  });
}
function getRevertConfirmHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<style>
  body {
    margin: 0;
    font-family: var(--vscode-font-family);
    background: rgba(0,0,0,0.55);
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .card {
    width: 520px;
    background: var(--vscode-editor-background);
    border-radius: 14px;
    padding: 26px 28px;
    box-shadow: 0 30px 80px rgba(0,0,0,0.75);
    border: 1px solid rgba(255,120,120,0.35);
  }

  h2 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
  }

  .desc {
    margin-top: 12px;
    font-size: 13px;
    line-height: 1.55;
    opacity: 0.9;
  }

  ul {
    margin: 14px 0;
    padding-left: 18px;
    font-size: 13px;
  }

  .note {
    font-size: 12px;
    opacity: 0.8;
    margin-top: 10px;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    margin-top: 22px;
  }

  button {
    padding: 8px 16px;
    font-size: 13px;
    border-radius: 8px;
    border: none;
    cursor: pointer;
  }

  .secondary {
    background: transparent;
    border: 1px solid var(--vscode-editorGroup-border);
    color: var(--vscode-editor-foreground);
  }

  .danger {
    background: #d16969;
    color: white;
    box-shadow: 0 6px 18px rgba(0,0,0,0.45);
  }
</style>
</head>

<body>
  <div class="card">
    <h2>⚠️ Revert Shielder Protection</h2>

    <div class="desc">
      This will completely remove Shielder protection from this project.
    </div>

    <ul>
      <li>Secrets will be restored into source code</li>
      <li>Shielder files will be deleted</li>
      <li>AI tools will be able to read secrets</li>
    </ul>

    <div class="note">
      You can re-enable protection anytime by running <b>Scan Project</b>.
    </div>

    <div class="actions">
      <button class="secondary" onclick="cancel()">Cancel</button>
      <button class="danger" onclick="revert()">Revert & Remove</button>
    </div>
  </div>

<script>
  const vscode = acquireVsCodeApi();

  function cancel() {
    vscode.postMessage({ type: "cancel" });
  }

  function revert() {
    vscode.postMessage({ type: "revert" });
  }
</script>
</body>
</html>`;
}


function normalizePath(p) {
  return p.replace(/\\/g, "/").toLowerCase();
}

function markInternalOp(uri) {
  internalFsOps.add(normalizePath(uri.fsPath));
}

function unmarkInternalOp(uri) {
  internalFsOps.delete(normalizePath(uri.fsPath));
}

function isInternalOp(uri) {
  const path = normalizePath(uri.fsPath);

  // direct match
  if (internalFsOps.has(path)) return true;

  // fallback: filename-based match (VERY IMPORTANT)
  const name = path.split("/").pop();
  return (
    name === PROJECT_KEY_FILE.toLowerCase() ||
    name === SECRET_FILE.toLowerCase()
  );
}


async function isProjectProtected(ws) {
  try {
    const keyUri = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);
    const storeUri = vscode.Uri.joinPath(ws.uri, SECRET_FILE);

    await vscode.workspace.fs.stat(keyUri);
    await vscode.workspace.fs.stat(storeUri);

    return true;
  } catch {
    return false;
  }
}

async function getProtectionState(extensionContext, ws) {
  const store = await loadSecretFile(ws, { createIfMissing: false });
  if (!store) {
    return { protected: false };
  }

  const mode = store.data?.mode ?? null;
  if (!mode) {
    return { protected: false, store };
  }

  // 🔐 Machine mode is ALWAYS protected (key auto-generated)
  if (mode === "machine") {
    return { protected: true, mode, store };
  }

  // 🔐 Project mode requires project key
  if (mode === "project") {
    try {
      await getProjectKey(ws);
      return { protected: true, mode, store };
    } catch {
      return { protected: false, mode, store, reason: "missing-project-key" };
    }
  }

  return { protected: false, store };
}



function deactivate() { }

module.exports = { activate, deactivate };

/*
All the changes are done and noe we will move to generate key logic on machine level .
*/

/*
Hope this will be an placeholder to revert back the change if its needed
*/