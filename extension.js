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

/*********************************
 * CONSTANTS
 *********************************/
const ALGORITHM = "aes-256-gcm";
const PROJECT_KEY_FILE = ".shielder.key";
const SECRET_FILE = ".ai-secret-guard.json";

/*********************************
 * REGEX RULES
 *********************************/
const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PHONE_REGEX = /^\+?\d[\d\s-]{7,14}\d$/;
const API_KEY_REGEX = /^(sk_live_|sk_test_|AIzaSy)[A-Za-z0-9_-]+$/;

const STRING_ASSIGN_REGEX =
  /\b(const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*["'`]([^"'`]+)["'`]/g;

const STRING_LITERAL_REGEX = /["'`]([^"'`\n]+)["'`]/g;

const HARD_EXCLUDED_FILES = new Set([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.json",
  "podfile.lock",
  "Podfile.lock",
  "Info.plist" // optional: iOS metadata
]);


  const internalFsOps = new Set();

const SHIELDER_INTERNAL_FILES = new Set([
  PROJECT_KEY_FILE,          // .shielder.key
  SECRET_FILE                // .ai-secret-guard.json
]);

/*********************************
 * FINGERPRINT (DAY 9.3)
 *********************************/


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
  const fileName = uri.fsPath.split("/").pop();

  // 🚫 Skip Shielder internal files
  if (SHIELDER_INTERNAL_FILES.has(fileName)) {
    return true;
  }

  // 🚫 Skip hard-excluded project metadata files
  if (HARD_EXCLUDED_FILES.has(fileName)) {
    return true;
  }

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

  const salt = crypto.randomBytes(16).toString("hex");
  const raw = `${rootPath}|${pkgName}|${created}|${salt}`;

  return crypto.createHash("sha256").update(raw).digest("hex");
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

// New logic 
async function ensureProjectKey(workspaceFolder) {
  const uri = vscode.Uri.joinPath(workspaceFolder.uri, PROJECT_KEY_FILE);

  try {
    // If file exists, do nothing
    await vscode.workspace.fs.readFile(uri);
    vscode.window.showInformationMessage("🔑 Project key already exists");
    return;
  } catch {
    // Generate strong random key
    const key = crypto.randomBytes(32);

    // Add a binary header so editors don't treat it as text
    const header = Buffer.from("SHIELDER_KEY_v1\n", "utf8");
    const payload = Buffer.concat([header, key]);

    await vscode.workspace.fs.writeFile(uri, payload);

    vscode.window.showWarningMessage(
      "🔐 Project key generated. Backup `.shielder.key`. Losing it = losing secrets."
    );
  }
}


// async function getProjectKey(workspaceFolder) {
//   return Buffer.from(
//     await vscode.workspace.fs.readFile(
//       vscode.Uri.joinPath(workspaceFolder.uri, PROJECT_KEY_FILE)
//     )
//   );
// }



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
function encryptWithKey(key, value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  return {
    iv: iv.toString("hex"),
    data: encrypted.toString("hex"),
    tag: cipher.getAuthTag().toString("hex")
  };
}

function decryptWithKey(key, payload) {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(payload.iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(payload.data, "hex")),
    decipher.final()
  ]).toString("utf8");
}

function hashValue(v) {
  return crypto.createHash("sha256").update(v).digest("hex");
}

/*********************************
 * SECRET STORE
 *********************************/
async function loadSecretFile(workspaceFolder) {
  const uri = vscode.Uri.joinPath(workspaceFolder.uri, SECRET_FILE);

  try {
    const data = JSON.parse(
      (await vscode.workspace.fs.readFile(uri)).toString()
    );
    return { uri, data };
  } catch {
    const fingerprint = await generateProjectFingerprint(workspaceFolder);
    const fresh = {
      version: 2,
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

function isIgnoredContext(line) {
  if (!line) return true;

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

    // 🚫 IMPORT / EXPORT / REQUIRE (CRITICAL FIX)
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
  if (isIgnoredContext(line)) {
  return [];
}

  STRING_ASSIGN_REGEX.lastIndex = 0;
  STRING_LITERAL_REGEX.lastIndex = 0;

  const found = [];
  const seen = new Set();
  let m;

  // ─────────────────────────
  // 1️⃣ ASSIGNMENT DETECTION
  // ─────────────────────────
  while ((m = STRING_ASSIGN_REGEX.exec(line))) {
    const variable = m[2];
    const value = m[3];

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
  // 2️⃣ ARGUMENT / INLINE STRINGS
  // ─────────────────────────
  while ((m = STRING_LITERAL_REGEX.exec(line))) {
    const value = m[1];

    if (seen.has(value)) continue;
    if (value === "NOT_DECRYPTED_YET") continue;

    let type = null;
    if (EMAIL_REGEX.test(value)) type = "email";
    else if (PHONE_REGEX.test(value)) type = "phone";
    else if (API_KEY_REGEX.test(value)) type = "apiKey";
    else if (isLikelyKey(value)) type = "genericKey";
    else continue;

    found.push({
      value,
      type,
      variable: null // argument / inline
    });

    seen.add(value);
  }

  return found;
}



/*********************************
 * EXTENSION
 *********************************/

function setupProtectionWatchers(context) {
  // ─────────────────────────────
  // FILE SYSTEM WATCHERS
  // ─────────────────────────────
  const keyWatcher = vscode.workspace.createFileSystemWatcher(
    `**/${PROJECT_KEY_FILE}`
  );

  const storeWatcher = vscode.workspace.createFileSystemWatcher(
    `**/${SECRET_FILE}`
  );



  // 🔐 Key deleted (CRITICAL → modal)
  keyWatcher.onDidDelete((uri) => {
    if (isInternalOp(uri)) return;
    vscode.window.showErrorMessage(
      "🚨 Shielder key was deleted!\n\nSecrets can no longer be decrypted unless the key is restored.",
      { modal: true },
      "Learn more",
      "OK"
    ).then(selection => {
      if (selection === "Learn more") {
        openShielderIncidentWebview("key-deleted");
      }
    });
  });

 
  // 📦 Store deleted (CRITICAL → modal)
  storeWatcher.onDidDelete((uri) => {
    if (isInternalOp(uri)) return;
    vscode.window.showErrorMessage(
      "🚨 Secret store was deleted!\n\nProtection state is lost unless restored.",
      { modal: true },
      "Learn more",
      "OK"
    ).then(selection => {
      if (selection === "Learn more") {
        openShielderIncidentWebview("store-deleted");
      }
    });
  });

  context.subscriptions.push(keyWatcher, storeWatcher);
}


let blockingDialogActive = false;


function handleManagedFileOpen(editor) {
  if (!editor) return;

  const file = editor.document.fileName;
  const fileName = path.basename(file);

  if (
    file.endsWith(PROJECT_KEY_FILE) ||
    file.endsWith(SECRET_FILE)
  ) {
    if (blockingDialogActive) return;
    blockingDialogActive = true;

    vscode.window.showWarningMessage(
      `🔒 Protected file detected

File: ${fileName}

This file is managed by Shielder.
Manual editing is not allowed and changes will be reverted automatically.`,
      { modal: true },
      "OK"
    ).then(() => {
      blockingDialogActive = false;
      vscode.commands.executeCommand(
        "workbench.action.closeActiveEditor"
      );
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


function activate(context) {
setupProtectionWatchers(context);
  // also run once on activation
  handleWorkspaceOpen(context);

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      await handleWorkspaceOpen(context);
    })
  );


  // ─────────────────────────────
// BLOCK MANAGED FILES ON OPEN
// ─────────────────────────────
// Block managed files on open / focus
context.subscriptions.push(
  vscode.workspace.onDidOpenTextDocument(doc => {
    const editor = vscode.window.visibleTextEditors.find(
      e => e.document === doc
    );
    handleManagedFileOpen(editor);
  })
);

context.subscriptions.push(
  vscode.window.onDidChangeActiveTextEditor(editor => {
    handleManagedFileOpen(editor);
  })
);


context.subscriptions.push(
  vscode.commands.registerCommand("shielder.revertProject", async () => {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) return;
     // ✅ DECLARE it properly
    const protectedProject = await isProjectProtected(ws);

    if (!protectedProject) {
      openNotProtectedWebview(ws);
      return;
    }
    openRevertConfirm(context, ws);
  })
);


  context.subscriptions.push(
    vscode.commands.registerCommand("shielder.exportKey", async () => {
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) {
        vscode.window.showWarningMessage("No workspace open");
        return;
      }

      openExportKeyConfirm(ws);
    })
  );


context.subscriptions.push(
  vscode.commands.registerCommand("shielder.manageSecrets", async () => {
    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) return;

    // ✅ DECLARE it properly
    const protectedProject = await isProjectProtected(ws);

    if (!protectedProject) {
      openNotProtectedWebview(ws);
      return;
    }
   openManageSecrets(ws);
  })
);



  /* -------- SCAN PROJECT -------- */
 context.subscriptions.push(
  vscode.commands.registerCommand("shielder.scan", async () => {
    await context.workspaceState.update("shielder.reverted", false);

    const ws = vscode.workspace.workspaceFolders?.[0];
    if (!ws) {
      vscode.window.showWarningMessage(
        "⚠️ No workspace folder open. Open a project to scan."
      );
      return;
    }

    vscode.window.showInformationMessage("🔍 Scanning project for secrets…");

    await ensureProjectKey(ws);
    const store = await loadSecretFile(ws);
    const key = await getProjectKey(ws);

    const files = await vscode.workspace.findFiles(
      "**/*.{js,ts,jsx,tsx}",
      "**/node_modules/**"
    );

    let updatedFiles = 0;
    let detectedAny = false;

    for (const file of files) {
      if (shouldSkipScanFile(file)) continue;

      try {
        const text = (await vscode.workspace.fs.readFile(file)).toString();
        const lines = text.split("\n");

        // ─────────────────────────────
        // FILE-LEVEL GATE (LINE-BASED)
        // ─────────────────────────────
        const fileHasSecrets = lines.some(line => detect(line).length > 0);
        if (!fileHasSecrets) continue;

        let updated = text;

        // ─────────────────────────────
        // Ensure resolveSecret import
        // ─────────────────────────────
        const hasResolverImport = lines.some(
          l =>
            l.includes('import { resolveSecret }') &&
            l.includes('@shielder/runtime')
        );

        if (!hasResolverImport) {
          let insertAt = 0;
          while (
            insertAt < lines.length &&
            (lines[insertAt].startsWith("import ") ||
              lines[insertAt].startsWith("require("))
          ) {
            insertAt++;
          }

          lines.splice(
            insertAt,
            0,
            'import { resolveSecret } from "@shielder/runtime";'
          );
        }

        // ─────────────────────────────
        // LINE-BY-LINE REPLACEMENT
        // ─────────────────────────────
        for (let i = 0; i < lines.length; i++) {
          const found = detect(lines[i]);
          if (!found.length) continue;

          for (const s of found) {
            detectedAny = true;
            const hash = hashValue(s.value);

            // 🔥 IMPORTANT FIX:
            // If secret already exists → STILL replace in this file
            const existing = store.data.secrets.find(e => e.hash === hash);

            if (existing) {
              if (!lines[i].includes("resolveSecret(")) {
                lines[i] = lines[i]
                  .replace(
                    `"${s.value}"`,
                    `resolveSecret("${existing.placeholder}")`
                  )
                  .replace(
                    `'${s.value}'`,
                    `resolveSecret("${existing.placeholder}")`
                  );
              }
              continue;
            }

            // New secret
            const id = crypto.randomBytes(4).toString("hex");
            const placeholder = `<SECRET_${id.toUpperCase()}>`;
            const encrypted = encryptWithKey(key, s.value);

            if (!lines[i].includes("resolveSecret(")) {
              lines[i] = lines[i]
                .replace(
                  `"${s.value}"`,
                  `resolveSecret("${placeholder}")`
                )
                .replace(
                  `'${s.value}'`,
                  `resolveSecret("${placeholder}")`
                );
            }

            store.data.secrets.push({
              id,
              type: s.type,
              hash,
              file: path.relative(ws.uri.fsPath, file.fsPath),
              line: i + 1,
              placeholder,
              variable: s.variable,
              encrypted,
              disabled: false
            });
          }
        }

        updated = lines.join("\n");

        if (updated !== text) {
          await vscode.workspace.fs.writeFile(file, Buffer.from(updated));
          updatedFiles++;
        }
      } catch (err) {
        vscode.window.showWarningMessage(
          `❌ Failed to read file: ${path.basename(file.fsPath)}`
        );
      }
    }

    if (!detectedAny) {
      vscode.window.showInformationMessage("ℹ️ No secrets detected");
      return;
    }

    await vscode.workspace.fs.writeFile(
      store.uri,
      Buffer.from(JSON.stringify(store.data, null, 2))
    );

    vscode.window.showInformationMessage(
      `🔐 Secrets protected: ${updatedFiles} files updated`
    );
  })
);


  /* -------- ROTATE PROJECT KEY (9.4.2) -------- */
  context.subscriptions.push(
    vscode.commands.registerCommand("shielder.rotateKey", async () => {
      const ws = vscode.workspace.workspaceFolders?.[0];
      if (!ws) return;

      const confirm = await vscode.window.showWarningMessage(
        "♻️ Rotate project key? Old exported keys will stop working.",
        { modal: true },
        "Rotate"
      );

      if (confirm !== "Rotate") return;

      const store = await loadSecretFile(ws);
      const oldKey = await getProjectKey(ws);

      // 1️⃣ Decrypt all secrets in memory
      const plaintexts = store.data.secrets.map(s =>
        decryptWithKey(oldKey, s.encrypted)
      );

      // 2️⃣ Generate & write new key
      const newKey = crypto.randomBytes(32);
      await vscode.workspace.fs.writeFile(
        vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE),
        newKey
      );

      // 3️⃣ Re-encrypt secrets
      store.data.secrets.forEach((s, i) => {
        s.encrypted = encryptWithKey(newKey, plaintexts[i]);
      });

      // 4️⃣ Save store
      await vscode.workspace.fs.writeFile(
        store.uri,
        Buffer.from(JSON.stringify(store.data, null, 2))
      );

      vscode.window.showInformationMessage(
        "♻️ Project key rotated successfully"
      );
    })
  );
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


function openManageSecrets(ws) {
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
      length: s.encrypted?.data
        ? Math.floor(s.encrypted.data.length / 2)
        : 8
    });
  }

  return result;
}


  panel.webview.onDidReceiveMessage(async msg => {
    const store = await loadSecretFile(ws);
    const key = await getProjectKey(ws);

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

      await vscode.workspace.fs.writeFile(
        store.uri,
        Buffer.from(JSON.stringify(store.data, null, 2))
      );
    }

    // ─────────────────────────────
    // 🔁 TOGGLE ENABLE / DISABLE
    // ─────────────────────────────
    if (msg.type === "toggle") {
      const s = store.data.secrets.find(x => x.id === msg.id);
      if (!s) return;

      const fileUri = vscode.Uri.joinPath(ws.uri, s.file);
      const lines = (await vscode.workspace.fs.readFile(fileUri))
        .toString()
        .split("\n");

      const target = `resolveSecret("${s.placeholder}")`;

      // ───────── DISABLE ─────────
      if (!s.disabled) {
        const foundIndex = lines.findIndex(line =>
          line.includes(target)
        );

        if (foundIndex === -1) {
          vscode.window.showErrorMessage(
            `Cannot disable: placeholder not found in ${s.file}`
          );
          return;
        }

        const plaintext = decryptWithKey(key, s.encrypted);

        lines[foundIndex] = lines[foundIndex].replace(
          target,
          `"${plaintext}"`
        );

        s.disabled = true;
      }

      // ───────── ENABLE ─────────
      else {
        const plainIndex = lines.findIndex(line =>
          line.includes(`"${decryptWithKey(key, s.encrypted)}"`)
        );

        if (plainIndex === -1) {
          vscode.window.showErrorMessage(
            `Cannot enable: plaintext not found in ${s.file}`
          );
          return;
        }

        const match = lines[plainIndex].match(/["']([^"']+)["']/);
        if (!match) {
          vscode.window.showErrorMessage(
            `Cannot enable: plaintext parse failed in ${s.file}`
          );
          return;
        }

        const plaintext = match[1];
        s.encrypted = encryptWithKey(key, plaintext);

        lines[plainIndex] = lines[plainIndex].replace(
          `"${plaintext}"`,
          `resolveSecret("${s.placeholder}")`
        );

        s.disabled = false;
      }

      // ✍️ Write source file
      await vscode.workspace.fs.writeFile(
        fileUri,
        Buffer.from(lines.join("\n"))
      );

      // 💾 Save store
      await vscode.workspace.fs.writeFile(
        store.uri,
        Buffer.from(JSON.stringify(store.data, null, 2))
      );

      // 🔁 Re-render UI (same pipeline as load)
      const secretsForUI = await buildSecretsForUI(ws, store);

      panel.webview.postMessage({
        type: "render",
        secrets: secretsForUI
      });
    }
  });
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



// async function handleWorkspaceOpen() {
//   const ws = vscode.workspace.workspaceFolders?.[0];
//   if (!ws) return;

//   // 1️⃣ Already protected → do nothing
//   try {
//     await vscode.workspace.fs.readFile(
//       vscode.Uri.joinPath(ws.uri, ".ai-secret-guard.json")
//     );
//     return;
//   } catch {}

//   // 2️⃣ Light scan for possible secrets
//   const files = await vscode.workspace.findFiles(
//     "**/*.{js,ts,env,json}",
//     "**/node_modules/**",
//     10 // limit for speed
//   );

//   let suspicious = false;

//   for (const file of files) {
//     try {
//       const text = (await vscode.workspace.fs.readFile(file)).toString();
//       if (
//         /sk_live_|sk_test_|AIzaSy|AKIA|SECRET|API_KEY/i.test(text)
//       ) {
//         suspicious = true;
//         break;
//       }
//     } catch {}
//   }

//   if (!suspicious) return;

//   openOnOpenWarning(ws);
// }


async function handleWorkspaceOpen(context) {

const reverted = context.workspaceState.get("shielder.reverted", false);
if (reverted) return;


  const ws = vscode.workspace.workspaceFolders?.[0];
  if (!ws) return;

  const config = vscode.workspace.getConfiguration("shielder");
  const autoProtect = config.get("autoProtectOnOpen", false);
// const alreadyShown = context.workspaceState.get("shielder.warningShown", false);

const alreadyShown = context.workspaceState.get(
  "shielder.warningShown",
  false
);


  // ─────────────────────────────
  // 1️⃣ AUTO PROTECT (OPT-IN)
  // ─────────────────────────────
  if (autoProtect) {
    try {
      // Already protected → nothing to do
      await vscode.workspace.fs.readFile(
        vscode.Uri.joinPath(ws.uri, ".ai-secret-guard.json")
      );
      return;
    } catch {
      // Not protected → auto scan silently
      vscode.commands.executeCommand("shielder.scan");
      return;
    }
  }

  // ─────────────────────────────
  // 2️⃣ DEFAULT MODE → WARNING FLOW
  // ─────────────────────────────

  // Already protected → do nothing
  try {
    await vscode.workspace.fs.readFile(
      vscode.Uri.joinPath(ws.uri, ".ai-secret-guard.json")
    );
    return;
  } catch { }

  // Light scan for suspicious secrets
  const files = await vscode.workspace.findFiles(
    "**/*.{js,ts,env,json}",
    "**/node_modules/**",
    10 // limit for speed
  );

  let suspicious = false;

  for (const file of files) {
    try {
      const text = (await vscode.workspace.fs.readFile(file)).toString();
      if (
        /sk_live_|sk_test_|AIzaSy|AKIA|SECRET|API_KEY/i.test(text)
      ) {
        suspicious = true;
        break;
      }
    } catch { }
  }

 // Show warning if suspicious OR first-time open
if (!suspicious && alreadyShown) return;

openOnOpenWarning(ws);

// persist flag (workspace-level)
await context.workspaceState.update("shielder.warningShown", true);


}


function openOnOpenWarning(ws) {
  const panel = vscode.window.createWebviewPanel(
    "shielderOnOpenWarning",
    "Shielder — Security Warning",
    vscode.ViewColumn.Active,
    { enableScripts: true }
  );

  panel.webview.html = getOnOpenWarningHTML();

  panel.webview.onDidReceiveMessage(async msg => {

    if (msg.type === "protect") {
      panel.dispose();
      vscode.commands.executeCommand("shielder.scan");
      return;
    }

    if (msg.type === "protect-always") {
      const config = vscode.workspace.getConfiguration("shielder");

      await config.update(
        "autoProtectOnOpen",
        true,
        vscode.ConfigurationTarget.Workspace
      );

      panel.dispose();
      vscode.commands.executeCommand("shielder.scan");
      return;
    }

    if (msg.type === "ignore") {
      panel.dispose();
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

  .primary-outline {
    background: rgba(255,255,255,0.06);
    color: var(--vscode-editor-foreground);
    border: 1px solid var(--vscode-editorGroup-border);
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
        <h2>Shielder AI Warning</h2>
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
      <button class="secondary" onclick="ignore()">Ignore</button>
      <button class="primary-outline" onclick="protectAlways()">
        Protect & Always Enable
      </button>
      <button class="primary" onclick="protect()">Protect Now</button>
    </div>
  </div>

<script>
  const vscode = acquireVsCodeApi();
  function protect() {
    vscode.postMessage({ type: "protect" });
  }
  function protectAlways() {
    vscode.postMessage({ type: "protect-always" });
  }
  function ignore() {
    vscode.postMessage({ type: "ignore" });
  }
</script>
</body>
</html>`;
}

/*

  Revert Project logic

*/

async function revertProject(context, ws) {
  const storeUri = vscode.Uri.joinPath(ws.uri, SECRET_FILE);
  const keyUri = vscode.Uri.joinPath(ws.uri, PROJECT_KEY_FILE);

  let store;

  // 1️⃣ Load existing secret store (DO NOT auto-create)
  try {
    const raw = await vscode.workspace.fs.readFile(storeUri);
    store = JSON.parse(raw.toString());
  } catch {
    vscode.window.showWarningMessage(
      "No protected secrets found to revert."
    );
    return;
  }

  const key = await getProjectKey(ws);

  // 2️⃣ Restore secrets back into source files
  for (const s of store.secrets) {
    const fileUri = vscode.Uri.joinPath(ws.uri, s.file);
    let content = (await vscode.workspace.fs.readFile(fileUri)).toString();

    const plaintext = decryptWithKey(key, s.encrypted);

    // resolveSecret("PLACEHOLDER") → "plaintext"
    content = content.replace(
      new RegExp(`resolveSecret\\(["']${s.placeholder}["']\\)`, "g"),
      `"${plaintext}"`
    );

    // remove runtime import if present
    content = content.replace(
      /import\s+\{\s*resolveSecret\s*\}\s+from\s+["']@shielder\/runtime["'];?\n?/g,
      ""
    );

    await vscode.workspace.fs.writeFile(
      fileUri,
      Buffer.from(content)
    );
  }

  // 3️⃣ Mark internal deletes (CRITICAL)
  markInternalOp(keyUri);
  markInternalOp(storeUri);

  try {
    await vscode.workspace.fs.delete(keyUri);
  } catch {}

  try {
    await vscode.workspace.fs.delete(storeUri);
  } catch {}

  // 4️⃣ Unmark after delete
  unmarkInternalOp(keyUri);
  unmarkInternalOp(storeUri);

  // 5️⃣ Remember that user explicitly reverted this project
  await context.workspaceState.update("shielder.reverted", true);

  // 6️⃣ Friendly confirmation
  vscode.window.showInformationMessage(
    "Shielder protection removed. Secrets restored to source code.",
    "Re-Protect"
  ).then(choice => {
    if (choice === "Re-Protect") {
      vscode.commands.executeCommand("shielder.scan");
    }
  });
}



function openRevertConfirm(context, ws) {
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
      await revertProject(context, ws);
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


function openNotProtectedWebview(ws) {
  const panel = vscode.window.createWebviewPanel(
    "shielderNotProtected",
    "Shielder — Project Not Protected",
    vscode.ViewColumn.Active,
    { enableScripts: true }
  );

  panel.webview.html = getNotProtectedHTML();

  panel.webview.onDidReceiveMessage(msg => {
    if (msg.type === "cancel") {
      panel.dispose();
      return;
    }

    if (msg.type === "protect") {
      panel.dispose();
      vscode.commands.executeCommand("shielder.scan");
    }
  });
}


function getNotProtectedHTML() {
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

 .danger {
    background: #d16969;
    color: white;
    box-shadow: 0 6px 18px rgba(0,0,0,0.45);
  }
  .card {
    width: 520px;
    background: var(--vscode-editor-background);
    border-radius: 14px;
    padding: 26px 28px;
    box-shadow: 0 30px 80px rgba(0,0,0,0.75);
    border: 1px solid rgba(255, 193, 7, 0.35);
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

  .primary {
    background: #0e639c;
    color: white;
    box-shadow: 0 6px 18px rgba(0,0,0,0.45);
  }
</style>
</head>

<body>
  <div class="card">
    <h2>🔒 Project Not Protected</h2>

    <div class="desc">
      This project is currently not protected by Shielder.
    </div>

    <div class="note">
      To manage secrets, the project must be protected first.
    </div>

    <div class="actions">
       <button class="secondary" onclick="cancel()">Cancel</button>
      <button class="danger" onclick="protect()">Protect Now</button>
    </div>
  </div>

<script>
  const vscode = acquireVsCodeApi();

  function cancel() {
    vscode.postMessage({ type: "cancel" });
  }

  function protect() {
    vscode.postMessage({ type: "protect" });
  }
</script>
</body>
</html>`;
}

function deactivate() { }

module.exports = { activate, deactivate };
