# 🛡️ ShielderX

**Protect secrets from AI vibe-coding tools — without breaking your app.**

ShielderX is a **local security boundary** for modern development workflows.  
It prevents AI coding tools (Copilot, Cursor, Windsurf, etc.) from reading **real secrets** during development, while your application continues to work normally.

> ❗ ShielderX is **not** an AI coding assistant  
> ✅ It is a **defensive security tool**

---

## 🚨 The Problem

AI coding tools scan your source code to generate suggestions.  
During this scan, sensitive data can be exposed:

- API keys  
- Tokens  
- Emails & phone numbers  
- Internal IDs  
- Company secrets  

Once exposed, secrets can:
- Be remembered by AI tools  
- Appear in logs or commits  
- Spread across teams unintentionally  

---

## ✅ The Solution

ShielderX ensures that:

- AI tools **never see real secrets**
- Secrets are **encrypted at rest**
- Your app **runs normally**
- No backend or cloud service is required (v1)

---

## 🧠 Core Concept

```
Source Code → ShielderX → AI Tools
                  ↓
           Encrypted Secret Store
```

- Secrets are replaced with placeholders
- Real values are encrypted
- Decryption happens **only at runtime**
- No plaintext secrets on disk

---

## 🔐 How ShielderX Works

### 1️⃣ Scan (IDE Time)

Run from VS Code:

```
ShielderX: Scan Project
```

What happens:
- Detects sensitive values
- Replaces them with placeholders  
  ```js
  const API_KEY = "<SECRET_ABC123>";
  ```
- Encrypts the real value
- Stores it securely

👉 AI tools only see placeholders.

---

### 2️⃣ Runtime Resolution

In your app:

```js
import { resolveSecret } from "@shielder/runtime";

const key = resolveSecret("<SECRET_ABC123>");
```

Runtime behavior:
- Decrypts **in memory only**
- Never writes plaintext to disk
- Fails loudly if a secret is missing

---

## 📁 Files Created

| File | Purpose | Commit Safe |
|---|---|---|
| `.shielder.key` | Project-specific encryption key | ❌ No |
| `.ai-secret-guard.json` | Encrypted secret store | ✅ Yes |

---

## 🔄 Managing Secrets

Run:

```
ShielderX: Manage Secrets
```

You can:
- View secrets (masked)
- Edit values safely
- Disable / re-enable protection

---

## 🧠 Threat Model

### Protects Against
- AI tools reading source code
- Accidental secret exposure
- Secrets committed to repos

### Does NOT Protect Against
- Compromised machines
- Malicious developers
- Runtime memory inspection

---

## ⚠️ Important Warnings

- Losing `.shielder.key` = permanent data loss
- Restoring plaintext allows AI to read secrets
- No secret recovery without the key

---

## 🧾 Responsibility

- Users manage their own keys
- Best-effort security only


## 📄 License

MIT License
