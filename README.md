# 🔐 Secure Vault

A production-grade Android password manager with true **End-to-End Encryption**.
Firebase never sees your plaintext data or encryption keys — ever.

---

## 🔒 Security Architecture

| Layer | Technology |
|-------|-----------|
| Key Derivation | **Argon2id** (64MB RAM, 3 passes, 4 lanes) |
| Fallback KDF | PBKDF2-HMAC-SHA512 (600,000 iterations) |
| Encryption | **AES-256-GCM** (authenticated, 12-byte IV) |
| Integrity | **HMAC-SHA256** per vault item |
| Key Storage | **Android Keystore** (hardware-backed) |
| Biometric | Hardware-backed BiometricPrompt (gates Keystore key — NOT the crypto key) |
| Transport | Firebase Firestore (only encrypted blobs stored) |

**The master password is never stored anywhere. The derived AES key lives only in RAM.**

---

## 📦 Project Structure

```
app/src/main/java/com/mythronix/keysandpassword/
├── activities/
│   ├── SplashActivity.kt      — Entry point routing
│   ├── AuthActivity.kt        — Firebase login / signup
│   ├── LockActivity.kt        — Biometric + master password unlock
│   ├── VaultActivity.kt       — Encrypted vault list
│   ├── AddEditActivity.kt     — Create / edit entries
│   └── SettingsActivity.kt    — Account + security settings
├── crypto/
│   ├── CryptoManager.kt       — Argon2id, AES-256-GCM, HMAC-SHA256
│   └── KeystoreHelper.kt      — Android Keystore key wrapping
├── firebase/
│   ├── AuthManager.kt         — Firebase Auth wrapper
│   └── FirestoreManager.kt    — Firestore CRUD (encrypted data only)
├── models/
│   └── VaultItem.kt           — Data models + JSON payload helpers
├── ui/
│   └── VaultAdapter.kt        — RecyclerView adapter
├── App.kt                     — Application class (auto-lock lifecycle)
└── VaultSession.kt            — In-memory key session manager
```

---

## 🚀 How to Run

### Prerequisites
- Android Studio Hedgehog (2023.1.1) or newer
- Android device / emulator with API 28+ (Android 9+)
- Physical device recommended for biometric testing

### Steps

```bash
# 1. Unzip and open in Android Studio
File → Open → select SecureVault/

# 2. Sync Gradle
File → Sync Project with Gradle Files

# 3. Enable Firebase services in your Firebase Console:
#    - Authentication → Email/Password → Enable
#    - Firestore Database → Create database → Standard edition
#    - Firestore → Rules → paste the rules below

# 4. Run on device
Run → Run 'app'  (Shift+F10)
```

### Firestore Security Rules (required)
```js
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/{document=**} {
      allow read, write: if request.auth != null
                         && request.auth.uid == userId;
    }
  }
}
```

---

## ⚙️ GitHub Actions — Automatic APK Build

Every push to `main` automatically builds debug and release APKs.
Artifacts are available in the **Actions** tab of your repository.

### To enable signed release APK:

1. Generate a keystore:
```bash
keytool -genkey -v -keystore my-release-key.jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias my-key-alias
```

2. Convert to Base64:
```bash
base64 -i my-release-key.jks | pbcopy   # macOS
base64 my-release-key.jks               # Linux
```

3. Add these **GitHub Secrets** (Settings → Secrets → Actions):

| Secret | Value |
|--------|-------|
| `KEYSTORE_BASE64` | Base64 of your `.jks` file |
| `KEY_ALIAS` | Your key alias |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_PASSWORD` | Key password |

### To trigger a release:
```bash
git tag v1.0.0
git push origin v1.0.0
```
This creates a GitHub Release with APKs attached automatically.

---

## 📤 GitHub Push Commands

```bash
cd SecureVault
git init
git add .
git commit -m "Initial commit - Secure Vault App"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-vault.git
git push -u origin main
```

---

## 🛡️ Security Hardening Checklist

- [x] `FLAG_SECURE` on all screens (no screenshots)
- [x] Clipboard auto-clears after 30 seconds
- [x] No sensitive data in Android logs
- [x] `allowBackup="false"` in manifest
- [x] TLS-only network traffic (`network_security_config.xml`)
- [x] HMAC-SHA256 integrity check on every vault item
- [x] Constant-time HMAC comparison (timing attack prevention)
- [x] Biometric never used as encryption key
- [x] AES key lives only in RAM (`VaultSession.kt`)
- [x] Auto-lock after 2 minutes of backgrounding
- [x] ProGuard + R8 minification + log stripping in release builds
- [x] Android Keystore hardware-backed key wrapping

---

## 📋 Firestore Data Schema

```
users/{userId}/
  └── salt: string          ← Argon2 salt (not a secret — safe to store)

users/{userId}/vault/{itemId}/
  ├── type: "password" | "token"
  ├── name: string          ← Display name (plaintext metadata)
  ├── encryptedData: string ← Base64(AES-GCM ciphertext + auth tag)
  ├── iv: string            ← Base64(12-byte GCM IV)
  ├── hmac: string          ← Base64(HMAC-SHA256 integrity tag)
  └── createdAt: long       ← Unix timestamp
```

Firebase stores **zero plaintext secrets**. Passwords and tokens exist
only in `encryptedData` which is decrypted locally after master password entry.

---

*Secure Vault v1.0 — Package: com.mythronix.keysandpassword*
