package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.MenuItem
import android.view.View
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.crypto.KeystoreHelper
import com.mythronix.keysandpassword.crypto.LockoutManager
import com.mythronix.keysandpassword.crypto.PinManager
import com.mythronix.keysandpassword.databinding.ActivitySettingsBinding
import com.mythronix.keysandpassword.models.VaultItem
import com.mythronix.keysandpassword.offline.OfflineAccountManager
import com.mythronix.keysandpassword.offline.OfflineVaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding

    private var pendingExportPassword: CharArray? = null
    private var pendingImportPassword: CharArray? = null
    private var pendingImportUri: Uri? = null

    // ── SAF Launchers ────────────────────────────────────────────────────────

    private val exportFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        if (uri != null) lifecycleScope.launch { doExport(uri) }
    }

    private val importFileLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) { pendingImportUri = uri; showImportPasswordDialog() }
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (!VaultSession.isUnlocked()) { goToLock(); return }

        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "Settings"

        refreshUI()
        setupClicks()
        setupLockoutSliders()
    }

    override fun onResume() {
        super.onResume()
        if (!VaultSession.isUnlocked()) { goToLock(); return }
        refreshUI()
    }

    override fun onDestroy() {
        super.onDestroy()
        pendingExportPassword?.fill('\u0000')
        pendingImportPassword?.fill('\u0000')
        pendingExportPassword = null
        pendingImportPassword = null
    }

    // ── UI Refresh ───────────────────────────────────────────────────────────

    private fun refreshUI() {
        val userId = VaultSession.getUserId() ?: ""
        binding.tvAccountEmail.text   = "Offline Account"
        binding.tvUserId.text         = "ID: ${userId.take(14)}…"
        binding.switchAppPin.isChecked    = PinManager.isPinEnabled(this)
        binding.switchDuressPin.isChecked = PinManager.isDuressPinEnabled(this)
        binding.tvAppVersion.text = "Secure Vault v2.0.0  •  Argon2id  •  AES-256-GCM"

        // Dark mode
        val prefs = getSharedPreferences("sv_settings", MODE_PRIVATE)
        val darkMode = prefs.getBoolean("dark_mode", false)
        binding.switchDarkMode.isChecked = darkMode

        // Clipboard clear
        binding.switchClipboardClear.isChecked = prefs.getBoolean("clipboard_auto_clear", true)

        // Lockout sliders
        binding.sliderMaxAttempts.value = LockoutManager.getMaxAttempts(this).toFloat()
        binding.tvMaxAttemptsValue.text = "${LockoutManager.getMaxAttempts(this)} attempts"
        binding.sliderLockDuration.value = LockoutManager.getDurationIndex(this).toFloat()
        binding.tvLockDurationValue.text = LockoutManager.getDurationLabel(LockoutManager.getDurationIndex(this))

        // Fingerprint status
        val hasFp = if (userId.isNotEmpty())
            buildSecurePrefs().getString(LockActivity.prefWrappedKey(userId), null) != null
        else false
        val fpState = androidx.biometric.BiometricManager.from(this)
            .canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
        binding.tvFingerprintStatus.text = when {
            fpState == androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "Not available on this device"
            fpState == androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "No fingerprint enrolled in device settings"
            hasFp   -> "✅ Enabled"
            else    -> "Not set up — tap button below"
        }
        binding.btnSetupFingerprint.text = if (hasFp) "Re-register / Disable" else "Set Up Fingerprint"
    }

    // ── Click Handlers ───────────────────────────────────────────────────────

    private fun setupClicks() {
        binding.btnLockNow.setOnClickListener { VaultSession.lock(); goToLock() }
        binding.btnResetBiometric.setOnClickListener { confirmResetBiometric() }
        binding.btnSetupFingerprint.setOnClickListener { showFingerprintOptions() }
        binding.btnChangeMasterPassword.setOnClickListener { showChangeMasterPasswordDialog() }

        binding.btnChangeAccountPassword.visibility = View.GONE
        binding.btnViewSessions.visibility = View.GONE

        binding.switchAppPin.setOnCheckedChangeListener { _, checked ->
            if (checked) showSetPinDialog(false) else confirmDisablePin(false)
        }
        binding.btnSetPin.setOnClickListener { showSetPinDialog(false) }

        binding.switchDuressPin.setOnCheckedChangeListener { _, checked ->
            if (checked) showSetPinDialog(true) else confirmDisablePin(true)
        }
        binding.btnSetDuressPin.setOnClickListener { showSetPinDialog(true) }

        binding.btnDeleteAllData.setOnClickListener { showDeleteAllDataPasswordDialog() }
        binding.btnSignOut.setOnClickListener { confirmSignOut() }
        binding.btnExportData.setOnClickListener { showExportDialog() }
        binding.btnImportData.setOnClickListener { showImportDialog() }

        // Dark mode
        binding.switchDarkMode.setOnCheckedChangeListener { _, checked ->
            val p = getSharedPreferences("sv_settings", MODE_PRIVATE).edit()
            p.putBoolean("dark_mode", checked).apply()
            if (checked) AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
            else AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
        }

        // Clipboard
        binding.switchClipboardClear.setOnCheckedChangeListener { _, checked ->
            getSharedPreferences("sv_settings", MODE_PRIVATE).edit()
                .putBoolean("clipboard_auto_clear", checked).apply()
            snack(if (checked) "Clipboard auto-clear enabled" else "Clipboard auto-clear disabled")
        }
    }

    // ── Lockout Sliders ──────────────────────────────────────────────────────

    private fun setupLockoutSliders() {
        binding.sliderMaxAttempts.addOnChangeListener { _, value, _ ->
            val attempts = value.toInt()
            LockoutManager.setMaxAttempts(this, attempts)
            binding.tvMaxAttemptsValue.text = "$attempts attempts"
        }

        binding.sliderLockDuration.addOnChangeListener { _, value, _ ->
            val idx = value.toInt()
            LockoutManager.setDurationIndex(this, idx)
            binding.tvLockDurationValue.text = LockoutManager.getDurationLabel(idx)
        }
    }

    // ── Fingerprint (unchanged from before) ──────────────────────────────────

    private fun showFingerprintOptions() {
        val key    = VaultSession.getKey() ?: run { snack("Vault locked"); return }
        val userId = VaultSession.getUserId() ?: return
        val prefs  = buildSecurePrefs()
        val hasFp  = prefs.getString(LockActivity.prefWrappedKey(userId), null) != null

        val bm = androidx.biometric.BiometricManager.from(this)
        val state = bm.canAuthenticate(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)

        when (state) {
            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                MaterialAlertDialogBuilder(this)
                    .setTitle("Not Available").setMessage("This device does not support biometric authentication.")
                    .setPositiveButton("OK", null).show()
            }
            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                MaterialAlertDialogBuilder(this)
                    .setTitle("No Fingerprint Enrolled")
                    .setMessage("Your device supports fingerprint but none is enrolled.\n\nGo to phone Settings → Biometrics to add one, then return here.")
                    .setPositiveButton("Open Settings") { _, _ ->
                        startActivity(android.content.Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
                    }
                    .setNegativeButton("Cancel", null).show()
            }
            else -> {
                if (hasFp) {
                    MaterialAlertDialogBuilder(this)
                        .setTitle("Fingerprint Unlock  ✅")
                        .setMessage("Fingerprint unlock is currently enabled.")
                        .setPositiveButton("Re-register") { _, _ ->
                            clearFingerprintData(userId); doFingerprintSetup(key, userId)
                        }
                        .setNegativeButton("Disable") { _, _ ->
                            clearFingerprintData(userId); snack("Fingerprint unlock disabled"); refreshUI()
                        }
                        .setNeutralButton("Cancel", null).show()
                } else {
                    MaterialAlertDialogBuilder(this)
                        .setTitle("Enable Fingerprint Unlock?")
                        .setMessage("Register your fingerprint for faster vault access.")
                        .setPositiveButton("Enable") { _, _ -> doFingerprintSetup(key, userId) }
                        .setNegativeButton("Cancel", null).show()
                }
            }
        }
    }

    private fun doFingerprintSetup(key: javax.crypto.SecretKey, userId: String) {
        val prefs = buildSecurePrefs()
        try {
            KeystoreHelper.deleteWrappingKey(userId)
            KeystoreHelper.generateWrappingKey(userId)
            val encCipher = KeystoreHelper.getEncryptCipherOrNull(userId)
            if (encCipher == null) { snack("Fingerprint hardware unavailable"); return }

            val prompt = androidx.biometric.BiometricPrompt(
                this, androidx.core.content.ContextCompat.getMainExecutor(this),
                object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                        r.cryptoObject?.cipher?.let { c ->
                            val (wrapped, iv) = KeystoreHelper.wrapKey(c, key)
                            prefs.edit()
                                .putString(LockActivity.prefWrappedKey(userId), wrapped)
                                .putString(LockActivity.prefWrappedIv(userId), iv).apply()
                        }
                        snack("✅ Fingerprint unlock enabled!"); refreshUI()
                    }
                    override fun onAuthenticationError(code: Int, s: CharSequence) {
                        if (code != androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED &&
                            code != androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON)
                            snack("Fingerprint error: $s")
                    }
                    override fun onAuthenticationFailed() = snack("Not recognised — try again")
                })

            val info = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                .setTitle("Register Fingerprint")
                .setSubtitle("Touch sensor to register")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info, androidx.biometric.BiometricPrompt.CryptoObject(encCipher))
        } catch (e: Exception) { snack("Setup failed: ${e.message}") }
    }

    private fun clearFingerprintData(userId: String) {
        KeystoreHelper.deleteWrappingKey(userId)
        buildSecurePrefs().edit()
            .remove(LockActivity.prefWrappedKey(userId))
            .remove(LockActivity.prefWrappedIv(userId)).apply()
    }

    // ── Change Master Password ───────────────────────────────────────────────

    private fun showChangeMasterPasswordDialog() {
        val curField  = buildPasswordField("Current master password")
        val newField  = buildPasswordField("New master password (min 8 chars)")
        val confField = buildPasswordField("Confirm new master password")

        MaterialAlertDialogBuilder(this)
            .setTitle("Change Master Password")
            .setMessage("All vault items will be re-encrypted.")
            .setView(vstack(curField.first, newField.first, confField.first))
            .setPositiveButton("Change") { _, _ ->
                val cur = curField.second.text.toString()
                val new = newField.second.text.toString()
                val con = confField.second.text.toString()
                if (cur.isEmpty() || new.isEmpty()) { snack("Fill all fields"); return@setPositiveButton }
                if (new != con) { snack("Passwords don't match"); return@setPositiveButton }
                if (new.length < 8) { snack("Min 8 characters"); return@setPositiveButton }
                doChangeMasterPassword(cur, new)
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun doChangeMasterPassword(currentPw: String, newPw: String) {
        binding.progressGlobal.visibility = View.VISIBLE
        lifecycleScope.launch {
            try {
                val userId = VaultSession.getUserId() ?: throw Exception("Not logged in")

                val isValid = withContext(Dispatchers.IO) {
                    OfflineAccountManager.verifyPassword(this@SettingsActivity, currentPw.toCharArray())
                }
                if (!isValid) {
                    binding.progressGlobal.visibility = View.GONE
                    snack("Current password is incorrect"); return@launch
                }

                val saltB64 = withContext(Dispatchers.IO) {
                    OfflineAccountManager.getSaltB64(this@SettingsActivity)
                } ?: throw Exception("Salt not found")

                val currentKey = CryptoManager.deriveKey(
                    currentPw.toCharArray(), CryptoManager.saltFromBase64(saltB64)
                )

                val items = withContext(Dispatchers.IO) {
                    OfflineVaultStore.listItems(this@SettingsActivity, userId)
                }

                val newSalt = CryptoManager.generateSalt()
                val newKey = CryptoManager.deriveKey(newPw.toCharArray(), newSalt)

                val reEncrypted = withContext(Dispatchers.Default) {
                    items.map { item ->
                        val plain = CryptoManager.decrypt(
                            item.encryptedData, item.iv, currentKey, userId, item.id, item.type
                        )
                        val (enc, iv) = CryptoManager.encrypt(plain, newKey, userId, item.id, item.type)
                        item.copy(encryptedData = enc, iv = iv, hmac = "", aadVersion = VaultItem.AAD_VERSION)
                    }
                }

                withContext(Dispatchers.IO) {
                    OfflineAccountManager.updatePassword(this@SettingsActivity, newPw.toCharArray())
                    OfflineVaultStore.replaceAllItems(this@SettingsActivity, userId, reEncrypted)
                }

                VaultSession.setKey(newKey, userId)
                clearFingerprintData(userId)

                binding.progressGlobal.visibility = View.GONE
                snack("✅ Master password changed. Re-enroll fingerprint from Settings.")
            } catch (e: Exception) {
                binding.progressGlobal.visibility = View.GONE
                snack("Failed: ${e.message}")
            }
        }
    }

    // ── PIN ──────────────────────────────────────────────────────────────────

    private fun showSetPinDialog(isDuress: Boolean) {
        val title    = if (isDuress) "Set Duress PIN" else "Set App PIN"
        val pinField = buildPinField("New PIN (4-8 digits)")
        val confField = buildPinField("Confirm PIN")

        MaterialAlertDialogBuilder(this).setTitle(title)
            .setView(vstack(pinField.first, confField.first))
            .setPositiveButton("Set PIN") { _, _ ->
                val pin = pinField.second.text.toString()
                val con = confField.second.text.toString()
                if (pin.length < 4) { snack("PIN must be 4-8 digits"); return@setPositiveButton }
                if (pin != con) { snack("PINs don't match"); return@setPositiveButton }
                if (isDuress) {
                    if (PinManager.isPinEnabled(this) && PinManager.verifyPin(this, pin)) {
                        snack("Duress PIN cannot be same as App PIN"); return@setPositiveButton
                    }
                    PinManager.setDuressPin(this, pin); snack("✅ Duress PIN set")
                } else {
                    if (PinManager.isDuressPinEnabled(this) && PinManager.verifyDuressPin(this, pin)) {
                        snack("App PIN cannot be same as Duress PIN"); return@setPositiveButton
                    }
                    val key = VaultSession.getKey()
                    if (key == null) { snack("Vault locked — cannot set PIN"); return@setPositiveButton }
                    PinManager.setPin(this, pin, key); snack("✅ App PIN set")
                }
                refreshUI()
            }
            .setNegativeButton("Cancel") { _, _ -> refreshUI() }.show()
    }

    private fun confirmDisablePin(isDuress: Boolean) {
        val label = if (isDuress) "Duress PIN" else "App PIN"
        MaterialAlertDialogBuilder(this).setTitle("Disable $label?")
            .setPositiveButton("Disable") { _, _ ->
                if (isDuress) PinManager.disableDuressPin(this) else PinManager.disablePin(this)
                snack("$label disabled"); refreshUI()
            }
            .setNegativeButton("Cancel") { _, _ -> refreshUI() }.show()
    }

    // ── Biometric Reset ──────────────────────────────────────────────────────

    private fun confirmResetBiometric() {
        val userId = VaultSession.getUserId() ?: return
        MaterialAlertDialogBuilder(this)
            .setTitle("Reset Biometric Key")
            .setMessage("You'll re-enter your master password on next unlock.")
            .setPositiveButton("Reset") { _, _ -> clearFingerprintData(userId); snack("Biometric reset") }
            .setNegativeButton("Cancel", null).show()
    }

    // ── Delete All Data (Password Protected) ─────────────────────────────────

    private fun showDeleteAllDataPasswordDialog() {
        val pwField = buildPasswordField("Enter master password to confirm")
        MaterialAlertDialogBuilder(this)
            .setTitle("⚠️ Delete ALL Data")
            .setMessage("Enter your master password to confirm. This permanently deletes your entire vault. Cannot be undone.")
            .setView(pwField.first)
            .setPositiveButton("DELETE ALL") { _, _ ->
                val pw = pwField.second.text.toString()
                if (pw.isEmpty()) { snack("Enter your password"); return@setPositiveButton }
                lifecycleScope.launch {
                    val valid = withContext(Dispatchers.IO) {
                        OfflineAccountManager.verifyPassword(this@SettingsActivity, pw.toCharArray())
                    }
                    if (!valid) { snack("Incorrect password"); return@launch }
                    confirmDeleteAllData()
                }
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun confirmDeleteAllData() {
        lifecycleScope.launch {
            binding.progressGlobal.visibility = View.VISIBLE
            try {
                val userId = VaultSession.getUserId() ?: return@launch
                withContext(Dispatchers.IO) {
                    OfflineVaultStore.deleteAllUserData(this@SettingsActivity, userId)
                    OfflineAccountManager.deleteAccount(this@SettingsActivity)
                }
                KeystoreHelper.deleteAllWrappingKeys()
                VaultSession.clearAll()
                PinManager.clearAll(this@SettingsActivity)
                buildSecurePrefs().edit().clear().apply()
                binding.progressGlobal.visibility = View.GONE
                startActivity(Intent(this@SettingsActivity, AuthActivity::class.java)); finishAffinity()
            } catch (e: Exception) {
                binding.progressGlobal.visibility = View.GONE
                snack("Failed: ${e.message}")
            }
        }
    }

    // ── Export ───────────────────────────────────────────────────────────────

    private fun showExportDialog() {
        val pwField = buildPasswordField("Enter master password")
        MaterialAlertDialogBuilder(this)
            .setTitle("Export Data (Backup)")
            .setMessage("Your vault data will be encrypted and saved as a backup file (.svbk).")
            .setView(pwField.first)
            .setPositiveButton("Export") { _, _ ->
                val pw = pwField.second.text.toString()
                if (pw.isEmpty()) { snack("Enter your password"); return@setPositiveButton }
                lifecycleScope.launch {
                    val valid = withContext(Dispatchers.IO) {
                        OfflineAccountManager.verifyPassword(this@SettingsActivity, pw.toCharArray())
                    }
                    if (!valid) { snack("Incorrect password"); return@launch }
                    pendingExportPassword = pw.toCharArray()
                    exportFileLauncher.launch("SecureVault-backup.svbk")
                }
            }
            .setNegativeButton("Cancel", null).show()
    }

    private suspend fun doExport(uri: Uri) {
        val pw = pendingExportPassword ?: run { snack("Password expired, try again"); return }
        pendingExportPassword = null
        binding.progressGlobal.visibility = View.VISIBLE
        try {
            val userId = VaultSession.getUserId() ?: throw Exception("Not logged in")
            val saltB64 = withContext(Dispatchers.IO) {
                OfflineAccountManager.getSaltB64(this@SettingsActivity)
            } ?: throw Exception("Account salt not found")

            val itemsJson = withContext(Dispatchers.IO) {
                OfflineVaultStore.exportItemsAsJson(this@SettingsActivity, userId)
            }

            val exportObj = JSONObject()
            exportObj.put("exportVersion", 1)
            exportObj.put("saltB64", saltB64)
            exportObj.put("createdAt", System.currentTimeMillis())
            exportObj.put("items", JSONArray(itemsJson))
            val exportJson = exportObj.toString(2)

            val salt = CryptoManager.saltFromBase64(saltB64)
            val exportKey = CryptoManager.deriveKey(pw, salt)
            pw.fill('\u0000')
            val (encryptedB64, ivB64) = CryptoManager.encrypt(exportJson, exportKey)

            val fileContent = "$saltB64\n$ivB64\n$encryptedB64"
            withContext(Dispatchers.IO) {
                contentResolver.openOutputStream(uri)?.use { it.write(fileContent.toByteArray(Charsets.UTF_8)) }
                    ?: throw Exception("Cannot write to file")
            }

            binding.progressGlobal.visibility = View.GONE
            snack("✅ Backup exported successfully!")
        } catch (e: Exception) {
            binding.progressGlobal.visibility = View.GONE
            pw.fill('\u0000')
            snack("Export failed: ${e.message}")
        }
    }

    // ── Import ───────────────────────────────────────────────────────────────

    private fun showImportDialog() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Import Data (Restore)")
            .setMessage("Select a backup file (.svbk) to restore your vault data. Items with same ID will be overwritten.")
            .setPositiveButton("Select File") { _, _ ->
                importFileLauncher.launch(arrayOf("*/*"))
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun showImportPasswordDialog() {
        val pwField = buildPasswordField("Enter the backup file's password")
        MaterialAlertDialogBuilder(this)
            .setTitle("Decrypt Backup")
            .setMessage("Enter the master password that was used when creating this backup.")
            .setView(pwField.first)
            .setPositiveButton("Restore") { _, _ ->
                val pw = pwField.second.text.toString()
                if (pw.isEmpty()) { snack("Enter your password"); return@setPositiveButton }
                pendingImportPassword = pw.toCharArray()
                val uri = pendingImportUri
                if (uri != null) lifecycleScope.launch { doImport(uri) }
            }
            .setNegativeButton("Cancel") { _, _ ->
                pendingImportPassword = null; pendingImportUri = null
            }.show()
    }

    private suspend fun doImport(uri: Uri) {
        val pw = pendingImportPassword ?: run { snack("Password expired"); return }
        val currentUserId = VaultSession.getUserId() ?: run { snack("Not logged in"); return }
        pendingImportPassword = null; pendingImportUri = null

        binding.progressGlobal.visibility = View.VISIBLE
        try {
            val fileContent = withContext(Dispatchers.IO) {
                contentResolver.openInputStream(uri)?.use { it.bufferedReader().readText() }
                    ?: throw Exception("Cannot read file")
            }

            val parts = fileContent.trim().split("\n", limit = 3)
            if (parts.size < 3) throw Exception("Invalid backup file format")
            val saltB64 = parts[0].trim(); val ivB64 = parts[1].trim(); val encryptedB64 = parts[2].trim()
            if (saltB64.isBlank() || ivB64.isBlank() || encryptedB64.isBlank())
                throw Exception("Corrupted backup file")

            val salt = CryptoManager.saltFromBase64(saltB64)
            val exportKey = CryptoManager.deriveKey(pw, salt)
            pw.fill('\u0000')

            val decryptedJson = CryptoManager.decrypt(encryptedB64, ivB64, exportKey)
            val exportObj = JSONObject(decryptedJson)
            if (exportObj.optString("saltB64", "") != saltB64)
                throw Exception("Backup file integrity check failed")

            val itemsArr = exportObj.optJSONArray("items") ?: throw Exception("No items found")
            val currentKey = VaultSession.getKey() ?: throw Exception("Vault session expired")

            var skipped = 0
            val importedItems = mutableListOf<VaultItem>()
            for (i in 0 until itemsArr.length()) {
                val obj = itemsArr.getJSONObject(i)
                val item = VaultItem(
                    id = obj.optString("id", ""),
                    type = obj.optString("type", VaultItem.TYPE_PASSWORD),
                    name = obj.optString("name", ""),
                    encryptedData = obj.optString("encryptedData", ""),
                    iv = obj.optString("iv", ""),
                    hmac = obj.optString("hmac", ""),
                    aadVersion = obj.optString("aadVersion", VaultItem.AAD_VERSION),
                    createdAt = obj.optLong("createdAt", System.currentTimeMillis())
                )
                try {
                    val plaintext = CryptoManager.decrypt(item.encryptedData, item.iv, exportKey, currentUserId, item.id, item.type)
                    val (newEnc, newIv) = CryptoManager.encrypt(plaintext, currentKey, currentUserId, item.id, item.type)
                    importedItems.add(item.copy(encryptedData = newEnc, iv = newIv, hmac = "", aadVersion = VaultItem.AAD_VERSION))
                } catch (_: Exception) { skipped++ }
            }

            val existingItems = withContext(Dispatchers.IO) {
                OfflineVaultStore.listItems(this@SettingsActivity, currentUserId).toMutableList()
            }
            for (newItem in importedItems) {
                val idx = existingItems.indexOfFirst { it.id == newItem.id }
                if (idx >= 0) existingItems[idx] = newItem else existingItems.add(newItem)
            }
            withContext(Dispatchers.IO) {
                OfflineVaultStore.replaceAllItems(this@SettingsActivity, currentUserId, existingItems)
            }

            binding.progressGlobal.visibility = View.GONE
            val msg = "✅ Restored ${importedItems.size} items${if (skipped > 0) " ($skipped skipped)" else ""}!"
            snack(msg)
        } catch (e: Exception) {
            binding.progressGlobal.visibility = View.GONE
            pw.fill('\u0000')
            snack("Import failed: ${e.message}")
        }
    }

    // ── Sign Out ─────────────────────────────────────────────────────────────

    private fun confirmSignOut() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Lock Vault")
            .setMessage("Your encrypted data stays safely on your device.")
            .setPositiveButton("Lock") { _, _ ->
                KeystoreHelper.deleteAllWrappingKeys()
                VaultSession.clearAll()
                startActivity(Intent(this, LockActivity::class.java)); finishAffinity()
            }
            .setNegativeButton("Cancel", null).show()
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private fun buildPasswordField(hint: String): Pair<TextInputLayout, TextInputEditText> {
        val et = TextInputEditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val til = TextInputLayout(this, null, com.google.android.material.R.attr.textInputOutlinedStyle).apply {
            this.hint = hint; endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE; addView(et)
            layoutParams = android.widget.LinearLayout.LayoutParams(-1, -2).also { it.topMargin = 16 }
        }
        return Pair(til, et)
    }

    private fun buildPinField(hint: String): Pair<TextInputLayout, TextInputEditText> {
        val et = TextInputEditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }
        val til = TextInputLayout(this, null, com.google.android.material.R.attr.textInputOutlinedStyle).apply {
            this.hint = hint; endIconMode = TextInputLayout.END_ICON_PASSWORD_TOGGLE; addView(et)
            layoutParams = android.widget.LinearLayout.LayoutParams(-1, -2).also { it.topMargin = 16 }
        }
        return Pair(til, et)
    }

    private fun vstack(vararg views: android.view.View): android.widget.LinearLayout =
        android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 8, 48, 0)
            views.forEach { addView(it) }
        }

    private fun buildSecurePrefs(): android.content.SharedPreferences {
        val mk = androidx.security.crypto.MasterKey.Builder(this)
            .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM).build()
        return androidx.security.crypto.EncryptedSharedPreferences.create(this, "sv_secure_prefs", mk,
            androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }

    private fun goToLock() { startActivity(Intent(this, LockActivity::class.java)); finishAffinity() }
    private fun snack(msg: String) = Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }
}
