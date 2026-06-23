package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.MenuItem
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.crypto.KeystoreHelper
import com.mythronix.keysandpassword.crypto.PinManager
import com.mythronix.keysandpassword.databinding.ActivitySettingsBinding
import com.mythronix.keysandpassword.models.VaultItem
import com.mythronix.keysandpassword.offline.OfflineAccountManager
import com.mythronix.keysandpassword.offline.OfflineVaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding

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
    }

    override fun onResume() {
        super.onResume()
        if (!VaultSession.isUnlocked()) { goToLock(); return }
        refreshUI()
    }

    private fun refreshUI() {
        val userId = VaultSession.getUserId() ?: ""
        binding.tvAccountEmail.text   = "Offline Account"
        binding.tvUserId.text         = "ID: ${userId.take(14)}…"
        binding.switchAppPin.isChecked    = PinManager.isPinEnabled(this)
        binding.switchDuressPin.isChecked = PinManager.isDuressPinEnabled(this)
        binding.tvAppVersion.text = "Secure Vault v1.0.0  •  Argon2id  •  AES-256-GCM"

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

    private fun setupClicks() {
        binding.btnLockNow.setOnClickListener { VaultSession.lock(); goToLock() }
        binding.btnResetBiometric.setOnClickListener { confirmResetBiometric() }
        binding.btnSetupFingerprint.setOnClickListener { showFingerprintOptions() }
        binding.btnChangeMasterPassword.setOnClickListener { showChangeMasterPasswordDialog() }

        // Hide Firebase-dependent buttons
        binding.btnChangeAccountPassword.visibility = android.view.View.GONE
        binding.btnViewSessions.visibility = android.view.View.GONE

        binding.switchAppPin.setOnCheckedChangeListener { _, checked ->
            if (checked) showSetPinDialog(false) else confirmDisablePin(false)
        }
        binding.btnSetPin.setOnClickListener { showSetPinDialog(false) }

        binding.switchDuressPin.setOnCheckedChangeListener { _, checked ->
            if (checked) showSetPinDialog(true) else confirmDisablePin(true)
        }
        binding.btnSetDuressPin.setOnClickListener { showSetPinDialog(true) }

        binding.btnDeleteAllData.setOnClickListener { confirmDeleteAllData() }
        binding.btnSignOut.setOnClickListener { confirmSignOut() }
    }

    // ── Fingerprint ───────────────────────────────────────────────────────────

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
                    .setTitle("Not Available")
                    .setMessage("This device does not support biometric authentication.")
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

    // ── Change Master Password ────────────────────────────────────────────────

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

                // Verify current password is correct
                val isValid = withContext(Dispatchers.IO) {
                    OfflineAccountManager.verifyPassword(this@SettingsActivity, currentPw.toCharArray())
                }
                if (!isValid) {
                    binding.progressGlobal.visibility = View.GONE
                    snack("Current password is incorrect"); return@launch
                }

                // Load current salt, derive current key, load all items
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

                // Re-encrypt all items with new key
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
                    // Update account salt/verifier in-place (preserves accountId)
                    OfflineAccountManager.updatePassword(this@SettingsActivity, newPw.toCharArray())
                    // Save re-encrypted vault items
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

    // ── PIN ───────────────────────────────────────────────────────────────────

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

    // ── Biometric Reset ───────────────────────────────────────────────────────

    private fun confirmResetBiometric() {
        val userId = VaultSession.getUserId() ?: return
        MaterialAlertDialogBuilder(this)
            .setTitle("Reset Biometric Key")
            .setMessage("You'll re-enter your master password on next unlock.")
            .setPositiveButton("Reset") { _, _ -> clearFingerprintData(userId); snack("Biometric reset") }
            .setNegativeButton("Cancel", null).show()
    }

    // ── Delete All Data ───────────────────────────────────────────────────────

    private fun confirmDeleteAllData() {
        MaterialAlertDialogBuilder(this)
            .setTitle("⚠️ Delete ALL Data")
            .setMessage("Permanently deletes your entire vault and all encrypted data. Cannot be undone.")
            .setPositiveButton("DELETE ALL") { _, _ ->
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
            .setNegativeButton("Cancel", null).show()
    }

    // ── Sign Out ──────────────────────────────────────────────────────────────

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

    // ── Helpers ───────────────────────────────────────────────────────────────

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
