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
import com.google.firebase.auth.EmailAuthProvider
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.crypto.KeystoreHelper
import com.mythronix.keysandpassword.crypto.PinManager
import com.mythronix.keysandpassword.databinding.ActivitySettingsBinding
import com.mythronix.keysandpassword.firebase.AuthManager
import com.mythronix.keysandpassword.firebase.DeviceSessionManager
import com.mythronix.keysandpassword.firebase.FirestoreManager
import com.mythronix.keysandpassword.models.VaultItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
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
        val user   = AuthManager.getCurrentUser()
        val userId = user?.uid ?: ""
        binding.tvAccountEmail.text   = user?.email ?: "—"
        binding.tvUserId.text         = "UID: ${userId.take(14)}…"
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
        binding.btnChangeAccountPassword.setOnClickListener { showChangeAccountPasswordDialog() }
        binding.btnChangeMasterPassword.setOnClickListener { showChangeMasterPasswordDialog() }
        binding.btnViewSessions.setOnClickListener { showDeviceSessions() }

        binding.switchAppPin.setOnCheckedChangeListener { _, checked ->
            if (checked) showSetPinDialog(false) else confirmDisablePin(false)
        }
        binding.btnSetPin.setOnClickListener { showSetPinDialog(false) }

        binding.switchDuressPin.setOnCheckedChangeListener { _, checked ->
            if (checked) showSetPinDialog(true) else confirmDisablePin(true)
        }
        binding.btnSetDuressPin.setOnClickListener { showSetPinDialog(true) }

        binding.btnDeleteAllData.setOnClickListener { showDeleteAllDataFlow() }
        binding.btnSignOut.setOnClickListener { confirmSignOut() }
    }

    // ── Fingerprint ───────────────────────────────────────────────────────────

    private fun showFingerprintOptions() {
        val key    = VaultSession.getKey() ?: run { snack("Vault locked"); return }
        val userId = AuthManager.getCurrentUser()?.uid ?: return
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

    // ── Device Sessions (view only) ───────────────────────────────────────────

    private fun showDeviceSessions() {
        binding.progressGlobal.visibility = View.VISIBLE
        lifecycleScope.launch {
            val sessions = withContext(Dispatchers.IO) {
                runCatching { DeviceSessionManager.getSessions(this@SettingsActivity, AuthManager.currentUserId()) }
                    .getOrDefault(emptyList())
            }
            binding.progressGlobal.visibility = View.GONE

            if (sessions.isEmpty()) { snack("No session data found"); return@launch }

            val items = sessions.map { s ->
                val tag = if (s.isCurrentDevice) " ✅ (This device)" else ""
                "📱 ${s.deviceName}$tag\n${s.osVersion}\nLast seen: ${s.lastSeenFormatted()}"
            }.toTypedArray()

            MaterialAlertDialogBuilder(this@SettingsActivity)
                .setTitle("Logged-In Devices")
                .setItems(items, null)
                .setNegativeButton("Close", null)
                .show()
        }
    }

    // ── Change Account Password ───────────────────────────────────────────────

    private fun showChangeAccountPasswordDialog() {
        val curField  = buildPasswordField("Current account password")
        val newField  = buildPasswordField("New account password")
        val confField = buildPasswordField("Confirm new password")

        MaterialAlertDialogBuilder(this)
            .setTitle("Change Account Password")
            .setMessage("Requires email verification.")
            .setView(vstack(curField.first, newField.first, confField.first))
            .setPositiveButton("Send Verification") { _, _ ->
                val cur = curField.second.text.toString()
                val new = newField.second.text.toString()
                val con = confField.second.text.toString()
                if (cur.isEmpty() || new.isEmpty()) { snack("Fill all fields"); return@setPositiveButton }
                if (new != con) { snack("Passwords don't match"); return@setPositiveButton }
                if (new.length < 6) { snack("Minimum 6 characters"); return@setPositiveButton }
                changeAccountPasswordWithVerification(cur, new)
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun changeAccountPasswordWithVerification(current: String, new: String) {
        binding.progressGlobal.visibility = View.VISIBLE
        lifecycleScope.launch {
            try {
                val user  = AuthManager.getCurrentUser() ?: throw Exception("Not logged in")
                val email = user.email ?: throw Exception("No email")
                withContext(Dispatchers.IO) {
                    user.reauthenticate(EmailAuthProvider.getCredential(email, current)).await()
                    user.sendEmailVerification().await()
                }
                binding.progressGlobal.visibility = View.GONE

                MaterialAlertDialogBuilder(this@SettingsActivity)
                    .setTitle("📧 Verify Email First")
                    .setMessage("Verification sent to:\n\n$email\n\nOpen the link, then tap Confirm.")
                    .setPositiveButton("Confirmed — Apply") { _, _ ->
                        lifecycleScope.launch {
                            binding.progressGlobal.visibility = View.VISIBLE
                            try {
                                withContext(Dispatchers.IO) { user.reload().await() }
                                if (!user.isEmailVerified) {
                                    binding.progressGlobal.visibility = View.GONE
                                    snack("Not verified yet — check inbox")
                                    return@launch
                                }
                                withContext(Dispatchers.IO) { user.updatePassword(new).await() }
                                binding.progressGlobal.visibility = View.GONE
                                snack("✅ Account password changed")
                            } catch (e: Exception) {
                                binding.progressGlobal.visibility = View.GONE
                                snack("Failed: ${e.message}")
                            }
                        }
                    }
                    .setNegativeButton("Cancel", null).setCancelable(false).show()
            } catch (e: Exception) {
                binding.progressGlobal.visibility = View.GONE
                snack("Failed: ${friendlyAuthError(e.message)}")
            }
        }
    }

    // ── Change Master Password ────────────────────────────────────────────────

    private fun showChangeMasterPasswordDialog() {
        val curField  = buildPasswordField("Current master password")
        val newField  = buildPasswordField("New master password (min 8 chars)")
        val confField = buildPasswordField("Confirm new master password")

        MaterialAlertDialogBuilder(this)
            .setTitle("Change Master Password")
            .setMessage("All vault items will be re-encrypted. Email verification required.")
            .setView(vstack(curField.first, newField.first, confField.first))
            .setPositiveButton("Verify & Change") { _, _ ->
                val cur = curField.second.text.toString()
                val new = newField.second.text.toString()
                val con = confField.second.text.toString()
                if (cur.isEmpty() || new.isEmpty()) { snack("Fill all fields"); return@setPositiveButton }
                if (new != con) { snack("Passwords don't match"); return@setPositiveButton }
                if (new.length < 8) { snack("Min 8 characters"); return@setPositiveButton }
                changeMasterPasswordWithVerification(cur, new)
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun changeMasterPasswordWithVerification(currentPw: String, newPw: String) {
        binding.progressGlobal.visibility = View.VISIBLE
        lifecycleScope.launch {
            try {
                val user = AuthManager.getCurrentUser() ?: throw Exception("Not logged in")
                withContext(Dispatchers.IO) { user.sendEmailVerification().await() }
                binding.progressGlobal.visibility = View.GONE

                MaterialAlertDialogBuilder(this@SettingsActivity)
                    .setTitle("📧 Verify Before Changing")
                    .setMessage("Verification sent to:\n\n${user.email}\n\nOpen the link, then tap Confirm.")
                    .setPositiveButton("Confirmed — Re-encrypt") { _, _ ->
                        lifecycleScope.launch { doChangeMasterPassword(user, currentPw, newPw) }
                    }
                    .setNegativeButton("Cancel", null).setCancelable(false).show()
            } catch (e: Exception) {
                binding.progressGlobal.visibility = View.GONE
                snack("Failed: ${e.message}")
            }
        }
    }

    private suspend fun doChangeMasterPassword(
        user: com.google.firebase.auth.FirebaseUser, currentPw: String, newPw: String
    ) {
        binding.progressGlobal.visibility = View.VISIBLE
        try {
            withContext(Dispatchers.IO) { user.reload().await() }
            if (!user.isEmailVerified) {
                binding.progressGlobal.visibility = View.GONE
                snack("Email not verified yet"); return
            }

            val userId = user.uid
            val (currentKey, items, newSalt, newKey) = withContext(Dispatchers.IO) {
                val saltB64 = FirestoreManager.getSalt(userId) ?: throw Exception("Salt not found")
                val cKey    = CryptoManager.deriveKey(currentPw.toCharArray(), CryptoManager.saltFromBase64(saltB64))
                val items   = FirestoreManager.getVaultItems(userId)
                val nSalt   = CryptoManager.generateSalt()
                val nKey    = CryptoManager.deriveKey(newPw.toCharArray(), nSalt)
                quadruple(cKey, items, nSalt, nKey)
            }

            val reEncrypted = withContext(Dispatchers.Default) {
                items.map { item ->
                    val plain = if (item.isLegacy) CryptoManager.decryptLegacy(item.encryptedData, item.iv, currentKey)
                                else CryptoManager.decrypt(item.encryptedData, item.iv, currentKey, userId, item.id, item.type)
                    val (enc, iv) = CryptoManager.encrypt(plain, newKey, userId, item.id, item.type)
                    item.copy(encryptedData = enc, iv = iv, hmac = "", aadVersion = VaultItem.AAD_VERSION)
                }
            }

            withContext(Dispatchers.IO) {
                FirestoreManager.saveSalt(userId, CryptoManager.saltToBase64(newSalt))
                FirestoreManager.replaceAllVaultItems(userId, reEncrypted)
                runCatching {
                    val vSalt = CryptoManager.generateVerifierSalt()
                    val vHash = CryptoManager.computeVerifier(newPw.toCharArray(), vSalt)
                    FirestoreManager.saveVerifier(userId, vHash, CryptoManager.verifierSaltToBase64(vSalt))
                }
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


    private data class Quadruple<A,B,C,D>(val a: A, val b: B, val c: C, val d: D)
    private fun <A,B,C,D> quadruple(a: A, b: B, c: C, d: D) = Quadruple(a,b,c,d)
    private operator fun <A,B,C,D> Quadruple<A,B,C,D>.component1() = a
    private operator fun <A,B,C,D> Quadruple<A,B,C,D>.component2() = b
    private operator fun <A,B,C,D> Quadruple<A,B,C,D>.component3() = c
    private operator fun <A,B,C,D> Quadruple<A,B,C,D>.component4() = d

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
        val uid = AuthManager.getCurrentUser()?.uid ?: return
        MaterialAlertDialogBuilder(this)
            .setTitle("Reset Biometric Key")
            .setMessage("You'll re-enter your master password on next unlock.")
            .setPositiveButton("Reset") { _, _ -> clearFingerprintData(uid); snack("Biometric reset") }
            .setNegativeButton("Cancel", null).show()
    }

    // ── Delete All Data ───────────────────────────────────────────────────────

    private fun showDeleteAllDataFlow() {
        val pwField = buildPasswordField("Your account password")
        MaterialAlertDialogBuilder(this)
            .setTitle("⚠️ Delete ALL Data")
            .setMessage("Permanently deletes your entire vault. Cannot be undone.\nRequires password + email verification.")
            .setView(vstack(pwField.first))
            .setPositiveButton("Send Verification Email") { _, _ ->
                val pw = pwField.second.text.toString()
                if (pw.isEmpty()) { snack("Password required"); return@setPositiveButton }
                sendDeleteVerification(pw)
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun sendDeleteVerification(accountPassword: String) {
        binding.progressGlobal.visibility = View.VISIBLE
        lifecycleScope.launch {
            try {
                val user  = AuthManager.getCurrentUser() ?: throw Exception("Not logged in")
                val email = user.email ?: throw Exception("No email")
                withContext(Dispatchers.IO) {
                    user.reauthenticate(EmailAuthProvider.getCredential(email, accountPassword)).await()
                    user.sendEmailVerification().await()
                }
                binding.progressGlobal.visibility = View.GONE

                MaterialAlertDialogBuilder(this@SettingsActivity)
                    .setTitle("📧 Confirm Deletion")
                    .setMessage("Verification sent to:\n\n$email\n\n⚠️ ALL vault data will be permanently deleted.")
                    .setPositiveButton("✓ Verified — DELETE ALL") { _, _ ->
                        lifecycleScope.launch {
                            binding.progressGlobal.visibility = View.VISIBLE
                            try {
                                withContext(Dispatchers.IO) { user.reload().await() }
                                if (!user.isEmailVerified) {
                                    binding.progressGlobal.visibility = View.GONE
                                    snack("Not verified yet — check inbox"); return@launch
                                }
                                deleteAllUserData(user.uid)
                            } catch (e: Exception) {
                                binding.progressGlobal.visibility = View.GONE
                                snack("Failed: ${e.message}")
                            }
                        }
                    }
                    .setNegativeButton("Cancel", null).setCancelable(false).show()
            } catch (e: Exception) {
                binding.progressGlobal.visibility = View.GONE
                snack("Failed: ${friendlyAuthError(e.message)}")
            }
        }
    }

    private suspend fun deleteAllUserData(userId: String) {
        try {
            withContext(Dispatchers.IO) { FirestoreManager.deleteAllUserData(userId) }
            KeystoreHelper.deleteAllWrappingKeys()
            VaultSession.clearAll()
            PinManager.clearAll(this)
            buildSecurePrefs().edit().clear().apply()
            AuthManager.signOut()
            binding.progressGlobal.visibility = View.GONE
            startActivity(Intent(this, AuthActivity::class.java)); finishAffinity()
        } catch (e: Exception) {
            binding.progressGlobal.visibility = View.GONE
            snack("Failed: ${e.message}")
        }
    }

    // ── Sign Out ──────────────────────────────────────────────────────────────

    private fun confirmSignOut() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Sign Out")
            .setMessage("Your encrypted data stays safely in Firebase.")
            .setPositiveButton("Sign Out") { _, _ ->
                KeystoreHelper.deleteAllWrappingKeys()
                VaultSession.clearAll()
                AuthManager.signOut()
                startActivity(Intent(this, AuthActivity::class.java)); finishAffinity()
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

    private fun friendlyAuthError(msg: String?) = when {
        msg == null -> "Unknown error"
        msg.contains("password") || msg.contains("credential") -> "Incorrect password"
        msg.contains("network") -> "Network error — check internet"
        msg.contains("too-many") -> "Too many attempts. Try later."
        else -> msg
    }

    private fun goToLock() { startActivity(Intent(this, LockActivity::class.java)); finishAffinity() }
    private fun snack(msg: String) = Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }
}
