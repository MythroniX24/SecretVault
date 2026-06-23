package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.crypto.KeystoreHelper
import com.mythronix.keysandpassword.crypto.LockoutManager
import com.mythronix.keysandpassword.crypto.PinManager
import com.mythronix.keysandpassword.databinding.ActivityLockBinding
import com.mythronix.keysandpassword.offline.OfflineAccountManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LockActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLockBinding
    private lateinit var securePrefs: android.content.SharedPreferences

    private var accountId = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityLockBinding.inflate(layoutInflater)
        setContentView(binding.root)

        securePrefs = buildSecurePrefs()

        binding.btnUnlockPassword.setOnClickListener { unlockWithPassword() }
        binding.btnUnlockPin.setOnClickListener      { showPinDialog() }
        binding.tvUseMasterPassword.setOnClickListener {
            binding.layoutBiometric.visibility      = View.GONE
            binding.layoutMasterPassword.visibility = View.VISIBLE
            binding.tvUseMasterPassword.visibility  = View.GONE
        }
        if (PinManager.isPinEnabled(this)) binding.btnUnlockPin.visibility = View.VISIBLE

        // Show master password form immediately — no blank screen
        showUnlockMode()

        // Load account and check biometric availability
        lifecycleScope.launch { loadAndCheckBiometric() }
    }

    // ─── Show master password form ────────────────────────────────────────────
    private fun showUnlockMode() {
        binding.layoutBiometric.visibility      = View.GONE
        binding.layoutMasterPassword.visibility = View.VISIBLE
        binding.tvUseMasterPassword.visibility  = View.GONE
        binding.tvLockTitle.text    = "Unlock Vault"
        binding.tvLockSubtitle.text = "Enter your master password"
        binding.tilConfirmMasterPw.visibility = View.GONE
        binding.btnUnlockPassword.text        = "Unlock"
        binding.layoutStrength.visibility     = View.GONE
    }

    // ─── Async: load account, check biometric availability ────────────────────
    private suspend fun loadAndCheckBiometric() {
        val account = withContext(Dispatchers.IO) {
            OfflineAccountManager.loadAccount(this@LockActivity)
        }

        if (account == null) {
            // No account found — redirect to create one
            goToAuth()
            return
        }

        accountId = account.accountId

        // Check if biometric is available
        val wrappedKey = securePrefs.getString(prefWrappedKey(accountId), null)
        val wrappedIv  = securePrefs.getString(prefWrappedIv(accountId), null)
        val hasBio     = wrappedKey != null && wrappedIv != null
                         && KeystoreHelper.hasWrappingKey(accountId) && checkBiometric()

        if (hasBio) {
            binding.layoutBiometric.visibility      = View.VISIBLE
            binding.layoutMasterPassword.visibility = View.GONE
            binding.tvUseMasterPassword.visibility  = View.VISIBLE
            triggerBiometric(wrappedKey!!, wrappedIv!!)
        }
    }

    // ─── Biometric ────────────────────────────────────────────────────────────
    private fun triggerBiometric(wrappedKey: String, wrappedIv: String) {
        lifecycleScope.launch {
            val lock = runCatching { LockoutManager.checkLock(this@LockActivity, accountId, LockoutManager.LockType.FINGERPRINT) }
                .getOrNull()
            if (lock?.isLocked == true) {
                snack("⛔ Fingerprint locked for ${lock.remainingHours()}")
                binding.layoutBiometric.visibility      = View.GONE
                binding.layoutMasterPassword.visibility = View.VISIBLE
                binding.tvUseMasterPassword.visibility  = View.GONE
                return@launch
            }
            val cipher = KeystoreHelper.getDecryptCipherOrNull(accountId, wrappedIv)
            if (cipher == null) {
                securePrefs.edit().remove(prefWrappedKey(accountId)).remove(prefWrappedIv(accountId)).apply()
                KeystoreHelper.deleteWrappingKey(accountId)
                binding.layoutBiometric.visibility      = View.GONE
                binding.layoutMasterPassword.visibility = View.VISIBLE
                binding.tvUseMasterPassword.visibility  = View.GONE
                snack("Biometric changed — re-enter master password")
                return@launch
            }
            val prompt = BiometricPrompt(this@LockActivity,
                ContextCompat.getMainExecutor(this@LockActivity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        val key = runCatching {
                            KeystoreHelper.unwrapKey(r.cryptoObject!!.cipher!!, wrappedKey)
                        }.getOrNull() ?: return
                        VaultSession.setKey(key, accountId)
                        runCatching { LockoutManager.clearLock(this@LockActivity, accountId, LockoutManager.LockType.FINGERPRINT) }
                        goToVault()
                    }
                    override fun onAuthenticationError(c: Int, s: CharSequence) {
                        if (c != BiometricPrompt.ERROR_USER_CANCELED &&
                            c != BiometricPrompt.ERROR_NEGATIVE_BUTTON) snack("Biometric: $s")
                    }
                    override fun onAuthenticationFailed() {
                        lifecycleScope.launch {
                            val st = runCatching { LockoutManager.recordFailure(this@LockActivity, accountId, LockoutManager.LockType.FINGERPRINT) }.getOrNull()
                            if (st?.isLocked == true) {
                                snack("⛔ Fingerprint locked 24h — use Master Password")
                                binding.layoutBiometric.visibility      = View.GONE
                                binding.layoutMasterPassword.visibility = View.VISIBLE
                            } else snack("Not recognised — try again")
                        }
                    }
                })
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Secure Vault")
                .setSubtitle("Use fingerprint to unlock")
                .setNegativeButtonText("Use Master Password")
                .build()
            runCatching { prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher)) }
                .onFailure {
                    binding.layoutBiometric.visibility      = View.GONE
                    binding.layoutMasterPassword.visibility = View.VISIBLE
                }
        }
    }

    // ─── Master Password ──────────────────────────────────────────────────────
    private fun unlockWithPassword() {
        val pw      = binding.etMasterPassword.text.toString()
        if (pw.length < 8) { snack("Minimum 8 characters required"); return }
        if (accountId.isEmpty()) { snack("Loading account — please wait"); return }

        setLoading(true)
        lifecycleScope.launch {
            try {
                // Check lockout
                val st = runCatching { LockoutManager.checkLock(this@LockActivity, accountId, LockoutManager.LockType.MASTER_PASSWORD) }.getOrNull()
                if (st?.isLocked == true) {
                    setLoading(false)
                    snack("⛔ Locked for ${st.remainingHours()} — too many wrong attempts")
                    return@launch
                }

                // Verify password against offline account
                val passwordCorrect = withContext(Dispatchers.IO) {
                    OfflineAccountManager.verifyPassword(this@LockActivity, pw.toCharArray())
                }

                if (!passwordCorrect) {
                    val lockStatus = runCatching { LockoutManager.recordFailure(this@LockActivity, accountId, LockoutManager.LockType.MASTER_PASSWORD) }.getOrNull()
                    setLoading(false)
                    if (lockStatus?.isLocked == true) snack("⛔ Account locked 24h — too many wrong attempts")
                    else snack("Wrong master password")
                    return@launch
                }

                // Derive AES key
                val saltB64 = withContext(Dispatchers.IO) {
                    OfflineAccountManager.getSaltB64(this@LockActivity)
                } ?: run {
                    setLoading(false)
                    snack("Account data corrupted — recreate vault")
                    return@launch
                }

                val salt = CryptoManager.saltFromBase64(saltB64)
                val key = withContext(Dispatchers.Default) {
                    CryptoManager.deriveKey(pw.toCharArray(), salt)
                }

                VaultSession.setKey(key, accountId)

                // Clear lockout on successful unlock
                runCatching { LockoutManager.clearLock(this@LockActivity, accountId, LockoutManager.LockType.MASTER_PASSWORD) }

                setLoading(false)
                if (checkBiometric()) offerFingerprint(key) else goToVault()

            } catch (e: Exception) {
                setLoading(false)
                snack("Error: ${e.message ?: "Unknown error"}")
            }
        }
    }

    private fun offerFingerprint(key: javax.crypto.SecretKey) {
        MaterialAlertDialogBuilder(this)
            .setTitle("Enable Fingerprint Unlock?")
            .setMessage("Unlock your vault quickly with fingerprint next time.")
            .setPositiveButton("Enable") { _, _ -> setupBiometric(key) }
            .setNegativeButton("Skip")   { _, _ -> goToVault() }
            .show()
    }

    private fun setupBiometric(key: javax.crypto.SecretKey) {
        try {
            KeystoreHelper.deleteWrappingKey(accountId)
            KeystoreHelper.generateWrappingKey(accountId)
            val cipher = KeystoreHelper.getEncryptCipherOrNull(accountId) ?: run { goToVault(); return }
            val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        r.cryptoObject?.cipher?.let { c ->
                            val (w, iv) = KeystoreHelper.wrapKey(c, key)
                            securePrefs.edit().putString(prefWrappedKey(accountId), w)
                                .putString(prefWrappedIv(accountId), iv).apply()
                        }
                        goToVault()
                    }
                    override fun onAuthenticationError(c: Int, s: CharSequence) = goToVault()
                    override fun onAuthenticationFailed() = snack("Not recognised")
                })
            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Register Fingerprint")
                    .setSubtitle("Touch sensor to enable fingerprint unlock")
                    .setNegativeButtonText("Skip").build(),
                BiometricPrompt.CryptoObject(cipher))
        } catch (_: Exception) { goToVault() }
    }

    // ─── PIN ──────────────────────────────────────────────────────────────────
    private fun showPinDialog() {
        if (accountId.isEmpty()) return
        lifecycleScope.launch {
            val lock = runCatching { LockoutManager.checkLock(this@LockActivity, accountId, LockoutManager.LockType.PIN) }.getOrNull()
            if (lock?.isLocked == true) { snack("⛔ PIN locked — use Master Password"); return@launch }
            val et = com.google.android.material.textfield.TextInputEditText(this@LockActivity).apply {
                inputType = android.text.InputType.TYPE_CLASS_NUMBER or
                            android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            }
            val til = com.google.android.material.textfield.TextInputLayout(
                this@LockActivity, null, com.google.android.material.R.attr.textInputOutlinedStyle
            ).apply { hint = "Enter PIN"; addView(et); setPadding(48, 16, 48, 0) }
            MaterialAlertDialogBuilder(this@LockActivity)
                .setTitle("Enter App PIN").setView(til)
                .setPositiveButton("Unlock") { _, _ ->
                    lifecycleScope.launch {
                        val pin = et.text.toString()
                        if (PinManager.isDuressPinEnabled(this@LockActivity) &&
                            PinManager.verifyDuressPin(this@LockActivity, pin)) {
                            VaultSession.clearAll()
                            startActivity(Intent(this@LockActivity, AuthActivity::class.java))
                            finishAffinity(); return@launch
                        }
                        val mk = withContext(Dispatchers.Default) {
                            PinManager.verifyPinAndGetKey(this@LockActivity, pin)
                        }
                        if (mk != null) {
                            runCatching { LockoutManager.clearLock(this@LockActivity, accountId, LockoutManager.LockType.PIN) }
                            VaultSession.setKey(mk, accountId); goToVault()
                        } else {
                            val st = runCatching { LockoutManager.recordFailure(this@LockActivity, accountId, LockoutManager.LockType.PIN) }.getOrNull()
                            if (st?.isLocked == true) snack("⛔ PIN locked 24h")
                            else snack("Incorrect PIN")
                        }
                    }
                }.setNegativeButton("Cancel", null).show()
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────
    private fun checkBiometric(): Boolean {
        val bm = BiometricManager.from(this)
        val r  = if (android.os.Build.VERSION.SDK_INT >= 30)
                     bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                 else @Suppress("DEPRECATION") bm.canAuthenticate()
        return r == BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun goToVault() { startActivity(Intent(this, VaultActivity::class.java)); finish() }
    private fun goToAuth() { startActivity(Intent(this, AuthActivity::class.java)); finish() }

    private fun setLoading(on: Boolean) {
        binding.progressBar.visibility      = if (on) View.VISIBLE else View.GONE
        binding.btnUnlockPassword.isEnabled = !on
        binding.etMasterPassword.isEnabled  = !on
    }

    private fun snack(msg: String) = Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()

    private fun buildSecurePrefs(): android.content.SharedPreferences {
        val mk = MasterKey.Builder(this).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(this, "sv_secure_prefs", mk,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }

    companion object {
        fun prefWrappedKey(uid: String) = "sv_wk_${uid.take(12)}"
        fun prefWrappedIv(uid: String)  = "sv_wi_${uid.take(12)}"
    }
}
