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
import com.mythronix.keysandpassword.crypto.PasswordStrengthUtil
import com.mythronix.keysandpassword.crypto.PinManager
import com.mythronix.keysandpassword.databinding.ActivityLockBinding
import com.mythronix.keysandpassword.offline.OfflineAccountManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.crypto.SecretKey

class LockActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLockBinding
    private lateinit var securePrefs: android.content.SharedPreferences

    // Offline: single local account id stored in OfflineAccountManager.
    // We keep it stable by deriving AAD / keystore ids from the offline accountId.
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityLockBinding.inflate(layoutInflater)
        setContentView(binding.root)

        securePrefs = buildSecurePrefs()
        uid = AuthManager.getCurrentUser()?.uid ?: ""

        binding.btnUnlockPassword.setOnClickListener { unlockWithPassword() }
        binding.btnUnlockPin.setOnClickListener      { showPinDialog() }
        binding.tvUseMasterPassword.setOnClickListener {
            binding.layoutBiometric.visibility      = View.GONE
            binding.layoutMasterPassword.visibility = View.VISIBLE
            binding.tvUseMasterPassword.visibility  = View.GONE
        }
        if (PinManager.isPinEnabled(this)) binding.btnUnlockPin.visibility = View.VISIBLE

        // SHOW FORM IMMEDIATELY — don't wait for network (fixes blank screen)
        showUnlockMode()
        // Then check biometric availability async
        lifecycleScope.launch { checkAndShowBiometric() }
    }

    // ─── Show master password form immediately, no blank screen ──────────────
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

    // ─── Async: check if biometric available, show if yes ────────────────────
    private suspend fun initFlow() {
        // Check if user is new (no salt = first time)
        val salt = withContext(Dispatchers.IO) {
            try { if (uid.isNotEmpty()) FirestoreManager.getSalt(uid) else null }
            catch (_: Exception) { null }
        }
        isNewUser = (salt == null)

        if (isNewUser) {
            // First time: show create password form
            binding.layoutBiometric.visibility      = View.GONE
            binding.layoutMasterPassword.visibility = View.VISIBLE
            binding.tvUseMasterPassword.visibility  = View.GONE
            binding.tvLockTitle.text    = "Set Master Password"
            binding.tvLockSubtitle.text = "Create a strong password. Never stored — remember it!"
            binding.tilConfirmMasterPw.visibility = View.VISIBLE
            binding.btnUnlockPassword.text        = "Create Vault"
            binding.layoutStrength.visibility     = View.GONE
            attachStrengthMeter()
        }
    }

    private suspend fun checkAndShowBiometric() {
        // First check salt to determine new vs returning user
        withContext(Dispatchers.IO) {
            try {
                val salt = if (uid.isNotEmpty()) FirestoreManager.getSalt(uid) else null
                isNewUser = (salt == null)
            } catch (_: Exception) {
                isNewUser = false // assume returning user on network error
            }
        }

        if (isNewUser) {
            // New user - show create password form
            binding.tvLockTitle.text              = "Set Master Password"
            binding.tvLockSubtitle.text           = "Create a strong password — never stored, remember it!"
            binding.tilConfirmMasterPw.visibility = View.VISIBLE
            binding.btnUnlockPassword.text        = "Create Vault"
            binding.layoutMasterPassword.visibility = View.VISIBLE
            attachStrengthMeter()
            return
        }

        // Returning user - check biometric
        val wrappedKey = securePrefs.getString(prefWrappedKey(uid), null)
        val wrappedIv  = securePrefs.getString(prefWrappedIv(uid), null)
        val hasBio     = wrappedKey != null && wrappedIv != null
                         && KeystoreHelper.hasWrappingKey(uid) && checkBiometric()

        if (hasBio) {
            binding.layoutBiometric.visibility      = View.VISIBLE
            binding.layoutMasterPassword.visibility = View.GONE
            binding.tvUseMasterPassword.visibility  = View.VISIBLE
            triggerBiometric(wrappedKey!!, wrappedIv!!)
        }
        // else: password form already shown from showUnlockMode()
    }

    // ─── Strength meter — attached when in create-password mode ──────────────
    private var strengthAttached = false
    private fun attachStrengthMeter() {
        if (strengthAttached) return
        strengthAttached = true
        binding.etMasterPassword.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun afterTextChanged(s: Editable?) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, count: Int) {
                val pw = s?.toString() ?: ""
                if (pw.isEmpty() || !isNewUser) {
                    binding.layoutStrength.visibility = View.GONE; return
                }
                binding.layoutStrength.visibility = View.VISIBLE
                val r = PasswordStrengthUtil.evaluate(pw)
                val filled: Int
                if      (r.score >= 80) filled = 5
                else if (r.score >= 60) filled = 4
                else if (r.score >= 40) filled = 3
                else if (r.score >= 20) filled = 2
                else if (r.score > 0)   filled = 1
                else                    filled = 0
                val col: Int
                if      (filled >= 4) col = Color.parseColor("#4CAF50")
                else if (filled >= 2) col = Color.parseColor("#FF9800")
                else                  col = Color.parseColor("#F44336")
                val emp = Color.parseColor("#E0E0E0")
                binding.bar1.setBackgroundColor(if (filled >= 1) col else emp)
                binding.bar2.setBackgroundColor(if (filled >= 2) col else emp)
                binding.bar3.setBackgroundColor(if (filled >= 3) col else emp)
                binding.bar4.setBackgroundColor(if (filled >= 4) col else emp)
                binding.bar5.setBackgroundColor(if (filled >= 5) col else emp)
                binding.tvStrengthLabel.text = r.strength.label
                binding.tvStrengthLabel.setTextColor(col)
                binding.tvStrengthTip.text = r.tips.firstOrNull() ?: ""
            }
        })
    }

    // ─── Biometric ────────────────────────────────────────────────────────────
    private fun triggerBiometric(wrappedKey: String, wrappedIv: String) {
        lifecycleScope.launch {
            if (uid.isNotEmpty()) {
                val lock = withContext(Dispatchers.IO) {
                    runCatching { LockoutManager.checkLock(uid, LockoutManager.LockType.FINGERPRINT) }
                        .getOrNull()
                }
                if (lock?.isLocked == true) {
                    snack("⛔ Fingerprint locked for ${lock.remainingHours()}")
                    binding.layoutBiometric.visibility      = View.GONE
                    binding.layoutMasterPassword.visibility = View.VISIBLE
                    binding.tvUseMasterPassword.visibility  = View.GONE
                    return@launch
                }
            }
            val cipher = KeystoreHelper.getDecryptCipherOrNull(uid, wrappedIv)
            if (cipher == null) {
                securePrefs.edit().remove(prefWrappedKey(uid)).remove(prefWrappedIv(uid)).apply()
                KeystoreHelper.deleteWrappingKey(uid)
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
                        VaultSession.setKey(key, uid)
                        lifecycleScope.launch(Dispatchers.IO) {
                            runCatching { LockoutManager.clearLock(uid, LockoutManager.LockType.FINGERPRINT) }
                            runCatching { DeviceSessionManager.recordSession(this@LockActivity, uid) }
                        }
                        goToVault()
                    }
                    override fun onAuthenticationError(c: Int, s: CharSequence) {
                        if (c != BiometricPrompt.ERROR_USER_CANCELED &&
                            c != BiometricPrompt.ERROR_NEGATIVE_BUTTON) snack("Biometric: $s")
                    }
                    override fun onAuthenticationFailed() {
                        lifecycleScope.launch {
                            val st = withContext(Dispatchers.IO) {
                                runCatching { LockoutManager.recordFailure(uid, LockoutManager.LockType.FINGERPRINT) }.getOrNull()
                            }
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
        val confirm = binding.etConfirmMasterPassword.text.toString()
        if (pw.length < 8) { snack("Minimum 8 characters required"); return }
        if (isNewUser && pw != confirm) { snack("Passwords do not match"); return }

        setLoading(true)
        lifecycleScope.launch {
            try {
                if (!isNewUser && uid.isNotEmpty()) {
                    val st = withContext(Dispatchers.IO) {
                        runCatching { LockoutManager.checkLock(uid, LockoutManager.LockType.MASTER_PASSWORD) }.getOrNull()
                    }
                    if (st?.isLocked == true) {
                        setLoading(false)
                        snack("⛔ Locked for ${st.remainingHours()} — too many wrong attempts")
                        return@launch
                    }
                }

                val salt: ByteArray = withContext(Dispatchers.IO) {
                    if (isNewUser) {
                        CryptoManager.generateSalt().also {
                            FirestoreManager.saveSalt(uid, CryptoManager.saltToBase64(it))
                        }
                    } else {
                        val b64 = FirestoreManager.getSalt(uid)
                        if (b64 == null) {
                            withContext(Dispatchers.Main) {
                                setLoading(false)
                                snack("Cannot reach server — check internet and try again")
                            }
                            return@withContext null
                        }
                        CryptoManager.saltFromBase64(b64)
                    }
                } ?: return@launch

                // Verify password quickly before slow Argon2
                if (!isNewUser && uid.isNotEmpty()) {
                    val wrong = withContext(Dispatchers.IO) {
                        try {
                            val v = FirestoreManager.getVerifier(uid)
                            if (v != null) {
                                val vs = CryptoManager.verifierSaltFromBase64(v.saltB64)
                                val h  = CryptoManager.computeVerifier(pw.toCharArray(), vs)
                                !CryptoManager.safeEquals(h, v.hash)
                            } else false
                        } catch (_: Exception) { false }
                    }
                    if (wrong) {
                        val st = withContext(Dispatchers.IO) {
                            runCatching { LockoutManager.recordFailure(uid, LockoutManager.LockType.MASTER_PASSWORD) }.getOrNull()
                        }
                        setLoading(false)
                        if (st?.isLocked == true) snack("⛔ Account locked 24h — too many wrong attempts")
                        else snack("Wrong master password")
                        return@launch
                    }
                }

                // Argon2id on background thread — prevents ANR
                val key = withContext(Dispatchers.Default) {
                    CryptoManager.deriveKey(pw.toCharArray(), salt)
                }
                VaultSession.setKey(key, uid)

                if (isNewUser && uid.isNotEmpty()) {
                    withContext(Dispatchers.IO) {
                        runCatching {
                            val vs = CryptoManager.generateVerifierSalt()
                            val vh = CryptoManager.computeVerifier(pw.toCharArray(), vs)
                            FirestoreManager.saveVerifier(uid, vh, CryptoManager.verifierSaltToBase64(vs))
                        }
                    }
                }

                if (!isNewUser && uid.isNotEmpty()) {
                    withContext(Dispatchers.IO) {
                        runCatching { LockoutManager.clearLock(uid, LockoutManager.LockType.MASTER_PASSWORD) }
                        runCatching { DeviceSessionManager.recordSession(this@LockActivity, uid) }
                    }
                }

                setLoading(false)
                if (checkBiometric()) offerFingerprint(key) else goToVault()

            } catch (e: Exception) {
                setLoading(false)
                snack("Error: ${e.message ?: "Check internet connection"}")
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

    fun setupBiometric(key: javax.crypto.SecretKey) {
        try {
            KeystoreHelper.deleteWrappingKey(uid)
            KeystoreHelper.generateWrappingKey(uid)
            val cipher = KeystoreHelper.getEncryptCipherOrNull(uid) ?: run { goToVault(); return }
            val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        r.cryptoObject?.cipher?.let { c ->
                            val (w, iv) = KeystoreHelper.wrapKey(c, key)
                            securePrefs.edit().putString(prefWrappedKey(uid), w)
                                .putString(prefWrappedIv(uid), iv).apply()
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
        if (uid.isEmpty()) return
        lifecycleScope.launch {
            val lock = withContext(Dispatchers.IO) {
                runCatching { LockoutManager.checkLock(uid, LockoutManager.LockType.PIN) }.getOrNull()
            }
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
                            VaultSession.clearAll(); AuthManager.signOut()
                            startActivity(Intent(this@LockActivity, AuthActivity::class.java))
                            finishAffinity(); return@launch
                        }
                        val mk = withContext(Dispatchers.Default) {
                            PinManager.verifyPinAndGetKey(this@LockActivity, pin)
                        }
                        if (mk != null) {
                            withContext(Dispatchers.IO) { runCatching { LockoutManager.clearLock(uid, LockoutManager.LockType.PIN) } }
                            VaultSession.setKey(mk, uid); goToVault()
                        } else {
                            val st = withContext(Dispatchers.IO) {
                                runCatching { LockoutManager.recordFailure(uid, LockoutManager.LockType.PIN) }.getOrNull()
                            }
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

    fun getBiometricState(): BiometricState {
        val bm = BiometricManager.from(this)
        val r  = if (android.os.Build.VERSION.SDK_INT >= 30)
                     bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                 else @Suppress("DEPRECATION") bm.canAuthenticate()
        return when (r) {
            BiometricManager.BIOMETRIC_SUCCESS              -> BiometricState.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricState.NONE_ENROLLED
            else                                            -> BiometricState.NOT_AVAILABLE
        }
    }

    enum class BiometricState { AVAILABLE, NONE_ENROLLED, NOT_AVAILABLE }

    private fun goToVault() { startActivity(Intent(this, VaultActivity::class.java)); finish() }

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
        fun prefKey(uid: String)        = prefWrappedKey(uid)
        fun prefKeyIv(uid: String)      = prefWrappedIv(uid)
    }
}
