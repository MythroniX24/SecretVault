package com.mythronix.keysandpassword.crypto

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * PIN Manager — PIN unlocks vault DIRECTLY without biometric.
 *
 * How it works:
 *   1. User sets PIN → derive AES key from PIN via PBKDF2
 *   2. Wrap master key bytes with that PIN-AES key (AES-256-GCM)
 *   3. Store wrapped blob in EncryptedSharedPreferences
 *   4. On PIN entry → re-derive key from PIN → decrypt blob → get master key
 *
 * This means PIN can INDEPENDENTLY unlock the vault, no biometric needed.
 * Duress PIN → silently signs out (vault appears empty/gone).
 */
object PinManager {

    private const val PREFS_NAME           = "sv_pin_store"
    private const val KEY_PIN_ENABLED      = "pin_on"
    private const val KEY_PIN_HASH         = "pin_h"
    private const val KEY_PIN_SALT         = "pin_s"
    private const val KEY_PIN_WRAPPED_KEY  = "pin_wk"    // AES-GCM wrapped master key
    private const val KEY_PIN_WRAPPED_IV   = "pin_wiv"   // IV for the wrapping
    private const val KEY_DURESS_ENABLED   = "dur_on"
    private const val KEY_DURESS_HASH      = "dur_h"
    private const val KEY_DURESS_SALT      = "dur_s"
    private const val PBKDF2_ITER          = 100_000
    private const val GCM_TAG_BITS         = 128

    private fun prefs(ctx: Context): android.content.SharedPreferences {
        val mk = MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(ctx, PREFS_NAME, mk,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }

    fun isPinEnabled(ctx: Context)       = prefs(ctx).getBoolean(KEY_PIN_ENABLED, false)
    fun isDuressPinEnabled(ctx: Context) = prefs(ctx).getBoolean(KEY_DURESS_ENABLED, false)
    fun hasMasterKeyWrapped(ctx: Context) = prefs(ctx).getString(KEY_PIN_WRAPPED_KEY, null) != null

    // ── App PIN ────────────────────────────────────────────────────────────────

    /**
     * Set PIN and wrap the current master key with it.
     * Call this when user sets/changes PIN (master key must be in VaultSession).
     */
    fun setPin(ctx: Context, pin: String, masterKey: SecretKey) {
        val salt       = randomSalt()
        val pinAesKey  = derivePinKey(pin, salt)
        val (wrapped, iv) = wrapWithPinKey(masterKey, pinAesKey)
        val hash       = hashPin(pin, salt)

        prefs(ctx).edit()
            .putBoolean(KEY_PIN_ENABLED, true)
            .putString(KEY_PIN_HASH, b64(hash))
            .putString(KEY_PIN_SALT, b64(salt))
            .putString(KEY_PIN_WRAPPED_KEY, wrapped)
            .putString(KEY_PIN_WRAPPED_IV, iv)
            .apply()
    }

    /**
     * Verify PIN and return decrypted master key if correct. Returns null if wrong PIN.
     */
    fun verifyPinAndGetKey(ctx: Context, pin: String): SecretKey? {
        val p        = prefs(ctx)
        val saltB64  = p.getString(KEY_PIN_SALT, null) ?: return null
        val salt     = Base64.decode(saltB64, Base64.NO_WRAP)

        if (!checkPinHash(p, pin, salt)) return null

        val wrapped  = p.getString(KEY_PIN_WRAPPED_KEY, null) ?: return null
        val ivB64    = p.getString(KEY_PIN_WRAPPED_IV, null) ?: return null
        val pinKey   = derivePinKey(pin, salt)

        return try { unwrapWithPinKey(wrapped, ivB64, pinKey) } catch (_: Exception) { null }
    }

    /** Just verify PIN hash (for display/settings purposes) */
    fun verifyPin(ctx: Context, pin: String): Boolean {
        val p       = prefs(ctx)
        val saltB64 = p.getString(KEY_PIN_SALT, null) ?: return false
        return checkPinHash(p, pin, Base64.decode(saltB64, Base64.NO_WRAP))
    }

    fun disablePin(ctx: Context) {
        prefs(ctx).edit()
            .remove(KEY_PIN_ENABLED).remove(KEY_PIN_HASH).remove(KEY_PIN_SALT)
            .remove(KEY_PIN_WRAPPED_KEY).remove(KEY_PIN_WRAPPED_IV)
            .apply()
    }

    // ── Duress PIN ─────────────────────────────────────────────────────────────

    fun setDuressPin(ctx: Context, pin: String) {
        val salt = randomSalt()
        prefs(ctx).edit()
            .putBoolean(KEY_DURESS_ENABLED, true)
            .putString(KEY_DURESS_HASH, b64(hashPin(pin, salt)))
            .putString(KEY_DURESS_SALT, b64(salt))
            .apply()
    }

    fun verifyDuressPin(ctx: Context, pin: String): Boolean {
        val p       = prefs(ctx)
        if (!p.getBoolean(KEY_DURESS_ENABLED, false)) return false
        val saltB64 = p.getString(KEY_DURESS_SALT, null) ?: return false
        val stored  = p.getString(KEY_DURESS_HASH, null) ?: return false
        val hash    = hashPin(pin, Base64.decode(saltB64, Base64.NO_WRAP))
        return MessageDigest.isEqual(hash, Base64.decode(stored, Base64.NO_WRAP))
    }

    fun disableDuressPin(ctx: Context) {
        prefs(ctx).edit().remove(KEY_DURESS_ENABLED).remove(KEY_DURESS_HASH).remove(KEY_DURESS_SALT).apply()
    }

    fun clearAll(ctx: Context) = prefs(ctx).edit().clear().apply()

    // ── Crypto helpers ────────────────────────────────────────────────────────

    private fun derivePinKey(pin: String, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITER, 256)
        val bytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(bytes, "AES")
    }

    private fun wrapWithPinKey(masterKey: SecretKey, pinKey: SecretKey): Pair<String, String> {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, pinKey, GCMParameterSpec(GCM_TAG_BITS, iv))
        val wrapped = cipher.doFinal(masterKey.encoded)
        return Pair(b64(wrapped), b64(iv))
    }

    private fun unwrapWithPinKey(wrappedB64: String, ivB64: String, pinKey: SecretKey): SecretKey {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, pinKey,
            GCMParameterSpec(GCM_TAG_BITS, Base64.decode(ivB64, Base64.NO_WRAP)))
        val keyBytes = cipher.doFinal(Base64.decode(wrappedB64, Base64.NO_WRAP))
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun hashPin(pin: String, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITER, 256)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
            .also { spec.clearPassword() }
    }

    private fun checkPinHash(p: android.content.SharedPreferences, pin: String, salt: ByteArray): Boolean {
        val stored = p.getString(KEY_PIN_HASH, null) ?: return false
        return MessageDigest.isEqual(hashPin(pin, salt), Base64.decode(stored, Base64.NO_WRAP))
    }

    private fun randomSalt() = ByteArray(16).also { SecureRandom().nextBytes(it) }
    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
}
