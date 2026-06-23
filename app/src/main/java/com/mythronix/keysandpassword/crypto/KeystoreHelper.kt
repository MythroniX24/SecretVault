package com.mythronix.keysandpassword.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object KeystoreHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val GCM_TAG_BITS     = 128
    private const val LEGACY_ALIAS     = "sv_wrapping_key_v1"

    fun userAlias(uid: String): String =
        if (uid.isBlank()) LEGACY_ALIAS else "sv_wrap_${uid.take(16)}"

    // ── Key generation — crash-proof, OEM-compatible ──────────────────────────

    /**
     * Generate biometric-protected key in Keystore.
     *
     * Tries strategies in order until one works:
     *   1. TEE key with BIOMETRIC_STRONG (standard, most devices)
     *   2. TEE key with BIOMETRIC_STRONG but no invalidation (Xiaomi/Samsung workaround)
     *   3. Basic TEE key (last resort — still hardware-backed)
     *
     * StrongBox NOT attempted — it's rare, causes OEM-specific crashes, adds no
     * meaningful security over TEE for this use case.
     */
    fun generateWrappingKey(uid: String) {
        val alias = userAlias(uid)
        val ks    = loadKeystore()
        // Delete any existing key first — may be corrupt from a previous failed attempt
        if (ks.containsAlias(alias)) {
            try { ks.deleteEntry(alias) } catch (_: Exception) {}
        }

        // Strategy 1: Standard biometric key
        runCatching {
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .apply { init(spec) }.generateKey()
            return  // success
        }

        // Strategy 2: Without invalidation (Xiaomi/Samsung OEM fix)
        runCatching {
            val spec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(false)
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .apply { init(spec) }.generateKey()
            return  // success
        }

        // Strategy 3: Basic TEE key (all auth types allowed)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(30, // 30-second timeout
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }.generateKey()
    }

    fun deleteWrappingKey(uid: String) {
        val ks = loadKeystore()
        listOf(userAlias(uid), LEGACY_ALIAS).forEach {
            runCatching { if (ks.containsAlias(it)) ks.deleteEntry(it) }
        }
    }

    fun deleteAllWrappingKeys() {
        val ks = loadKeystore()
        ks.aliases().asSequence()
            .filter { it.startsWith("sv_wrap_") || it == LEGACY_ALIAS }
            .toList()  // collect before modifying
            .forEach { runCatching { ks.deleteEntry(it) } }
    }

    fun hasWrappingKey(uid: String): Boolean {
        val ks = loadKeystore()
        return ks.containsAlias(userAlias(uid)) || ks.containsAlias(LEGACY_ALIAS)
    }

    // ── Cipher factories ──────────────────────────────────────────────────────

    /**
     * Get encrypt cipher. Returns null on failure (don't crash caller).
     */
    fun getEncryptCipherOrNull(uid: String): Cipher? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, loadKey(uid))
            cipher
        } catch (e: Exception) { null }
    }

    fun getEncryptCipher(uid: String): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, loadKey(uid))
        return cipher
    }

    fun getDecryptCipherOrNull(uid: String, ivBase64: String): Cipher? {
        return try {
            val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, loadKey(uid), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            deleteWrappingKey(uid)
            null
        } catch (e: Exception) { null }
    }

    // ── Wrap / Unwrap ─────────────────────────────────────────────────────────

    fun wrapKey(encryptCipher: Cipher, masterKey: SecretKey): Pair<String, String> {
        val wrapped = encryptCipher.doFinal(masterKey.encoded)
        return Pair(
            Base64.encodeToString(wrapped, Base64.NO_WRAP),
            Base64.encodeToString(encryptCipher.iv, Base64.NO_WRAP)
        )
    }

    fun unwrapKey(decryptCipher: Cipher, wrappedKeyBase64: String): SecretKey {
        val bytes = Base64.decode(wrappedKeyBase64, Base64.NO_WRAP)
        return SecretKeySpec(decryptCipher.doFinal(bytes), "AES")
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun loadKeystore() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun loadKey(uid: String): SecretKey {
        val ks = loadKeystore()
        val alias = when {
            ks.containsAlias(userAlias(uid)) -> userAlias(uid)
            ks.containsAlias(LEGACY_ALIAS)   -> LEGACY_ALIAS
            else -> throw java.security.KeyStoreException("No key for uid=$uid")
        }
        return ks.getKey(alias, null) as SecretKey
    }
}
