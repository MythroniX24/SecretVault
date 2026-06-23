package com.mythronix.keysandpassword.crypto

import android.util.Base64
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2KtResult
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SecureVault Crypto — v26
 *
 * Key Derivation : Argon2id — 64MB · 4 passes · 4 lanes
 *   AES-256 is already quantum-resistant (Grover reduces to 128-bit
 *   security — still unbreakable). Argon2id prevents GPU/ASIC attacks
 *   on the password itself.
 *
 * Encryption     : AES-256-GCM (no AAD — simpler, no mismatch bugs)
 *   GCM auth tag provides authenticated encryption.
 *   Each item gets a fresh 12-byte random IV.
 *
 * Backward compat:
 *   • v7-v11 items  : AES-GCM, no AAD, hmac field present → decryptSimple()
 *   • v12-v21 items : AES-GCM WITH AAD "sv2:{uid}:{id}:{type}" → decryptWithAAD()
 *   • v22+ items    : AES-GCM, no AAD → decryptSimple()
 *
 *   decrypt() tries simple first; if that fails, tries known AAD patterns.
 *   This ensures ALL historical items can be opened.
 */
object CryptoManager {

    private const val ARGON2_MEMORY_KB   = 65_536
    private const val ARGON2_ITERATIONS  = 4
    private const val ARGON2_PARALLELISM = 4
    private const val ARGON2_HASH_LEN    = 32
    private const val GCM_IV_LENGTH      = 12
    private const val GCM_TAG_BITS       = 128

    const val SALT_LENGTH_BYTES = 32

    // ── Salt ─────────────────────────────────────────────────────────────────
    fun generateSalt(): ByteArray =
        ByteArray(SALT_LENGTH_BYTES).also { SecureRandom().nextBytes(it) }
    fun saltToBase64(s: ByteArray): String = Base64.encodeToString(s, Base64.NO_WRAP)
    fun saltFromBase64(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)

    // ── Key Derivation — Argon2id only, no fallback ───────────────────────────
    fun deriveKey(password: CharArray, salt: ByteArray): SecretKey {
        require(password.isNotEmpty()) { "Password empty" }
        require(salt.size == SALT_LENGTH_BYTES) { "Bad salt" }
        return try {
            val hash: Argon2KtResult = Argon2Kt().hash(
                mode               = Argon2Mode.ARGON2_ID,
                password           = password.concatToString().toByteArray(Charsets.UTF_8),
                salt               = salt,
                tCostInIterations  = ARGON2_ITERATIONS,
                mCostInKibibyte    = ARGON2_MEMORY_KB,
                parallelism        = ARGON2_PARALLELISM,
                hashLengthInBytes  = ARGON2_HASH_LEN
            )
            val bytes = hash.rawHashAsByteArray()
            val key   = SecretKeySpec(bytes.copyOf(32), "AES")
            bytes.fill(0)
            key
        } finally {
            password.fill('\u0000')
        }
    }

    // ── Encrypt ───────────────────────────────────────────────────────────────
    /** Encrypt plaintext with AES-256-GCM. Returns (encryptedBase64, ivBase64). */
    fun encrypt(plaintext: String, key: SecretKey): Pair<String, String> {
        val iv = ByteArray(GCM_IV_LENGTH).also { SecureRandom().nextBytes(it) }
        val c  = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val ct = c.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Pair(Base64.encodeToString(ct, Base64.NO_WRAP),
                    Base64.encodeToString(iv, Base64.NO_WRAP))
    }

    // ── Decrypt with full backward compatibility ──────────────────────────────
    /**
     * Decrypt an item. Tries approaches in order:
     *   1. Simple AES-GCM (no AAD) — works for v7-v11 and v22+ items
     *   2. AES-GCM with AAD "sv2:{userId}:{itemId}:{type}" — for v12-v21 items
     *   3. AES-GCM with AAD "sv1:{userId}:{itemId}:{type}" — alternative
     *
     * Never throws due to wrong approach — only throws if key is truly wrong.
     */
    fun decrypt(
        encB64: String, ivB64: String, key: SecretKey,
        userId: String = "", itemId: String = "", itemType: String = ""
    ): String {
        val ct = Base64.decode(encB64, Base64.NO_WRAP)
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)

        // Try 1: No AAD (most items)
        try {
            return decryptRaw(ct, iv, key, null)
        } catch (_: javax.crypto.AEADBadTagException) {}
        catch (_: Exception) {}

        // Try 2: AAD sv2 (v12-v21 items)
        if (userId.isNotEmpty() && itemId.isNotEmpty()) {
            try {
                val aad = "sv2:$userId:$itemId:$itemType".toByteArray()
                return decryptRaw(ct, iv, key, aad)
            } catch (_: javax.crypto.AEADBadTagException) {}
            catch (_: Exception) {}

            // Try 3: AAD sv1 (older v12 items)
            try {
                val aad = "sv1:$userId:$itemId:$itemType".toByteArray()
                return decryptRaw(ct, iv, key, aad)
            } catch (_: javax.crypto.AEADBadTagException) {}
            catch (_: Exception) {}
        }

        // All attempts failed — key is genuinely wrong
        throw javax.crypto.AEADBadTagException("Decryption failed — wrong key or corrupted data")
    }

    /** Legacy alias — same as decrypt() */
    fun decryptLegacy(encB64: String, ivB64: String, key: SecretKey): String =
        decrypt(encB64, ivB64, key)

    private fun decryptRaw(ct: ByteArray, iv: ByteArray, key: SecretKey, aad: ByteArray?): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        if (aad != null) c.updateAAD(aad)
        return String(c.doFinal(ct), Charsets.UTF_8)
    }

    // ── Overload for callers that pass extra metadata (userId/itemId unused for encrypt) ──
    @Suppress("UNUSED_PARAMETER")
    fun encrypt(p: String, k: SecretKey, userId: String, itemId: String, t: String) = encrypt(p, k)

    // ── Password Verifier ─────────────────────────────────────────────────────
    fun generateVerifierSalt(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }
    fun verifierSaltToBase64(s: ByteArray): String = Base64.encodeToString(s, Base64.NO_WRAP)
    fun verifierSaltFromBase64(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)

    fun computeVerifier(password: CharArray, salt: ByteArray): String {
        val spec = javax.crypto.spec.PBEKeySpec(password, salt, 100_000, 256)
        val hash = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).encoded
        spec.clearPassword()
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    fun safeEquals(a: String, b: String): Boolean {
        val ab = a.toByteArray()
        val bb = b.toByteArray()
        if (ab.size != bb.size) return false
        var diff = 0
        for (i in ab.indices) diff = diff or (ab[i].toInt() xor bb[i].toInt())
        return diff == 0
    }
}
