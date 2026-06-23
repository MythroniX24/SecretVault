package com.mythronix.keysandpassword.offline

import android.content.Context
import android.util.Base64
import com.mythronix.keysandpassword.crypto.CryptoManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Offline-only account manager (no Firebase).
 *
 * Stored data (on disk):
 * - accountId (UUID) used as logical userId
 * - salt (Argon2 salt) in base64
 * - verifierSalt (PBKDF2 verifier salt) in base64
 * - verifierHash (PBKDF2 verifier hash) in base64
 *
 * SECURITY:
 * - master password is NEVER stored
 * - verifier allows fast wrong-password rejection
 * - vault items are encrypted; verifier data is not the AES key
 */
object OfflineAccountManager {

    private const val ACCOUNT_FILE = "sv_account.json"

    data class Account(
        val accountId: String,
        val saltB64: String,
        val verifierHashB64: String,
        val verifierSaltB64: String
    ) {
        fun toJson(): String = JSONObject()
            .put("accountId", accountId)
            .put("saltB64", saltB64)
            .put("verifierHashB64", verifierHashB64)
            .put("verifierSaltB64", verifierSaltB64)
            .toString()
    }

    private fun accountFile(ctx: Context): File = File(ctx.filesDir, ACCOUNT_FILE)

    suspend fun hasAccount(ctx: Context): Boolean =
        withContext(Dispatchers.IO) {
            accountFile(ctx).exists()
        }

    suspend fun loadAccount(ctx: Context): Account? =
        withContext(Dispatchers.IO) {
            val f = accountFile(ctx)
            if (!f.exists()) return@withContext null
            val txt = f.readText()
            if (txt.isBlank()) return@withContext null
            val j = JSONObject(txt)
            val id = j.optString("accountId", "")
            val salt = j.optString("saltB64", "")
            val vh = j.optString("verifierHashB64", "")
            val vs = j.optString("verifierSaltB64", "")
            if (id.isBlank() || salt.isBlank() || vh.isBlank() || vs.isBlank()) null
            else Account(id, salt, vh, vs)
        }

    suspend fun createAccount(ctx: Context, masterPassword: CharArray): Account =
        withContext(Dispatchers.IO) {
            require(!accountFile(ctx).exists()) { "Account already exists" }

            val accountId = UUID.randomUUID().toString()

            val salt = CryptoManager.generateSalt()
            val saltB64 = CryptoManager.saltToBase64(salt)

            val verifierSalt = CryptoManager.generateVerifierSalt()
            val verifierSaltB64 = CryptoManager.verifierSaltToBase64(verifierSalt)

            val verifierHash = CryptoManager.computeVerifier(masterPassword, verifierSalt)

            val acc = Account(
                accountId = accountId,
                saltB64 = saltB64,
                verifierHashB64 = verifierHash,
                verifierSaltB64 = verifierSaltB64
            )

            val obj = JSONObject()
                .put("accountId", acc.accountId)
                .put("saltB64", acc.saltB64)
                .put("verifierHashB64", acc.verifierHashB64)
                .put("verifierSaltB64", acc.verifierSaltB64)

            accountFile(ctx).writeText(obj.toString())
            acc
        }

    suspend fun verifyPassword(ctx: Context, masterPassword: CharArray): Boolean =
        withContext(Dispatchers.IO) {
            val acc = loadAccount(ctx) ?: return@withContext false
            val vs = CryptoManager.verifierSaltFromBase64(acc.verifierSaltB64)
            val computed = CryptoManager.computeVerifier(masterPassword, vs)
            CryptoManager.safeEquals(computed, acc.verifierHashB64)
        }

    /**
     * Update the account's salt and verifier with new values (master password change).
     * Preserves the same accountId — vault items stay associated.
     */
    suspend fun updatePassword(ctx: Context, newMasterPassword: CharArray): Account =
        withContext(Dispatchers.IO) {
            val existing = loadAccount(ctx) ?: throw IllegalStateException("No account to update")

            val newSalt = CryptoManager.generateSalt()
            val newSaltB64 = CryptoManager.saltToBase64(newSalt)

            val newVerifierSalt = CryptoManager.generateVerifierSalt()
            val newVerifierSaltB64 = CryptoManager.verifierSaltToBase64(newVerifierSalt)
            val newVerifierHash = CryptoManager.computeVerifier(newMasterPassword, newVerifierSalt)

            val updated = Account(
                accountId = existing.accountId,  // Preserve same ID!
                saltB64 = newSaltB64,
                verifierHashB64 = newVerifierHash,
                verifierSaltB64 = newVerifierSaltB64
            )

            accountFile(ctx).writeText(updated.toJson())
            updated
        }

    suspend fun deleteAccount(ctx: Context) =
        withContext(Dispatchers.IO) {
            accountFile(ctx).delete()
        }

    suspend fun getSaltB64(ctx: Context): String? =
        loadAccount(ctx)?.saltB64
}
