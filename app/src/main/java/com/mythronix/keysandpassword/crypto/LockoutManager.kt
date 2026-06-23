package com.mythronix.keysandpassword.crypto

import android.util.Base64
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await
import java.security.MessageDigest

/**
 * Firebase-backed lockout system.
 * Stored in Firestore — persists through app clear, uninstall, reinstall.
 *
 * Collections:
 *   lockouts/{emailHash}            ← pre-login (email/password attempts)
 *   users/{uid}/security/lockout    ← post-login (PIN, master password, fingerprint)
 *
 * Lockout durations:
 *   Sign-in password   : 5 wrong → 24h
 *   Master password    : 5 wrong → 24h
 *   App PIN            : 5 wrong → 24h
 *   Fingerprint        : 10 wrong → 24h
 */
object LockoutManager {

    private val db get() = FirebaseFirestore.getInstance()

    const val MAX_PW_ATTEMPTS          = 5
    const val MAX_PIN_ATTEMPTS         = 5
    const val MAX_FINGERPRINT_ATTEMPTS = 10
    const val LOCKOUT_DURATION_MS      = 24L * 60 * 60 * 1000  // 24 hours

    enum class LockType { SIGN_IN, MASTER_PASSWORD, PIN, FINGERPRINT }

    data class LockStatus(
        val isLocked: Boolean,
        val remainingMs: Long = 0L,
        val attempts: Int = 0
    ) {
        fun remainingHours(): String {
            val h = remainingMs / 3600_000
            val m = (remainingMs % 3600_000) / 60_000
            return if (h > 0) "${h}h ${m}m" else "${m}m"
        }
    }

    // ── Pre-login lockout (email-based, no userId) ────────────────────────────

    suspend fun checkSignInLock(email: String): LockStatus {
        return checkLock(signInDocRef(email))
    }

    suspend fun recordFailedSignIn(email: String): LockStatus {
        return recordFailure(signInDocRef(email), MAX_PW_ATTEMPTS)
    }

    suspend fun clearSignInLock(email: String) {
        clearLock(signInDocRef(email))
    }

    // ── Post-login lockout (userId-based) ─────────────────────────────────────

    suspend fun checkLock(userId: String, type: LockType): LockStatus {
        return checkLock(userLockDocRef(userId, type))
    }

    suspend fun recordFailure(userId: String, type: LockType): LockStatus {
        val max = when (type) {
            LockType.FINGERPRINT -> MAX_FINGERPRINT_ATTEMPTS
            else -> MAX_PW_ATTEMPTS
        }
        return recordFailure(userLockDocRef(userId, type), max)
    }

    suspend fun clearLock(userId: String, type: LockType) {
        clearLock(userLockDocRef(userId, type))
    }

    // ── Core logic ────────────────────────────────────────────────────────────

    private suspend fun checkLock(docRef: com.google.firebase.firestore.DocumentReference): LockStatus {
        return try {
            val doc = docRef.get().await()
            if (!doc.exists()) return LockStatus(false, 0L, 0)

            val attempts  = doc.getLong("attempts")?.toInt() ?: 0
            val lockedAt  = doc.getLong("lockedAt") ?: 0L
            val maxAttempts = doc.getLong("maxAttempts")?.toInt() ?: MAX_PW_ATTEMPTS

            if (lockedAt == 0L || attempts < maxAttempts) {
                return LockStatus(false, 0L, attempts)
            }

            val elapsed   = System.currentTimeMillis() - lockedAt
            val remaining = LOCKOUT_DURATION_MS - elapsed

            if (remaining <= 0) {
                // Lockout expired — auto-clear
                clearLock(docRef)
                LockStatus(false, 0L, 0)
            } else {
                LockStatus(true, remaining, attempts)
            }
        } catch (e: Exception) {
            LockStatus(false) // Fail open — don't lock out on network error
        }
    }

    private suspend fun recordFailure(
        docRef: com.google.firebase.firestore.DocumentReference,
        maxAttempts: Int
    ): LockStatus {
        return try {
            val doc      = docRef.get().await()
            val attempts = (doc.getLong("attempts") ?: 0L).toInt() + 1
            val lockedAt = if (attempts >= maxAttempts) System.currentTimeMillis() else 0L

            docRef.set(mapOf(
                "attempts"    to attempts,
                "lockedAt"    to lockedAt,
                "maxAttempts" to maxAttempts,
                "updatedAt"   to System.currentTimeMillis()
            )).await()

            if (attempts >= maxAttempts) {
                LockStatus(true, LOCKOUT_DURATION_MS, attempts)
            } else {
                LockStatus(false, 0L, attempts)
            }
        } catch (e: Exception) {
            LockStatus(false)
        }
    }

    private suspend fun clearLock(docRef: com.google.firebase.firestore.DocumentReference) {
        try { docRef.delete().await() } catch (_: Exception) {}
    }

    // ── Document references ───────────────────────────────────────────────────

    private fun signInDocRef(email: String) =
        db.collection("lockouts").document(hashEmail(email))

    private fun userLockDocRef(userId: String, type: LockType) =
        db.collection("users").document(userId)
            .collection("security").document(type.name.lowercase())

    private fun hashEmail(email: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(email.lowercase().trim().toByteArray())
        return Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.URL_SAFE)
            .replace("=", "").take(40)
    }
}
