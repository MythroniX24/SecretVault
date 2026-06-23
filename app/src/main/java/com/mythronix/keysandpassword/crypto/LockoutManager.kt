package com.mythronix.keysandpassword.crypto

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest

/**
 * Local lockout system — uses SharedPreferences instead of Firestore.
 *
 * Lockout durations:
 *   Master password    : 5 wrong → 24h
 *   App PIN            : 5 wrong → 24h
 *   Fingerprint        : 10 wrong → 24h
 */
object LockoutManager {

    private const val PREFS_NAME = "sv_lockout"
    private const val MAX_PW_ATTEMPTS          = 5
    private const val MAX_PIN_ATTEMPTS         = 5
    private const val MAX_FINGERPRINT_ATTEMPTS = 10
    const val LOCKOUT_DURATION_MS              = 24L * 60 * 60 * 1000  // 24 hours

    enum class LockType { MASTER_PASSWORD, PIN, FINGERPRINT }

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

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun key(accountId: String, type: LockType): String =
        "lockout_${hashAccount(accountId)}_${type.name.lowercase()}"

    private fun hashAccount(accountId: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(accountId.trim().toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }.take(20)
    }

    // ── Check lock status ────────────────────────────────────────────────────

    fun checkLock(ctx: Context, accountId: String, type: LockType): LockStatus {
        val p = prefs(ctx)
        val k = key(accountId, type)
        if (!p.contains("${k}_attempts")) return LockStatus(false, 0L, 0)

        val attempts  = p.getInt("${k}_attempts", 0)
        val lockedAt  = p.getLong("${k}_lockedAt", 0L)
        val maxAttempts = when (type) {
            LockType.FINGERPRINT -> MAX_FINGERPRINT_ATTEMPTS
            else -> MAX_PW_ATTEMPTS
        }

        if (lockedAt == 0L || attempts < maxAttempts) {
            return LockStatus(false, 0L, attempts)
        }

        val elapsed   = System.currentTimeMillis() - lockedAt
        val remaining = LOCKOUT_DURATION_MS - elapsed

        if (remaining <= 0) {
            // Lockout expired — auto-clear
            clearLock(ctx, accountId, type)
            return LockStatus(false, 0L, 0)
        }
        return LockStatus(true, remaining, attempts)
    }

    // ── Record failure ────────────────────────────────────────────────────────

    fun recordFailure(ctx: Context, accountId: String, type: LockType): LockStatus {
        val p = prefs(ctx)
        val k = key(accountId, type)
        val maxAttempts = when (type) {
            LockType.FINGERPRINT -> MAX_FINGERPRINT_ATTEMPTS
            else -> MAX_PW_ATTEMPTS
        }

        val attempts = p.getInt("${k}_attempts", 0) + 1
        val lockedAt = if (attempts >= maxAttempts) System.currentTimeMillis() else 0L

        p.edit()
            .putInt("${k}_attempts", attempts)
            .putLong("${k}_lockedAt", lockedAt)
            .putInt("${k}_max", maxAttempts)
            .putLong("${k}_updatedAt", System.currentTimeMillis())
            .apply()

        return if (attempts >= maxAttempts) {
            LockStatus(true, LOCKOUT_DURATION_MS, attempts)
        } else {
            LockStatus(false, 0L, attempts)
        }
    }

    // ── Clear lock ────────────────────────────────────────────────────────────

    fun clearLock(ctx: Context, accountId: String, type: LockType) {
        val p = prefs(ctx)
        val k = key(accountId, type)
        p.edit()
            .remove("${k}_attempts")
            .remove("${k}_lockedAt")
            .remove("${k}_max")
            .remove("${k}_updatedAt")
            .apply()
    }
}
