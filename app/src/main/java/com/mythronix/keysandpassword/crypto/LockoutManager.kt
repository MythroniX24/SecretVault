package com.mythronix.keysandpassword.crypto

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest

/**
 * Local lockout system with configurable duration.
 *
 * Lockout durations (default 24h for all types):
 *   Master password    : 5 wrong → configurable lock
 *   App PIN            : 5 wrong → configurable lock
 *   Fingerprint        : 10 wrong → configurable lock
 *
 * User can configure:
 *   - Max attempts (3-10) — applies to all lock types
 *   - Lock duration (0=1h, 1=6h, 2=12h, 3=18h, 4=24h)
 */
object LockoutManager {

    private const val PREFS_NAME = "sv_lockout"

    // Defaults
    private const val DEFAULT_MAX_ATTEMPTS = 5
    private const val DEFAULT_FINGERPRINT_ATTEMPTS = 10

    // Duration presets indexed by slider value (0-4)
    private val DURATION_PRESETS = longArrayOf(
        1L * 60 * 60 * 1000,    // 0 → 1 hour
        6L * 60 * 60 * 1000,    // 1 → 6 hours
        12L * 60 * 60 * 1000,   // 2 → 12 hours
        18L * 60 * 60 * 1000,   // 3 → 18 hours
        24L * 60 * 60 * 1000    // 4 → 24 hours (default)
    )
    private const val DEFAULT_DURATION_INDEX = 4  // 24h

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

    // ── Configuration helpers ─────────────────────────────────────────────────

    private fun configPrefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences("sv_lockout_config", Context.MODE_PRIVATE)

    fun getMaxAttempts(ctx: Context): Int =
        configPrefs(ctx).getInt("max_attempts", DEFAULT_MAX_ATTEMPTS)
            .coerceIn(3, 10)

    fun setMaxAttempts(ctx: Context, value: Int) {
        configPrefs(ctx).edit().putInt("max_attempts", value.coerceIn(3, 10)).apply()
    }

    fun getDurationIndex(ctx: Context): Int =
        configPrefs(ctx).getInt("duration_index", DEFAULT_DURATION_INDEX)
            .coerceIn(0, 4)

    fun setDurationIndex(ctx: Context, index: Int) {
        configPrefs(ctx).edit().putInt("duration_index", index.coerceIn(0, 4)).apply()
    }

    fun getLockDurationMs(ctx: Context): Long {
        val idx = getDurationIndex(ctx)
        return DURATION_PRESETS[idx.coerceIn(0, 4)]
    }

    fun getDurationLabel(index: Int): String = when (index) {
        0 -> "1 hour"
        1 -> "6 hours"
        2 -> "12 hours"
        3 -> "18 hours"
        4 -> "24 hours"
        else -> "24 hours"
    }

    fun getDurationLabels(): List<String> = DURATION_PRESETS.indices.map { getDurationLabel(it) }

    // ── Lockout storage ───────────────────────────────────────────────────────

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
        val maxAttempts = if (type == LockType.FINGERPRINT) DEFAULT_FINGERPRINT_ATTEMPTS
                          else getMaxAttempts(ctx)
        val duration  = getLockDurationMs(ctx)

        if (lockedAt == 0L || attempts < maxAttempts) {
            return LockStatus(false, 0L, attempts)
        }

        val elapsed   = System.currentTimeMillis() - lockedAt
        val remaining = duration - elapsed

        if (remaining <= 0) {
            clearLock(ctx, accountId, type)
            return LockStatus(false, 0L, 0)
        }
        return LockStatus(true, remaining, attempts)
    }

    // ── Record failure ────────────────────────────────────────────────────────

    fun recordFailure(ctx: Context, accountId: String, type: LockType): LockStatus {
        val p = prefs(ctx)
        val k = key(accountId, type)
        val maxAttempts = if (type == LockType.FINGERPRINT) DEFAULT_FINGERPRINT_ATTEMPTS
                          else getMaxAttempts(ctx)
        val duration = getLockDurationMs(ctx)

        val attempts = p.getInt("${k}_attempts", 0) + 1
        val lockedAt = if (attempts >= maxAttempts) System.currentTimeMillis() else 0L

        p.edit()
            .putInt("${k}_attempts", attempts)
            .putLong("${k}_lockedAt", lockedAt)
            .putInt("${k}_max", maxAttempts)
            .putLong("${k}_updatedAt", System.currentTimeMillis())
            .apply()

        return if (attempts >= maxAttempts) {
            LockStatus(true, duration, attempts)
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

    /** Clear ALL lockout data (all types) */
    fun clearAll(ctx: Context) {
        prefs(ctx).edit().clear().apply()
    }

    // ── Fingerprint attempts ──────────────────────────────────────────────────

    fun getFingerprintMaxAttempts(): Int = DEFAULT_FINGERPRINT_ATTEMPTS
}
