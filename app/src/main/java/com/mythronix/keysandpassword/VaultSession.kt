package com.mythronix.keysandpassword

import javax.crypto.SecretKey

/**
 * In-memory session — holds derived AES-256 key ONLY.
 *
 * SECURITY:
 *   • Key is NEVER written to disk, Firebase, logs, or SharedPreferences.
 *   • lock() sets masterKey = null — GC will collect it.
 *   • On Android, apps run in isolated processes; other apps cannot read
 *     this memory (unless device is rooted with Frida/etc).
 *   • App goes background → App.kt calls lock() immediately.
 *   • Every activity's onResume() checks isUnlocked() and redirects.
 */
object VaultSession {

    @Volatile private var masterKey: SecretKey? = null
    @Volatile private var currentUserId: String? = null

    fun setKey(key: SecretKey, userId: String) {
        masterKey     = key
        currentUserId = userId
    }

    fun getKey(): SecretKey? = masterKey
    fun getUserId(): String? = currentUserId
    fun isUnlocked(): Boolean = masterKey != null

    /** Zero out session — called on background, sign-out, and lock. */
    fun lock() {
        masterKey     = null
        currentUserId = null
    }

    /** Full cleanup — also clears userId. Use on sign-out / account delete. */
    fun clearAll() {
        masterKey     = null
        currentUserId = null
    }
}
