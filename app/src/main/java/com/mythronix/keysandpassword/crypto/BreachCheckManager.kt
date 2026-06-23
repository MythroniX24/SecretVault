package com.mythronix.keysandpassword.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.security.MessageDigest

/**
 * HaveIBeenPwned API — k-anonymity model.
 * Only first 5 chars of SHA1 hash are sent. Password never leaves device.
 */
object BreachCheckManager {

    suspend fun checkPassword(password: String): Result<Int> = withContext(Dispatchers.IO) {
        try {
            val sha1 = sha1Hex(password).uppercase()
            val prefix = sha1.take(5)
            val suffix = sha1.drop(5)

            val conn = URL("https://api.pwnedpasswords.com/range/$prefix").openConnection()
            conn.setRequestProperty("User-Agent", "SecureVault-Android")
            conn.connectTimeout = 8000
            conn.readTimeout    = 8000

            val response = conn.getInputStream().bufferedReader().readText()

            // Parse response: each line is "HASH_SUFFIX:COUNT"
            val count = response.lines()
                .firstOrNull { it.startsWith(suffix, ignoreCase = true) }
                ?.split(":")
                ?.getOrNull(1)
                ?.trim()
                ?.toIntOrNull() ?: 0

            Result.success(count)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun sha1Hex(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-1")
            .digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02X".format(it) }
    }
}
