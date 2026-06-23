package com.mythronix.keysandpassword.models

/**
 * Firestore path: users/{userId}/vault/{itemId}
 *
 * Plaintext fields stored in Firestore (non-sensitive):
 *   type, name, createdAt
 *   Note: "name" is metadata — consider encrypting if privacy matters.
 *         For now it lets users search without decrypting.
 *
 * Encrypted with AES-256-GCM + AAD binding:
 *   encryptedData : Base64(ciphertext + 128-bit GCM auth tag)
 *   iv            : Base64(12-byte random IV)
 *   aadVersion    : "sv1" — format version tag for future migration
 *
 * hmac field removed — redundant with GCM authentication tag.
 * AAD now provides ciphertext-to-identity binding.
 */
data class VaultItem(
    val id: String = "",
    val type: String = TYPE_PASSWORD,
    val name: String = "",
    val encryptedData: String = "",
    val iv: String = "",
    val hmac: String = "",           // kept for legacy compat; not written in new items
    val aadVersion: String = "sv1",  // "legacy" = pre-AAD items, "sv1" = current
    val createdAt: Long = System.currentTimeMillis(),
    val category: String = CATEGORY_UNCATEGORIZED,
    val isFavorite: Boolean = false
) {
    companion object {
        const val TYPE_PASSWORD = "password"
        const val TYPE_TOKEN    = "token"
        const val AAD_VERSION   = "sv1"
        const val AAD_LEGACY    = "legacy"
        const val CATEGORY_UNCATEGORIZED = "Uncategorized"
        const val CATEGORY_LOGIN   = "Login"
        const val CATEGORY_BANKING = "Banking"
        const val CATEGORY_EMAIL   = "Email"
        const val CATEGORY_SOCIAL  = "Social"
        const val CATEGORY_WORK    = "Work"
        const val CATEGORY_OTHER   = "Other"

        val ALL_CATEGORIES = listOf(
            CATEGORY_UNCATEGORIZED, CATEGORY_LOGIN, CATEGORY_BANKING,
            CATEGORY_EMAIL, CATEGORY_SOCIAL, CATEGORY_WORK, CATEGORY_OTHER
        )
    }

    val isLegacy: Boolean get() = aadVersion == AAD_LEGACY || aadVersion.isEmpty()

    fun toMap(): Map<String, Any> = mapOf(
        "type"          to type,
        "name"          to name,
        "encryptedData" to encryptedData,
        "iv"            to iv,
        "aadVersion"    to aadVersion,
        "createdAt"     to createdAt,
        "category"      to category,
        "isFavorite"    to isFavorite
    )
}

data class PasswordPayload(
    val emailOrUsername: String,
    val password: String,
    val notes: String = ""
) {
    fun toJson(): String = """{"e":"${esc(emailOrUsername)}","p":"${esc(password)}","n":"${esc(notes)}"}"""
    companion object {
        private fun esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")
        private fun String.unesc() = replace("\\\"", "\"").replace("\\\\", "\\")
        fun fromJson(json: String): PasswordPayload {
            val e = Regex(""""e":"((?:[^"\\]|\\.)*)"""").find(json)?.groupValues?.get(1)?.unesc() ?: ""
            val p = Regex(""""p":"((?:[^"\\]|\\.)*)"""").find(json)?.groupValues?.get(1)?.unesc() ?: ""
            val n = Regex(""""n":"((?:[^"\\]|\\.)*)"""").find(json)?.groupValues?.get(1)?.unesc() ?: ""
            return PasswordPayload(e, p, n)
        }
    }
}

data class TokenPayload(val token: String, val notes: String = "") {
    fun toJson(): String = """{"t":"${esc(token)}","n":"${esc(notes)}"}"""
    companion object {
        private fun esc(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"")
        private fun String.unesc() = replace("\\\"", "\"").replace("\\\\", "\\")
        fun fromJson(json: String): TokenPayload {
            val t = Regex(""""t":"((?:[^"\\]|\\.)*)"""").find(json)?.groupValues?.get(1)?.unesc() ?: ""
            val n = Regex(""""n":"((?:[^"\\]|\\.)*)"""").find(json)?.groupValues?.get(1)?.unesc() ?: ""
            return TokenPayload(t, n)
        }
    }
}
