package com.mythronix.keysandpassword.crypto

object PasswordStrengthUtil {

    enum class Strength(val label: String, val score: Int) {
        VERY_WEAK("Very Weak", 0),
        WEAK("Weak", 1),
        FAIR("Fair", 2),
        STRONG("Strong", 3),
        VERY_STRONG("Very Strong", 4)
    }

    data class StrengthResult(
        val strength: Strength,
        val score: Int,          // 0-100
        val tips: List<String>   // improvement suggestions
    )

    private val COMMON_PATTERNS = listOf(
        "123456", "password", "qwerty", "abc123", "111111",
        "12345678", "letmein", "welcome", "monkey", "dragon",
        "master", "admin", "login", "pass", "test"
    )

    fun evaluate(password: String): StrengthResult {
        if (password.isEmpty()) return StrengthResult(Strength.VERY_WEAK, 0, emptyList())

        var score = 0
        val tips = mutableListOf<String>()

        // Length scoring
        score += when {
            password.length >= 20 -> 30
            password.length >= 16 -> 25
            password.length >= 12 -> 18
            password.length >= 8  -> 10
            else -> 0
        }
        if (password.length < 12) tips.add("Use at least 12 characters")

        // Character variety
        val hasUpper   = password.any { it.isUpperCase() }
        val hasLower   = password.any { it.isLowerCase() }
        val hasDigit   = password.any { it.isDigit() }
        val hasSpecial = password.any { !it.isLetterOrDigit() }

        if (hasUpper)   score += 15 else tips.add("Add uppercase letters (A-Z)")
        if (hasLower)   score += 10
        if (hasDigit)   score += 15 else tips.add("Add numbers (0-9)")
        if (hasSpecial) score += 20 else tips.add("Add symbols (!@#\$%^&*)")

        // Variety bonus
        val varietyCount = listOf(hasUpper, hasLower, hasDigit, hasSpecial).count { it }
        if (varietyCount == 4) score += 10

        // Penalties
        val lower = password.lowercase()
        if (COMMON_PATTERNS.any { lower.contains(it) }) {
            score -= 20
            tips.add("Avoid common words/patterns")
        }

        // Repeated characters penalty
        val hasRepeating = password.zipWithNext().count { (a, b) -> a == b } > 2
        if (hasRepeating) { score -= 10; tips.add("Avoid repeated characters") }

        // Sequential penalty
        val hasSequential = (0 until password.length - 2).any { i ->
            password[i].code + 1 == password[i+1].code && password[i+1].code + 1 == password[i+2].code
        }
        if (hasSequential) score -= 10

        score = score.coerceIn(0, 100)

        val strength = when {
            score >= 80 -> Strength.VERY_STRONG
            score >= 60 -> Strength.STRONG
            score >= 40 -> Strength.FAIR
            score >= 20 -> Strength.WEAK
            else        -> Strength.VERY_WEAK
        }

        return StrengthResult(strength, score, tips.take(2))
    }
}
