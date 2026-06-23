# ── Secure Vault ProGuard / R8 Rules ─────────────────────────────────────────

# Firebase
-keep class com.google.firebase.** { *; }
-keep class com.google.android.gms.** { *; }

# Data models for Firestore
-keep class com.mythronix.keysandpassword.models.** { *; }

# Crypto classes (needed for reflection-based JNI in Argon2)
-keep class com.mythronix.keysandpassword.crypto.** { *; }
-keep class com.lambdapioneer.argon2kt.** { *; }

# AndroidX Biometric
-keep class androidx.biometric.** { *; }

# EncryptedSharedPreferences / Security
-keep class androidx.security.crypto.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.** { volatile <fields>; }

# Obfuscate everything else aggressively
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# ── CRITICAL: Strip ALL logging in release ────────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
    public static java.lang.String getStackTraceString(...);
}

# Strip Kotlin logging too
-assumenosideeffects class kotlin.io.ConsoleKt {
    public static void println(...);
    public static void print(...);
}

# ── Anti-reverse-engineering: aggressive obfuscation ─────────────────────────
-repackageclasses 'a'           # Move all classes to package 'a'
-allowaccessmodification        # Allow access modifier changes for better obfuscation
-adaptclassstrings              # Rewrite class name strings too
-overloadaggressively           # Reuse method names where possible
