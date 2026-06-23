# Secure Vault ProGuard / R8 Rules

# Keep data classes for JSON serialization (Gson / manual JSON)
-keepclassmembers class com.mythronix.keysandpassword.models.** { *; }

# Keep CryptoManager (no reflection, but safe to keep)
-keep class com.mythronix.keysandpassword.crypto.** { *; }

# Keep Argon2Kt native methods
-keep class com.lambdapioneer.argon2kt.** { *; }

# Keep Kotlin Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# Keep AndroidX Security
-keep class androidx.security.crypto.** { *; }

# Keep Biometric
-keep class androidx.biometric.** { *; }

# General Android rules
-keepattributes *Annotation*, Signature, Exception, InnerClasses, EnclosingMethod
-keepattributes SourceFile, LineNumberTable

# Keep enum classes
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Remove logging in release
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
}
