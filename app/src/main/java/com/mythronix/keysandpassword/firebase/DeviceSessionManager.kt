package com.mythronix.keysandpassword.firebase

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await
import java.text.SimpleDateFormat
import java.util.*

data class DeviceSession(
    val sessionId: String = "",
    val deviceName: String = "",
    val model: String = "",
    val osVersion: String = "",
    val lastSeen: Long = 0L,
    val isCurrentDevice: Boolean = false
) {
    fun lastSeenFormatted(): String {
        val sdf = SimpleDateFormat("MMM dd, yyyy  HH:mm", Locale.getDefault())
        return sdf.format(Date(lastSeen))
    }
}

object DeviceSessionManager {

    private val db get() = FirebaseFirestore.getInstance()

    /** Record this device login in Firestore. Called on successful unlock. */
    suspend fun recordSession(context: Context, userId: String) {
        try {
            val sessionId = getDeviceId(context)
            val deviceName = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
            val osVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"

            db.collection("users").document(userId)
                .collection("sessions").document(sessionId)
                .set(mapOf(
                    "sessionId"  to sessionId,
                    "deviceName" to deviceName,
                    "model"      to deviceName,
                    "osVersion"  to osVersion,
                    "lastSeen"   to System.currentTimeMillis()
                )).await()
        } catch (_: Exception) { /* non-critical */ }
    }

    /** Fetch all sessions for this user. */
    suspend fun getSessions(context: Context, userId: String): List<DeviceSession> {
        return try {
            val currentId = getDeviceId(context)
            db.collection("users").document(userId)
                .collection("sessions")
                .orderBy("lastSeen", com.google.firebase.firestore.Query.Direction.DESCENDING)
                .get().await()
                .documents.mapNotNull { doc ->
                    DeviceSession(
                        sessionId       = doc.id,
                        deviceName      = doc.getString("deviceName") ?: "Unknown Device",
                        model           = doc.getString("model") ?: "",
                        osVersion       = doc.getString("osVersion") ?: "",
                        lastSeen        = doc.getLong("lastSeen") ?: 0L,
                        isCurrentDevice = doc.id == currentId
                    )
                }
        } catch (e: Exception) { emptyList() }
    }

    /** Remove a specific device session. */
    suspend fun removeSession(userId: String, sessionId: String) {
        db.collection("users").document(userId)
            .collection("sessions").document(sessionId).delete().await()
    }

    private fun getDeviceId(context: Context): String {
        val raw = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        return raw ?: Build.FINGERPRINT.take(16)
    }
}
