package com.mythronix.keysandpassword.firebase

import com.google.firebase.firestore.FirebaseFirestore
import com.mythronix.keysandpassword.models.VaultItem
import kotlinx.coroutines.tasks.await

object FirestoreManager {

    private val db: FirebaseFirestore get() = FirebaseFirestore.getInstance()

    // ── Salt ──────────────────────────────────────────────────────────────────
    suspend fun saveSalt(userId: String, saltBase64: String) {
        db.collection("users").document(userId).set(mapOf("salt" to saltBase64)).await()
    }
    suspend fun getSalt(userId: String): String? =
        db.collection("users").document(userId).get().await().getString("salt")

    // ── Password Verifier ─────────────────────────────────────────────────────

    /**
     * Save PBKDF2 password verifier alongside Argon2 salt.
     * Verifier = PBKDF2-SHA256(password, verifierSalt, 100k iter)
     * NOT the encryption key — used only to quickly reject wrong passwords.
     */
    suspend fun saveVerifier(userId: String, verifierHash: String, verifierSaltB64: String) {
        try {
            db.collection("users").document(userId)
                .update(mapOf(
                    "verifierHash" to verifierHash,
                    "verifierSalt" to verifierSaltB64
                )).await()
        } catch (_: Exception) {
            // Document may not exist yet on first login - use set with merge
            db.collection("users").document(userId)
                .set(mapOf(
                    "verifierHash" to verifierHash,
                    "verifierSalt" to verifierSaltB64
                ), com.google.firebase.firestore.SetOptions.merge()).await()
        }
    }

    data class VerifierData(val hash: String, val saltB64: String)

    suspend fun getVerifier(userId: String): VerifierData? {
        return try {
            val doc     = db.collection("users").document(userId).get().await()
            val hash    = doc.getString("verifierHash") ?: return null
            val saltB64 = doc.getString("verifierSalt") ?: return null
            VerifierData(hash, saltB64)
        } catch (_: Exception) { null }
    }

    // ── Vault Items ───────────────────────────────────────────────────────────
    suspend fun saveVaultItem(userId: String, item: VaultItem): String {
        val col = db.collection("users").document(userId).collection("vault")
        val doc = if (item.id.isBlank()) col.document() else col.document(item.id)
        doc.set(item.toMap()).await()
        return doc.id
    }

    suspend fun getVaultItems(userId: String): List<VaultItem> =
        db.collection("users").document(userId).collection("vault")
            .orderBy("createdAt", com.google.firebase.firestore.Query.Direction.DESCENDING)
            .get().await().documents.mapNotNull { doc ->
                VaultItem(
                    id            = doc.id,
                    type          = doc.getString("type") ?: VaultItem.TYPE_PASSWORD,
                    name          = doc.getString("name") ?: "",
                    encryptedData = doc.getString("encryptedData") ?: return@mapNotNull null,
                    iv            = doc.getString("iv") ?: return@mapNotNull null,
                    hmac          = doc.getString("hmac") ?: "",
                    aadVersion    = doc.getString("aadVersion") ?: VaultItem.AAD_LEGACY,
                    createdAt     = doc.getLong("createdAt") ?: 0L
                )
            }

    suspend fun deleteVaultItem(userId: String, itemId: String) {
        db.collection("users").document(userId).collection("vault").document(itemId).delete().await()
    }

    suspend fun deleteAllUserData(userId: String) {
        val userRef      = db.collection("users").document(userId)
        val subcollections = listOf("vault", "sessions", "security")
        for (sub in subcollections) {
            val docs = try { userRef.collection(sub).get().await() } catch (_: Exception) { continue }
            if (docs.isEmpty) continue
            docs.documents.chunked(499).forEach { chunk ->
                val batch = db.batch()
                chunk.forEach { batch.delete(it.reference) }
                batch.commit().await()
            }
        }
        try { userRef.delete().await() } catch (_: Exception) {}
    }

    suspend fun replaceAllVaultItems(userId: String, items: List<VaultItem>) {
        val col = db.collection("users").document(userId).collection("vault")
        val existing = try { col.get().await() } catch (_: Exception) { null }
        existing?.documents?.chunked(499)?.forEach { chunk ->
            val batch = db.batch()
            chunk.forEach { batch.delete(it.reference) }
            batch.commit().await()
        }
        items.chunked(499).forEach { chunk ->
            val batch = db.batch()
            chunk.forEach { item ->
                val ref = if (item.id.isBlank()) col.document() else col.document(item.id)
                batch.set(ref, item.toMap())
            }
            batch.commit().await()
        }
    }
}
