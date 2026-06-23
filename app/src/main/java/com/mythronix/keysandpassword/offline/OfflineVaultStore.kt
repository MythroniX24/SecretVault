package com.mythronix.keysandpassword.offline

import android.content.Context
import android.util.Base64
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.models.VaultItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/**
 * Local/offline encrypted vault storage.
 *
 * SECURITY MODEL:
 * - Vault items are encrypted at application level (CryptoManager AES-GCM).
 * - We persist only the encrypted blobs (encryptedData, iv, aadVersion, type, name, createdAt).
 * - No plaintext vault secrets are stored on disk.
 *
 * Account binding:
 * - Uses VaultSession.getUserId() as the AAD userId input (cipher identity binding),
 *   but the stored blobs are already bound to the userId via CryptoManager.decrypt().
 *
 * Note:
 * - "name" is currently stored as plaintext metadata (as in your existing VaultItem model).
 *   If you want name encrypted too, we can extend the payload format later.
 */
object OfflineVaultStore {

    private const val VAULT_FILE = "sv_vault_items.json"

    private fun vaultFile(ctx: Context): File = File(ctx.filesDir, VAULT_FILE)

    suspend fun listItems(ctx: Context, userId: String): List<VaultItem> {
        return withContext(Dispatchers.IO) {
            val f = vaultFile(ctx)
            if (!f.exists()) return@withContext emptyList()

            val json = f.readText()
            if (json.isBlank()) return@withContext emptyList()

            val arr = JSONArray(json)
            (0 until arr.length())
                .mapNotNull { i ->
                    val obj = arr.getJSONObject(i)
                    val storedUserId = obj.optString("userId", "")
                    if (storedUserId != userId) return@mapNotNull null

                    VaultItem(
                        id = obj.optString("id", ""),
                        type = obj.optString("type", VaultItem.TYPE_PASSWORD),
                        name = obj.optString("name", ""),
                        encryptedData = obj.optString("encryptedData", ""),
                        iv = obj.optString("iv", ""),
                        hmac = obj.optString("hmac", ""),
                        aadVersion = obj.optString("aadVersion", VaultItem.AAD_VERSION),
                        createdAt = obj.optLong("createdAt", System.currentTimeMillis())
                    )
                }
                .sortedByDescending { it.createdAt }
        }
    }

    suspend fun saveItem(ctx: Context, userId: String, item: VaultItem): String {
        return withContext(Dispatchers.IO) {
            val current = listItems(ctx, userId).toMutableList()

            val id = if (item.id.isBlank()) UUID.randomUUID().toString() else item.id
            val normalized = item.copy(id = id)

            // Replace if exists
            val idx = current.indexOfFirst { it.id == id }
            if (idx >= 0) current[idx] = normalized else current.add(normalized)

            // Persist merged list for all users (keep file format stable)
            persistAllUsers(ctx, userId, current)
            id
        }
    }

    suspend fun deleteItem(ctx: Context, userId: String, itemId: String) {
        withContext(Dispatchers.IO) {
            val items = listItems(ctx, userId).filterNot { it.id == itemId }
            persistAllUsers(ctx, userId, items)
        }
    }

    suspend fun replaceAllItems(ctx: Context, userId: String, items: List<VaultItem>) {
        withContext(Dispatchers.IO) {
            persistAllUsers(ctx, userId, items)
        }
    }

    suspend fun deleteAllUserData(ctx: Context, userId: String) {
        withContext(Dispatchers.IO) {
            val f = vaultFile(ctx)
            if (!f.exists()) return@withContext

            val json = f.readText()
            if (json.isBlank()) return@withContext

            val arr = JSONArray(json)
            val remaining = JSONArray()
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                if (obj.optString("userId", "") != userId) remaining.put(obj)
            }
            f.writeText(remaining.toString())
        }
    }

    // ── Export / Import ────────────────────────────────────────────────

    /**
     * Export all vault items for a user as a JSON string.
     * Items are already individually encrypted — safe for export.
     */
    suspend fun exportItemsAsJson(ctx: Context, userId: String): String {
        return withContext(Dispatchers.IO) {
            val items = listItems(ctx, userId)
            val arr = JSONArray()
            items.forEach { item ->
                val obj = JSONObject()
                obj.put("id", item.id)
                obj.put("type", item.type)
                obj.put("name", item.name)
                obj.put("encryptedData", item.encryptedData)
                obj.put("iv", item.iv)
                obj.put("hmac", item.hmac)
                obj.put("aadVersion", item.aadVersion)
                obj.put("createdAt", item.createdAt)
                arr.put(obj)
            }
            arr.toString(2)
        }
    }

    private fun persistAllUsers(ctx: Context, userId: String, items: List<VaultItem>) {
        val f = vaultFile(ctx)
        val existing = if (f.exists()) {
            val txt = f.readText()
            if (txt.isBlank()) JSONArray() else JSONArray(txt)
        } else JSONArray()

        val out = JSONArray()
        // Copy all objects except this user, then add updated objects for this user
        for (i in 0 until existing.length()) {
            val obj = existing.getJSONObject(i)
            if (obj.optString("userId", "") != userId) out.put(obj)
        }
        items.forEach { item ->
            val obj = JSONObject()
            obj.put("userId", userId)
            obj.put("id", item.id)
            obj.put("type", item.type)
            obj.put("name", item.name)
            obj.put("encryptedData", item.encryptedData)
            obj.put("iv", item.iv)
            obj.put("hmac", item.hmac)
            obj.put("aadVersion", item.aadVersion)
            obj.put("createdAt", item.createdAt)
            out.put(obj)
        }
        f.parentFile?.mkdirs()
        f.writeText(out.toString())
    }
}
