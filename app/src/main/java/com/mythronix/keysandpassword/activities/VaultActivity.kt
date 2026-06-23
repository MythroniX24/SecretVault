package com.mythronix.keysandpassword.activities

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.WindowManager
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.mythronix.keysandpassword.R
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.databinding.ActivityVaultBinding
import com.mythronix.keysandpassword.models.PasswordPayload
import com.mythronix.keysandpassword.models.TokenPayload
import com.mythronix.keysandpassword.models.VaultItem
import com.mythronix.keysandpassword.offline.OfflineVaultStore
import com.mythronix.keysandpassword.ui.VaultAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VaultActivity : AppCompatActivity() {

    private lateinit var binding: ActivityVaultBinding
    private lateinit var adapter: VaultAdapter
    private var allItems: List<VaultItem> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (!VaultSession.isUnlocked()) { goToLock(); return }
        binding = ActivityVaultBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        setupRecyclerView()
        binding.fab.setOnClickListener { startActivity(Intent(this, AddEditActivity::class.java)) }
        setupSearch()
        loadVaultItems()
    }

    override fun onResume() {
        super.onResume()
        if (!VaultSession.isUnlocked()) { goToLock(); return }
        loadVaultItems()
    }

    private fun setupRecyclerView() {
        adapter = VaultAdapter(onItemClick = { showItemDetail(it) }, onItemLongClick = { showDeleteDialog(it) })
        binding.rvVault.layoutManager = androidx.recyclerview.widget.LinearLayoutManager(this)
        binding.rvVault.adapter = adapter
    }

    private fun setupSearch() {
        binding.etSearch.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { filterItems(s.toString()) }
            override fun afterTextChanged(s: android.text.Editable?) {}
        })
    }

    private fun filterItems(query: String) {
        val filtered = if (query.isBlank()) allItems
        else allItems.filter { it.name.contains(query, ignoreCase = true) }
        adapter.submitList(filtered)
        updateEmptyState(filtered.isEmpty())
    }

    private fun loadVaultItems() {
        binding.progressBar.visibility = View.VISIBLE
        lifecycleScope.launch {
            try {
                val userId = VaultSession.getUserId() ?: run {
                    binding.progressBar.visibility = View.GONE
                    goToLock(); return@launch
                }
                allItems = withContext(Dispatchers.IO) {
                    OfflineVaultStore.listItems(this@VaultActivity, userId)
                }
                adapter.submitList(allItems)
                updateEmptyState(allItems.isEmpty())
                binding.chipCount.visibility = if (allItems.isNotEmpty()) View.VISIBLE else View.GONE
                binding.chipCount.text = "${allItems.size} item${if (allItems.size != 1) "s" else ""}"
            } catch (e: Exception) {
                showSnack("Could not load vault: ${e.message}")
            } finally {
                binding.progressBar.visibility = View.GONE
            }
        }
    }

    private fun updateEmptyState(empty: Boolean) {
        binding.tvEmpty.visibility = if (empty) View.VISIBLE else View.GONE
        binding.rvVault.visibility = if (empty) View.GONE else View.VISIBLE
    }

    // ── Decrypt & show ────────────────────────────────────────────────────────

    private fun showItemDetail(item: VaultItem) {
        val key    = VaultSession.getKey() ?: run { goToLock(); return }
        val userId = VaultSession.getUserId() ?: run { goToLock(); return }
        try {
            val plainJson = CryptoManager.decrypt(item.encryptedData, item.iv, key, userId, item.id, item.type)
            if (item.type == VaultItem.TYPE_PASSWORD) showPasswordDetail(item, PasswordPayload.fromJson(plainJson))
            else showTokenDetail(item, TokenPayload.fromJson(plainJson))
        } catch (_: javax.crypto.AEADBadTagException) {
            showSnack("⚠️ Decryption failed — data may be corrupted or from a different account")
        } catch (e: Exception) {
            showSnack("Could not decrypt entry: ${e.message}")
        }
    }

    private fun showPasswordDetail(item: VaultItem, p: PasswordPayload) {
        val view = layoutInflater.inflate(R.layout.dialog_item_detail, null)
        view.findViewById<TextView>(R.id.tvField1Label).text = "Email / Username"
        view.findViewById<TextView>(R.id.tvField1Value).text = p.emailOrUsername.ifEmpty { "—" }
        view.findViewById<TextView>(R.id.tvField2Label).text = "Password"
        view.findViewById<TextView>(R.id.tvField2Value).text = p.password
        showNotesInDialog(view, p.notes)

        MaterialAlertDialogBuilder(this).setTitle(item.name).setView(view)
            .setPositiveButton("Copy Password") { _, _ -> copyToClipboard(p.password, "Password") }
            .setNeutralButton("Edit") { _, _ ->
                startActivity(Intent(this, AddEditActivity::class.java)
                    .putExtra(AddEditActivity.EXTRA_ITEM_ID, item.id))
            }
            .setNegativeButton("Close", null).show()
    }

    private fun showTokenDetail(item: VaultItem, t: TokenPayload) {
        val view = layoutInflater.inflate(R.layout.dialog_item_detail, null)
        view.findViewById<TextView>(R.id.tvField1Label).text = "Service"
        view.findViewById<TextView>(R.id.tvField1Value).text = item.name
        view.findViewById<TextView>(R.id.tvField2Label).text = "Token"
        view.findViewById<TextView>(R.id.tvField2Value).text = t.token
        showNotesInDialog(view, t.notes)

        MaterialAlertDialogBuilder(this).setTitle("API Token").setView(view)
            .setPositiveButton("Copy Token") { _, _ -> copyToClipboard(t.token, "Token") }
            .setNeutralButton("Edit") { _, _ ->
                startActivity(Intent(this, AddEditActivity::class.java)
                    .putExtra(AddEditActivity.EXTRA_ITEM_ID, item.id))
            }
            .setNegativeButton("Close", null).show()
    }

    private fun showNotesInDialog(view: View, notes: String) {
        if (notes.isNotEmpty()) {
            view.findViewById<View>(R.id.dividerNotes).visibility = View.VISIBLE
            view.findViewById<TextView>(R.id.tvNotesLabel).visibility = View.VISIBLE
            view.findViewById<TextView>(R.id.tvNotesValue).apply { text = notes; visibility = View.VISIBLE }
        }
    }

    private fun copyToClipboard(text: String, label: String) {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cb.setPrimaryClip(ClipData.newPlainText("Secure Vault", text))
        showSnack("$label copied — clears in 30s")
        Handler(Looper.getMainLooper()).postDelayed({
            runCatching { cb.setPrimaryClip(ClipData.newPlainText("", "")) }
        }, 30_000L)
    }

    private fun showDeleteDialog(item: VaultItem) {
        MaterialAlertDialogBuilder(this)
            .setTitle("Delete \"${item.name}\"?")
            .setMessage("This permanently removes the entry. Cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    try {
                        val userId = VaultSession.getUserId() ?: return@launch
                        withContext(Dispatchers.IO) {
                            OfflineVaultStore.deleteItem(this@VaultActivity, userId, item.id)
                        }
                        loadVaultItems()
                        showSnack("Entry deleted")
                    } catch (_: Exception) { showSnack("Delete failed") }
                }
            }
            .setNegativeButton("Cancel", null).show()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean { menuInflater.inflate(R.menu.menu_vault, menu); return true }
    override fun onOptionsItemSelected(item: MenuItem) = when (item.itemId) {
        R.id.action_settings -> { startActivity(Intent(this, SettingsActivity::class.java)); true }
        R.id.action_lock     -> { VaultSession.lock(); goToLock(); true }
        else -> super.onOptionsItemSelected(item)
    }

    private fun goToLock() { startActivity(Intent(this, LockActivity::class.java)); finish() }
    private fun showSnack(msg: String) = Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()
}
