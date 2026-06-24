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
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
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
    private var selectedCategory: String? = null  // null = All
    private var clipboardHandler: Handler? = null
    private var categoriesExpanded = true

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
        setupCategoryChips()
        loadVaultItems()
        updateChipVisibility()
    }

    override fun onResume() {
        super.onResume()
        if (!VaultSession.isUnlocked()) { goToLock(); return }
        loadVaultItems()
    }

    override fun onDestroy() {
        super.onDestroy()
        clipboardHandler?.removeCallbacksAndMessages(null)
    }

    private fun setupRecyclerView() {
        adapter = VaultAdapter(
            onItemClick = { showItemDetail(it) },
            onItemLongClick = { showDeleteDialog(it) },
            onFavoriteClick = { toggleFavorite(it) }
        )
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

    private fun setupCategoryChips() {
        binding.chipGroupCategories.removeAllViews()
        // "All" chip
        val allChip = Chip(this).apply {
            text = "All"
            isCheckable = true
            isChecked = true
            setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) { selectedCategory = null; filterItems(binding.etSearch.text.toString()) }
            }
        }
        binding.chipGroupCategories.addView(allChip)

        // Category chips
        for (cat in VaultItem.ALL_CATEGORIES) {
            val chip = Chip(this).apply {
                text = cat
                isCheckable = true
                setOnCheckedChangeListener { _, isChecked ->
                    if (isChecked) { selectedCategory = cat; filterItems(binding.etSearch.text.toString()) }
                }
            }
            binding.chipGroupCategories.addView(chip)
        }

        // Single selection behavior
        binding.chipGroupCategories.isSingleSelection = true

        // Filter toggle button — collapse resets to "All"
        binding.btnFilter.setOnClickListener {
            categoriesExpanded = !categoriesExpanded
            if (!categoriesExpanded) {
                selectedCategory = null
                filterItems(binding.etSearch.text.toString())
            }
            updateChipVisibility()
        }
    }

    private fun updateChipVisibility() {
        val hasItems = allItems.isNotEmpty()
        if (hasItems && categoriesExpanded) {
            binding.chipGroupCategories.visibility = View.VISIBLE
            binding.btnFilter.alpha = 1.0f
        } else {
            binding.chipGroupCategories.visibility = View.GONE
            binding.btnFilter.alpha = if (hasItems) 0.5f else 0.3f
        }
    }

    private fun filterItems(query: String) {
        var filtered = allItems

        // Apply category filter
        if (selectedCategory != null) {
            filtered = filtered.filter { it.category == selectedCategory }
        }

        // Apply search filter
        if (query.isNotBlank()) {
            filtered = filtered.filter { it.name.contains(query, ignoreCase = true) }
        }

        adapter.submitFullList(filtered)
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
                filterItems(binding.etSearch.text.toString())
                updateChipVisibility()
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
        // Don't hide chips when filter is empty — only hide when vault has no items
        // Chip visibility is managed by updateChipVisibility()
    }

    // ── Favorite Toggle ───────────────────────────────────────────────────────

    private fun toggleFavorite(item: VaultItem) {
        lifecycleScope.launch {
            try {
                val userId = VaultSession.getUserId() ?: return@launch
                val updated = item.copy(isFavorite = !item.isFavorite)
                withContext(Dispatchers.IO) {
                    OfflineVaultStore.saveItem(this@VaultActivity, userId, updated)
                }
                loadVaultItems()
                showSnack(if (updated.isFavorite) "⭐ Pinned to top" else "Unpinned")
            } catch (_: Exception) { showSnack("Failed to update") }
        }
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

        // Cancel previous clear timer
        clipboardHandler?.removeCallbacksAndMessages(null)
        clipboardHandler = Handler(Looper.getMainLooper())

        val clipboardClearEnabled = getSharedPreferences("sv_settings", MODE_PRIVATE)
            .getBoolean("clipboard_auto_clear", true)

        if (clipboardClearEnabled) {
            clipboardHandler?.postDelayed({
                runCatching { cb.setPrimaryClip(ClipData.newPlainText("", "")) }
            }, 30_000L)
        }
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
