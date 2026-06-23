package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.view.WindowManager
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.CryptoManager
import com.mythronix.keysandpassword.databinding.ActivityAddEditBinding
import com.mythronix.keysandpassword.models.PasswordPayload
import com.mythronix.keysandpassword.models.TokenPayload
import com.mythronix.keysandpassword.models.VaultItem
import com.mythronix.keysandpassword.offline.OfflineVaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AddEditActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAddEditBinding
    private var editItemId: String? = null
    private var currentType = VaultItem.TYPE_PASSWORD

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (!VaultSession.isUnlocked()) { goToLock(); return }

        binding = ActivityAddEditBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        editItemId = intent.getStringExtra(EXTRA_ITEM_ID)
        supportActionBar?.title = if (editItemId != null) "Edit Entry" else "New Entry"

        setupTypeSpinner()
        binding.btnSave.setOnClickListener { saveEntry() }
        if (editItemId != null) loadItemForEdit(editItemId!!)
    }

    override fun onResume() {
        super.onResume()
        if (!VaultSession.isUnlocked()) { goToLock(); return }
    }

    private fun setupTypeSpinner() {
        val types = listOf("Password Entry", "API Token")
        binding.spinnerType.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, types)
            .also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }
        binding.spinnerType.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: android.widget.AdapterView<*>?, v: View?, pos: Int, id: Long) {
                currentType = if (pos == 0) VaultItem.TYPE_PASSWORD else VaultItem.TYPE_TOKEN
                updateFieldVisibility()
            }
            override fun onNothingSelected(p: android.widget.AdapterView<*>?) {}
        }
    }

    private fun updateFieldVisibility() {
        val isPw = currentType == VaultItem.TYPE_PASSWORD
        binding.tilEmailUsername.visibility = if (isPw) View.VISIBLE else View.GONE
        binding.tilPassword.visibility      = if (isPw) View.VISIBLE else View.GONE
        binding.tilToken.visibility         = if (isPw) View.GONE    else View.VISIBLE
        binding.tilName.hint = if (isPw) "Account Name" else "Service Name"
    }

    private fun loadItemForEdit(itemId: String) {
        binding.progressBar.visibility = View.VISIBLE
        lifecycleScope.launch {
            try {
                val key    = VaultSession.getKey() ?: run { goToLock(); return@launch }
                val userId = VaultSession.getUserId() ?: run { goToLock(); return@launch }

                val items = withContext(Dispatchers.IO) { OfflineVaultStore.listItems(this@AddEditActivity, userId) }
                val item  = items.find { it.id == itemId } ?: run { finish(); return@launch }

                val plainJson = withContext(Dispatchers.Default) {
                    CryptoManager.decrypt(item.encryptedData, item.iv, key, userId, item.id, item.type)
                }

                binding.etName.setText(item.name)
                if (item.type == VaultItem.TYPE_PASSWORD) {
                    binding.spinnerType.setSelection(0)
                    val p = PasswordPayload.fromJson(plainJson)
                    binding.etEmailUsername.setText(p.emailOrUsername)
                    binding.etPassword.setText(p.password)
                    binding.etNotes.setText(p.notes)
                } else {
                    binding.spinnerType.setSelection(1)
                    val t = TokenPayload.fromJson(plainJson)
                    binding.etToken.setText(t.token)
                    binding.etNotes.setText(t.notes)
                }
            } catch (_: javax.crypto.AEADBadTagException) {
                snack("Decryption failed — entry may be from a different account")
            } catch (e: Exception) {
                snack("Load failed: ${e.message}")
            } finally {
                binding.progressBar.visibility = View.GONE
            }
        }
    }

    private fun saveEntry() {
        val name  = binding.etName.text.toString().trim()
        if (name.isEmpty()) { snack("Name is required"); return }
        val key    = VaultSession.getKey() ?: run { goToLock(); return }
        val userId = VaultSession.getUserId() ?: run { goToLock(); return }
        val notes  = binding.etNotes.text.toString().trim()

        val resolvedId = editItemId ?: java.util.UUID.randomUUID().toString()

        val plainJson = if (currentType == VaultItem.TYPE_PASSWORD) {
            val pw = binding.etPassword.text.toString()
            if (pw.isEmpty()) { snack("Password is required"); return }
            PasswordPayload(binding.etEmailUsername.text.toString().trim(), pw, notes).toJson()
        } else {
            val token = binding.etToken.text.toString().trim()
            if (token.isEmpty()) { snack("Token is required"); return }
            TokenPayload(token, notes).toJson()
        }

        binding.progressBar.visibility = View.VISIBLE
        binding.btnSave.isEnabled = false
        lifecycleScope.launch {
            try {
                val (enc, iv) = withContext(Dispatchers.Default) {
                    CryptoManager.encrypt(plainJson, key, userId, resolvedId, currentType)
                }
                val item = VaultItem(id = resolvedId, type = currentType, name = name,
                    encryptedData = enc, iv = iv, aadVersion = VaultItem.AAD_VERSION)

                withContext(Dispatchers.IO) { OfflineVaultStore.saveItem(this@AddEditActivity, userId, item) }
                finish()
            } catch (e: Exception) {
                binding.progressBar.visibility = View.GONE
                binding.btnSave.isEnabled = true
                snack("Save failed: ${e.message}")
            }
        }
    }

    private fun goToLock() { startActivity(Intent(this, LockActivity::class.java)); finish() }
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }
    private fun snack(msg: String) = Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()
    companion object { const val EXTRA_ITEM_ID = "extra_item_id" }
}
