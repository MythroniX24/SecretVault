package com.mythronix.keysandpassword.activities

import android.graphics.Color
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.crypto.BreachCheckManager
import com.mythronix.keysandpassword.crypto.PasswordStrengthUtil
import com.mythronix.keysandpassword.databinding.ActivityAuthBinding
import com.mythronix.keysandpassword.offline.OfflineAccountManager
import com.mythronix.keysandpassword.offline.OfflineVaultStore
import kotlinx.coroutines.launch

class AuthActivity : AppCompatActivity() {

    private lateinit var binding: ActivityAuthBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        binding = ActivityAuthBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // If vault already unlocked (e.g., rotation), skip.
        if (VaultSession.isUnlocked()) {
            goToLock()
            return
        }

        lifecycleScope.launch {
            val has = OfflineAccountManager.hasAccount(this@AuthActivity)
            if (has) goToLock()
            else setupCreateMasterPasswordUI()
        }
    }

    private fun setupCreateMasterPasswordUI() {
        binding.tvTitle.text = "Create Vault Offline"
        binding.tvSubtitle.text = "Everything stays on your device — encrypted"
        binding.btnAction.text = "Create Vault"

        // Offline: hide email, switch to master-password creation
        binding.tvSwitchMode.visibility = View.GONE
        binding.tilEmail.visibility = View.GONE
        binding.cardVerifyNotice.visibility = View.GONE

        binding.tilConfirmPassword.visibility = View.VISIBLE
        binding.layoutStrength.visibility = View.VISIBLE
        binding.btnBreachCheck.visibility = View.VISIBLE
        binding.tvBreachResult.visibility = View.GONE

        binding.btnAction.setOnClickListener { createAccount() }

        // Enable proper confirm UI
        binding.etPassword.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun afterTextChanged(s: Editable?) {}
            override fun onTextChanged(s: CharSequence?, st: Int, b: Int, count: Int) {
                updateStrengthMeter(s?.toString() ?: "")
            }
        })

        binding.btnBreachCheck.setOnClickListener {
            val pw = binding.etPassword.text.toString()
            if (pw.isEmpty()) {
                snack("Enter a password first")
                return@setOnClickListener
            }

            binding.btnBreachCheck.isEnabled = false
            binding.btnBreachCheck.text = "Checking…"
            lifecycleScope.launch {
                val result = BreachCheckManager.checkPassword(pw)
                binding.btnBreachCheck.isEnabled = true
                binding.btnBreachCheck.text = "Check if Pwned"
                binding.tvBreachResult.visibility = View.VISIBLE

                result.onSuccess { count ->
                    if (count == 0) {
                        binding.tvBreachResult.text = "✅ Password not found in any breach"
                        binding.tvBreachResult.setTextColor(Color.parseColor("#388E3C"))
                    } else {
                        binding.tvBreachResult.text = "⚠️ Found $count times — use different password!"
                        binding.tvBreachResult.setTextColor(Color.parseColor("#D32F2F"))
                    }
                }.onFailure {
                    binding.tvBreachResult.text = "⚡ Check failed — no internet?"
                    binding.tvBreachResult.setTextColor(Color.parseColor("#F57C00"))
                }
            }
        }

        updateStrengthMeter(binding.etPassword.text?.toString() ?: "")
    }

    private fun createAccount() {
        val pw = binding.etPassword.text.toString()
        val confirm = binding.etConfirmPassword.text.toString()

        if (pw.length < 8) {
            snack("Minimum 8 characters required")
            return
        }
        if (pw != confirm) {
            snack("Passwords do not match")
            return
        }

        binding.progressBar.visibility = View.VISIBLE
        binding.btnAction.isEnabled = false
        binding.etPassword.isEnabled = false
        binding.etConfirmPassword.isEnabled = false

        lifecycleScope.launch {
            try {
                OfflineAccountManager.createAccount(this@AuthActivity, pw.toCharArray())
                binding.progressBar.visibility = View.GONE
                VaultSession.lock()
                goToLock()
            } catch (e: Exception) {
                binding.progressBar.visibility = View.GONE
                binding.btnAction.isEnabled = true
                binding.etPassword.isEnabled = true
                binding.etConfirmPassword.isEnabled = true
                snack("Failed: ${e.message ?: "Unknown error"}")
            }
        }
    }

    private fun goToLock() {
        startActivity(android.content.Intent(this, LockActivity::class.java))
        finish()
    }

    private fun updateStrengthMeter(pw: String) {
        if (pw.isEmpty()) {
            binding.layoutStrength.visibility = View.GONE
            return
        }
        binding.layoutStrength.visibility = View.VISIBLE

        val result = PasswordStrengthUtil.evaluate(pw)
        val score = result.score

        val filled = when {
            score >= 80 -> 5
            score >= 60 -> 4
            score >= 40 -> 3
            score >= 20 -> 2
            score > 0 -> 1
            else -> 0
        }

        val activeColor = when {
            filled >= 4 -> Color.parseColor("#4CAF50")
            filled >= 2 -> Color.parseColor("#FF9800")
            else -> Color.parseColor("#F44336")
        }
        val emptyColor = Color.parseColor("#E0E0E0")

        binding.bar1.setBackgroundColor(if (filled >= 1) activeColor else emptyColor)
        binding.bar2.setBackgroundColor(if (filled >= 2) activeColor else emptyColor)
        binding.bar3.setBackgroundColor(if (filled >= 3) activeColor else emptyColor)
        binding.bar4.setBackgroundColor(if (filled >= 4) activeColor else emptyColor)
        binding.bar5.setBackgroundColor(if (filled >= 5) activeColor else emptyColor)

        binding.tvStrengthLabel.text = result.strength.label
        binding.tvStrengthLabel.setTextColor(activeColor)
        binding.tvStrengthTip.text = result.tips.firstOrNull() ?: ""
    }

    private fun snack(msg: String) =
        Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()
}
