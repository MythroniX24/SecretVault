package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.databinding.ActivitySplashBinding
import com.mythronix.keysandpassword.firebase.AuthManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

class SplashActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySplashBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySplashBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.root.postDelayed({ route() }, 800L)
    }

    private fun route() {
        val user = AuthManager.getCurrentUser()
        if (user == null) { go(AuthActivity::class.java); return }

        lifecycleScope.launch {
            // Reload with 4s timeout — don't block forever on bad network
            withTimeoutOrNull(4_000L) {
                withContext(Dispatchers.IO) { runCatching { user.reload().await() } }
            }

            val dest = when {
                !user.isEmailVerified   -> AuthActivity::class.java
                VaultSession.isUnlocked() -> VaultActivity::class.java
                else                    -> LockActivity::class.java
            }
            go(dest)
        }
    }

    private fun go(c: Class<*>) { startActivity(Intent(this, c)); finish() }
}
