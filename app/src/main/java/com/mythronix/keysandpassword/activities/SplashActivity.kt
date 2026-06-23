package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.mythronix.keysandpassword.VaultSession
import com.mythronix.keysandpassword.databinding.ActivitySplashBinding
import com.mythronix.keysandpassword.offline.OfflineAccountManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SplashActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySplashBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySplashBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.root.postDelayed({ route() }, 800L)
    }

    private fun route() {
        lifecycleScope.launch {
            val hasAccount = withContext(Dispatchers.IO) {
                OfflineAccountManager.hasAccount(this@SplashActivity)
            }

            val dest = when {
                !hasAccount                  -> AuthActivity::class.java
                VaultSession.isUnlocked()    -> VaultActivity::class.java
                else                         -> LockActivity::class.java
            }
            go(dest)
        }
    }

    private fun go(c: Class<*>) { startActivity(Intent(this, c)); finish() }
}
