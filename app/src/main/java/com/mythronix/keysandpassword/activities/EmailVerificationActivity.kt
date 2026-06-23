package com.mythronix.keysandpassword.activities

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
import com.mythronix.keysandpassword.databinding.ActivityEmailVerificationBinding
import com.mythronix.keysandpassword.firebase.AuthManager
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

class EmailVerificationActivity : AppCompatActivity() {

    private lateinit var binding: ActivityEmailVerificationBinding
    private var email = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE)
        binding = ActivityEmailVerificationBinding.inflate(layoutInflater)
        setContentView(binding.root)

        email = intent.getStringExtra("email") ?: AuthManager.getCurrentUser()?.email ?: ""
        val emailSent = intent.getBooleanExtra("emailSent", false)

        binding.tvEmail.text = email
        updateStatus(emailSent)

        binding.btnVerified.setOnClickListener { checkVerification() }
        binding.btnResend.setOnClickListener   { resendEmail() }
        binding.btnSignOut.setOnClickListener  { signOut() }

        // If not sent yet (user came from login with unverified account), send now
        if (!emailSent) {
            lifecycleScope.launch {
                try {
                    AuthManager.getCurrentUser()?.sendEmailVerification()?.await()
                    updateStatus(true)
                    snack("✅ Verification email sent to $email")
                } catch (_: Exception) {
                    // Show resend button prominently
                }
            }
        }
    }

    private fun updateStatus(sent: Boolean) {
        binding.tvStatus.text = if (sent)
            "We sent a verification link to:\n\n$email\n\n" +
            "1️⃣  Open your email app\n" +
            "2️⃣  Click the link in the email\n" +
            "3️⃣  Come back and tap  ✅ I've Verified\n\n" +
            "⚠️  Also check SPAM / JUNK folder!"
        else
            "Tap 'Resend Email' below to receive the verification link.\n\n" +
            "Check both inbox and SPAM folder."
    }

    private fun checkVerification() {
        setLoading(true)
        lifecycleScope.launch {
            try { AuthManager.getCurrentUser()?.reload()?.await() } catch (_: Exception) {}
            setLoading(false)
            if (AuthManager.getCurrentUser()?.isEmailVerified == true) {
                startActivity(Intent(this@EmailVerificationActivity, LockActivity::class.java))
                finishAffinity()
            } else {
                snack("Not verified yet — please click the link in your email (check spam too)")
            }
        }
    }

    private fun resendEmail() {
        setLoading(true)
        lifecycleScope.launch {
            try {
                AuthManager.getCurrentUser()?.sendEmailVerification()?.await()
                setLoading(false)
                updateStatus(true)
                snack("✅ Email sent to $email — check inbox AND spam folder")
            } catch (e: Exception) {
                setLoading(false)
                snack("Send failed: ${e.message}")
            }
        }
    }

    private fun signOut() {
        AuthManager.signOut()
        startActivity(Intent(this, AuthActivity::class.java))
        finishAffinity()
    }

    private fun setLoading(on: Boolean) {
        binding.progressBar.visibility = if (on) android.view.View.VISIBLE else android.view.View.GONE
        binding.btnVerified.isEnabled  = !on
        binding.btnResend.isEnabled    = !on
    }

    private fun snack(msg: String) =
        Snackbar.make(binding.root, msg, Snackbar.LENGTH_LONG).show()
}
