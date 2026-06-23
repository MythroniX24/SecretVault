package com.mythronix.keysandpassword

import android.app.Application
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner

class App : Application(), DefaultLifecycleObserver {

    override fun onCreate() {
        super<Application>.onCreate()
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        setupCrashHandler()
    }

    /** Lock vault immediately when app goes to background. */
    override fun onStop(owner: LifecycleOwner) {
        VaultSession.lock()
    }

    /**
     * Catch unhandled exceptions — clear sensitive memory before crash report.
     * This ensures master key is not left in memory after a crash.
     */
    private fun setupCrashHandler() {
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            // Zero out sensitive session data before crash report
            try { VaultSession.clearAll() } catch (_: Exception) {}
            Log.e("SecureVault", "Uncaught exception", throwable)
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }
}
