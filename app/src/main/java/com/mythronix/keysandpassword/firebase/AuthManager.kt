package com.mythronix.keysandpassword.firebase

import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import kotlinx.coroutines.tasks.await

object AuthManager {

    private val auth: FirebaseAuth get() = FirebaseAuth.getInstance()

    fun getCurrentUser(): FirebaseUser? = auth.currentUser
    fun isLoggedIn(): Boolean = auth.currentUser != null
    fun currentUserId(): String = auth.currentUser?.uid
        ?: throw IllegalStateException("No logged-in user")

    suspend fun signUp(email: String, password: String): FirebaseUser {
        val result = auth.createUserWithEmailAndPassword(email, password).await()
        return result.user ?: throw Exception("Sign-up failed")
    }

    suspend fun signIn(email: String, password: String): FirebaseUser {
        val result = auth.signInWithEmailAndPassword(email, password).await()
        val user = result.user ?: throw Exception("Sign-in failed")
        return user
    }

    fun isEmailVerified(): Boolean = auth.currentUser?.isEmailVerified == true

    fun signOut() { auth.signOut() }
}
