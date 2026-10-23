package io.github.acapitow.vault.ui

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Échec ou annulation de BiometricPrompt. */
class BiometricException(val code: Int, message: String) : Exception(message) {
    /** L'utilisateur a choisi le mot de passe ou fermé la fenêtre : pas une erreur à afficher. */
    val isCancellation: Boolean
        get() = code == BiometricPrompt.ERROR_USER_CANCELED ||
            code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
            code == BiometricPrompt.ERROR_CANCELED
}

/**
 * BiometricPrompt sous forme de fonction suspendue.
 *
 * Seule la biométrie forte (classe 3) est acceptée, et toujours avec un
 * CryptoObject : le succès n'est pas un booléen qu'on pourrait falsifier,
 * c'est le Cipher débloqué par le matériel. Pas de repli sur le code de
 * l'appareil : le repli, c'est le mot de passe maître.
 */
object BiometricAuth {

    fun isAvailable(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** @return [cipher] débloqué. @throws BiometricException en cas d'échec ou d'annulation. */
    suspend fun authenticate(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        negativeButton: String,
    ): Cipher = suspendCancellableCoroutine { continuation ->
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val unlocked = result.cryptoObject?.cipher
                if (unlocked != null) {
                    continuation.resume(unlocked)
                } else {
                    continuation.resumeWithException(BiometricException(-1, "CryptoObject absent"))
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                continuation.resumeWithException(BiometricException(errorCode, errString.toString()))
            }

            // onAuthenticationFailed : doigt non reconnu, la fenêtre reste ouverte pour réessayer.
        }
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setNegativeButtonText(negativeButton)
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
    }
}
