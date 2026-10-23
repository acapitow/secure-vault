package io.github.acapitow.vault.vault

import android.os.Build
import android.security.keystore.KeyProperties
import javax.crypto.SecretKey

/** Stockage de la clé liée à la biométrie. Interface pour pouvoir la simuler dans les tests JVM. */
interface BiometricKeyStore {
    /** Crée une nouvelle clé, en remplaçant l'éventuelle précédente. */
    fun create(): SecretKey
    fun get(): SecretKey?
    fun delete()
}

/**
 * Clé Keystore qui ne peut servir qu'après une authentification biométrique
 * forte (classe 3), pour chaque opération (MASVS-AUTH-2).
 *
 * L'authentification est liée cryptographiquement à l'opération : le Cipher
 * passé à BiometricPrompt (CryptoObject) n'est débloqué par le matériel
 * qu'après succès. Contourner l'interface (ex. Frida sur le callback
 * onAuthenticationSucceeded) ne donne donc rien : sans authentification
 * réelle, le Keystore refuse de déchiffrer.
 *
 * La clé est invalidée par le système si une empreinte ou un visage est
 * ajouté : quelqu'un qui connaît le code de l'appareil ne peut pas enrôler
 * son propre doigt pour ouvrir le coffre.
 */
object BiometricKey : BiometricKeyStore {

    private const val ALIAS = "secure-vault-biometric"

    @Synchronized
    override fun create(): SecretKey {
        AndroidKeys.delete(ALIAS)
        return AndroidKeys.generate(ALIAS) {
            setUserAuthenticationRequired(true)
            setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // 0 s : authentification exigée pour chaque opération, biométrie forte uniquement.
                setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                setUserAuthenticationValidityDurationSeconds(-1)
            }
        }
    }

    override fun get(): SecretKey? = AndroidKeys.get(ALIAS)

    override fun delete() = AndroidKeys.delete(ALIAS)
}
