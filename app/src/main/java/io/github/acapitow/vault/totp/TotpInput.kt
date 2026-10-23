package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.Secrets

/**
 * Saisie d'un compte TOTP : lien `otpauth://` (scanné ou collé) ou clé
 * secrète Base32 tapée à la main (ex. « JBSW Y3DP EHPK 3PXP »).
 */
object TotpInput {

    private const val SCHEME = "otpauth:"

    /**
     * @param issuer, account utilisés pour une clé Base32 seule (un lien
     *   otpauth porte les siens).
     * @throws IllegalArgumentException si l'entrée est invalide.
     */
    fun parse(input: CharArray, issuer: String, account: String): TotpAccount {
        if (input.size >= SCHEME.length && SCHEME.indices.all { input[it].lowercaseChar() == SCHEME[it] }) {
            return OtpAuthUri.parse(String(input))
        }
        val secret = Base32.decode(input)
        return try {
            TotpAccount(issuer.trim(), account.trim(), secret)
        } catch (e: IllegalArgumentException) {
            Secrets.wipe(secret)
            throw e
        }
    }
}
