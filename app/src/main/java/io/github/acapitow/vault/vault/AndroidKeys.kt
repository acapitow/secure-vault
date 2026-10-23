package io.github.acapitow.vault.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Accès commun à l'Android Keystore pour les clés AES-256-GCM du coffre. */
internal object AndroidKeys {

    private const val PROVIDER = "AndroidKeyStore"

    fun get(alias: String): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    fun delete(alias: String) {
        val keyStore = keyStore()
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    /**
     * Génère une clé non extractible, dans StrongBox (élément sécurisé dédié)
     * si l'appareil en a un, sinon dans le TEE.
     */
    fun generate(alias: String, configure: KeyGenParameterSpec.Builder.() -> Unit = {}): SecretKey =
        try {
            generate(alias, strongBox = true, configure)
        } catch (_: StrongBoxUnavailableException) {
            generate(alias, strongBox = false, configure)
        }

    private fun generate(alias: String, strongBox: Boolean, configure: KeyGenParameterSpec.Builder.() -> Unit): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true) // IV imposé par le Keystore, jamais réutilisé
            .setIsStrongBoxBacked(strongBox)
            .apply(configure)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec)
            generateKey()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
}
