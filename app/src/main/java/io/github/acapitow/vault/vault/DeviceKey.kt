package io.github.acapitow.vault.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Clé AES-256 de l'appareil dans l'Android Keystore (MASVS-STORAGE-1 / MASVS-CRYPTO-2).
 *
 * Générée dans StrongBox (élément sécurisé dédié) si l'appareil en a un,
 * sinon dans le TEE. Elle n'est jamais extractible : le chiffrement a lieu
 * dans le matériel. Elle ne sert qu'à envelopper la clé du coffre (quelques
 * dizaines d'octets), StrongBox étant lent sur de gros volumes.
 *
 * Elle n'exige pas d'authentification utilisateur : c'est le mot de passe
 * maître qui protège l'accès. La clé liée à la biométrie viendra à l'étape 4.
 *
 * `setUnlockedDeviceRequired` n'est volontairement pas utilisé : selon les
 * versions et constructeurs, retirer le verrouillage d'écran peut rendre la
 * clé définitivement inutilisable, et donc le coffre irrécupérable.
 */
object DeviceKey {

    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "secure-vault-device"

    @Synchronized
    fun getOrCreate(): SecretKey {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        return (keyStore.getKey(ALIAS, null) as? SecretKey) ?: generate()
    }

    private fun generate(): SecretKey =
        try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true) // IV imposé par le Keystore, jamais réutilisé
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec)
            generateKey()
        }
    }
}
