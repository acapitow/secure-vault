package io.github.acapitow.vault.vault

import javax.crypto.SecretKey

/**
 * Clé AES-256 de l'appareil dans l'Android Keystore (MASVS-STORAGE-1 / MASVS-CRYPTO-2).
 *
 * Elle n'est jamais extractible : le chiffrement a lieu dans le matériel.
 * Elle ne sert qu'à envelopper la clé du coffre (quelques dizaines d'octets),
 * StrongBox étant lent sur de gros volumes.
 *
 * Elle n'exige pas d'authentification utilisateur : c'est le mot de passe
 * maître qui protège l'accès. La biométrie utilise une autre clé ([BiometricKey]).
 *
 * `setUnlockedDeviceRequired` n'est volontairement pas utilisé : selon les
 * versions et constructeurs, retirer le verrouillage d'écran peut rendre la
 * clé définitivement inutilisable, et donc le coffre irrécupérable.
 */
object DeviceKey {

    private const val ALIAS = "secure-vault-device"

    @Synchronized
    fun getOrCreate(): SecretKey = AndroidKeys.get(ALIAS) ?: AndroidKeys.generate(ALIAS)
}
