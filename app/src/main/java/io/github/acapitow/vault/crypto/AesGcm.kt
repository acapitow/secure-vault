package io.github.acapitow.vault.crypto

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Échec de déchiffrement. Volontairement sans détail : pas d'oracle sur la cause. */
class DecryptionException(cause: Throwable? = null) : GeneralSecurityException("déchiffrement impossible", cause)

/**
 * Chiffrement authentifié AES-256-GCM (MASVS-CRYPTO-1).
 *
 * Format d'un bloc chiffré :
 *
 *     | version (1) | nonce (12) | texte chiffré (n) | tag (16) |
 *
 * L'octet de version fait partie des données authentifiées : il ne peut pas
 * être modifié sans faire échouer la vérification du tag.
 *
 * Le nonce est généré par le fournisseur lors de `init` (et non par l'appelant).
 * C'est le seul mode accepté par les clés Android Keystore, ce qui permet
 * d'utiliser cette même classe avec une clé matérielle (Android Keystore).
 */
object AesGcm {

    const val VERSION: Byte = 1
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    const val OVERHEAD = 1 + NONCE_SIZE + TAG_SIZE

    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    /** Clé logicielle à partir d'octets bruts (ex. sortie d'Argon2id). */
    fun key(bytes: ByteArray): SecretKey {
        require(bytes.size == KEY_SIZE) { "clé AES-256 attendue" }
        return SecretKeySpec(bytes, "AES")
    }

    /**
     * @param aad données associées, authentifiées mais non chiffrées
     *   (ex. identifiant de l'entrée) : empêchent de déplacer un bloc chiffré
     *   d'un contexte à un autre.
     */
    fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray = EMPTY): ByteArray =
        encrypt(encryptor(key), plaintext, aad)

    /** @throws DecryptionException si le bloc est altéré, tronqué, ou si la clé / l'AAD ne correspondent pas. */
    fun decrypt(key: SecretKey, blob: ByteArray, aad: ByteArray = EMPTY): ByteArray =
        decrypt(decryptor(key, blob), blob, aad)

    /*
     * Variantes en deux temps, pour les clés Keystore liées à la biométrie :
     * le Cipher initialisé est passé à BiometricPrompt (CryptoObject), qui ne
     * l'autorise qu'après authentification ; on termine ensuite l'opération.
     * Les exceptions d'initialisation (ex. KeyPermanentlyInvalidatedException)
     * ne sont pas masquées.
     */

    fun encryptor(key: SecretKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }

    fun encrypt(cipher: Cipher, plaintext: ByteArray, aad: ByteArray = EMPTY): ByteArray {
        val nonce = cipher.iv
        check(nonce != null && nonce.size == NONCE_SIZE) { "nonce GCM inattendu" }
        cipher.updateAAD(byteArrayOf(VERSION))
        cipher.updateAAD(aad)
        val sealed = cipher.doFinal(plaintext)

        return ByteArray(1 + NONCE_SIZE + sealed.size).also { out ->
            out[0] = VERSION
            nonce.copyInto(out, 1)
            sealed.copyInto(out, 1 + NONCE_SIZE)
        }
    }

    /** @throws DecryptionException si le bloc est mal formé. */
    fun decryptor(key: SecretKey, blob: ByteArray): Cipher {
        if (blob.size < OVERHEAD || blob[0] != VERSION) throw DecryptionException()
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, blob, 1, NONCE_SIZE))
        }
    }

    /** @param cipher issu de [decryptor] pour ce même [blob]. */
    fun decrypt(cipher: Cipher, blob: ByteArray, aad: ByteArray = EMPTY): ByteArray =
        try {
            if (blob.size < OVERHEAD || blob[0] != VERSION) throw DecryptionException()
            cipher.updateAAD(byteArrayOf(VERSION))
            cipher.updateAAD(aad)
            cipher.doFinal(blob, 1 + NONCE_SIZE, blob.size - 1 - NONCE_SIZE)
        } catch (e: DecryptionException) {
            throw e
        } catch (e: GeneralSecurityException) {
            throw DecryptionException(e)
        }

    /** GCM brut : vérifie le tag puis déchiffre. Exposé pour les vecteurs de test NIST. */
    internal fun open(key: SecretKey, nonce: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray =
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_SIZE * 8, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(sealed)
        } catch (e: GeneralSecurityException) {
            throw DecryptionException(e)
        }

    private val EMPTY = ByteArray(0)
}
