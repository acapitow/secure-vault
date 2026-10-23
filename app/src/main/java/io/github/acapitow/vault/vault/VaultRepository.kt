package io.github.acapitow.vault.vault

import io.github.acapitow.vault.crypto.AesGcm
import io.github.acapitow.vault.crypto.Argon2id
import io.github.acapitow.vault.crypto.DecryptionException
import io.github.acapitow.vault.crypto.KdfParams
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.crypto.useAndWipe
import kotlinx.serialization.SerializationException
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.InvalidKeyException
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Création, ouverture et sauvegarde du coffre (format décrit dans VaultFormat.kt).
 *
 * @param deviceKey clé matérielle de l'appareil ([DeviceKey] sous Android ;
 *   une clé logicielle dans les tests JVM).
 * @param biometricKeys clé liée à la biométrie ([BiometricKey] sous Android) ;
 *   `null` si la biométrie n'est pas prise en charge.
 */
class VaultRepository(
    private val file: File,
    private val deviceKey: () -> SecretKey,
    private val biometricKeys: BiometricKeyStore? = null,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    fun exists(): Boolean = file.exists()

    /** Crée un coffre vide. Le mot de passe n'est pas modifié ; l'appelant l'efface. */
    fun create(password: CharArray, kdf: KdfParams = KdfParams()): Vault {
        check(!exists()) { "un coffre existe déjà" }
        biometricKeys?.delete() // clé orpheline d'un ancien coffre
        return Secrets.randomBytes(AesGcm.KEY_SIZE).useAndWipe { dek ->
            Vault(newHeader(password, dek, kdf), AesGcm.key(dek), emptyList(), clock).also(::save)
        }
    }

    /**
     * @throws WrongPasswordException si le mot de passe est incorrect.
     * @throws CorruptedVaultException si le fichier est altéré ou illisible sur cet appareil.
     */
    fun unlock(password: CharArray): Vault {
        val vaultFile = read()
        return unwrap(vaultFile.header, password).useAndWipe { open(vaultFile, it) }
    }

    fun save(vault: Vault) {
        val payload = VaultJson.encodeToString(vault.content()).toByteArray().useAndWipe { json ->
            AesGcm.encrypt(vault.key(), json, PAYLOAD_AAD)
        }
        write(VaultFile(vault.header, payload))
    }

    /**
     * Change le mot de passe maître (nouveau sel, mêmes données, même clé de
     * coffre). Le mot de passe actuel est redemandé : un coffre laissé ouvert
     * ne suffit pas pour en prendre le contrôle.
     *
     * Le déverrouillage biométrique est désactivé : le sel change, et un
     * changement de mot de passe suit souvent une compromission.
     */
    fun changePassword(vault: Vault, current: CharArray, new: CharArray, kdf: KdfParams = vault.header.kdf) {
        unwrap(vault.header, current).useAndWipe { dek ->
            val same = vault.key().encoded.useAndWipe { Secrets.constantTimeEquals(dek, it) }
            check(same) { "coffre et fichier ne correspondent pas" }
            vault.header = newHeader(new, dek, kdf)
        }
        save(vault)
        biometricKeys?.delete()
    }

    /** Supprime définitivement le coffre (réinitialisation de l'application). */
    fun delete() {
        file.delete()
        biometricKeys?.delete()
    }

    // --- Biométrie ------------------------------------------------------------------------------

    val isBiometricEnabled: Boolean
        get() = exists() && read().header.biometricSlot != null && biometricKeys?.get() != null

    /** Activation, étape 1 : Cipher à faire valider par BiometricPrompt. */
    fun biometricEnrollment(): Cipher = AesGcm.encryptor(requireNotNull(biometricKeys) { "biométrie non prise en charge" }.create())

    /** Activation, étape 2 : [cipher] est celui de l'étape 1, débloqué par BiometricPrompt. */
    fun enableBiometric(vault: Vault, cipher: Cipher) {
        val slot = vault.key().encoded.useAndWipe { AesGcm.encrypt(cipher, it, vault.header.aad(BIOMETRIC_LAYER)) }
        vault.header = vault.header.copy(biometricSlot = slot)
        save(vault)
    }

    fun disableBiometric(vault: Vault) {
        vault.header = vault.header.copy(biometricSlot = null)
        save(vault)
        biometricKeys?.delete()
    }

    /**
     * Déverrouillage, étape 1 : Cipher à faire valider par BiometricPrompt,
     * ou `null` si la biométrie n'est pas activée.
     *
     * @throws BiometricInvalidatedException si le système a invalidé la clé ;
     *   la biométrie est alors désactivée.
     */
    fun biometricUnlock(): Cipher? {
        val vaultFile = read()
        val slot = vaultFile.header.biometricSlot ?: return null
        val key = biometricKeys?.get()
        if (key == null) {
            dropBiometricSlot(vaultFile)
            return null
        }
        return try {
            AesGcm.decryptor(key, slot)
        } catch (e: InvalidKeyException) {
            // KeyPermanentlyInvalidatedException : nouvelle empreinte enregistrée.
            dropBiometricSlot(vaultFile)
            biometricKeys.delete()
            throw BiometricInvalidatedException(e)
        } catch (e: DecryptionException) {
            throw CorruptedVaultException(e)
        }
    }

    /**
     * Déverrouillage, étape 2 : [cipher] est celui de l'étape 1, débloqué par BiometricPrompt.
     * @throws CorruptedVaultException si le fichier est altéré.
     */
    fun unlockWithBiometric(cipher: Cipher): Vault {
        val vaultFile = read()
        val header = vaultFile.header
        val dek = try {
            checkHeader(header)
            val slot = header.biometricSlot ?: throw CorruptedVaultException()
            AesGcm.decrypt(cipher, slot, header.aad(BIOMETRIC_LAYER))
        } catch (e: DecryptionException) {
            throw CorruptedVaultException(e)
        }
        return checkKeySize(dek).useAndWipe { open(vaultFile, it) }
    }

    private fun dropBiometricSlot(vaultFile: VaultFile) {
        write(VaultFile(vaultFile.header.copy(biometricSlot = null), vaultFile.payload))
    }

    // --- Interne --------------------------------------------------------------------------------

    private fun newHeader(password: CharArray, dek: ByteArray, kdf: KdfParams): VaultHeader {
        val salt = Secrets.randomBytes(Argon2id.SALT_SIZE)
        val draft = VaultHeader(FORMAT, kdf.validate(), salt, ByteArray(0))
        val inner = Argon2id.deriveKey(password, salt, kdf).useAndWipe { kek ->
            AesGcm.encrypt(AesGcm.key(kek), dek, draft.aad(PASSWORD_LAYER))
        }
        return draft.copy(passwordSlot = AesGcm.encrypt(deviceKey(), inner, draft.aad(DEVICE_LAYER)))
    }

    /** Retire les deux couches du slot mot de passe. L'appelant doit effacer la clé retournée. */
    private fun unwrap(header: VaultHeader, password: CharArray): ByteArray {
        val inner = try {
            checkHeader(header)
            AesGcm.decrypt(deviceKey(), header.passwordSlot, header.aad(DEVICE_LAYER))
        } catch (e: DecryptionException) {
            throw CorruptedVaultException(e)
        }
        val dek = Argon2id.deriveKey(password, header.salt, header.kdf).useAndWipe { kek ->
            try {
                AesGcm.decrypt(AesGcm.key(kek), inner, header.aad(PASSWORD_LAYER))
            } catch (_: DecryptionException) {
                throw WrongPasswordException()
            }
        }
        return checkKeySize(dek)
    }

    /** Refuse un format inconnu ou des paramètres KDF hors bornes (attaque par dégradation). */
    private fun checkHeader(header: VaultHeader) {
        if (header.format != FORMAT || header.salt.size != Argon2id.SALT_SIZE) throw CorruptedVaultException()
        try {
            header.kdf.validate()
        } catch (e: IllegalArgumentException) {
            throw CorruptedVaultException(e)
        }
    }

    private fun checkKeySize(dek: ByteArray): ByteArray {
        if (dek.size != AesGcm.KEY_SIZE) {
            Secrets.wipe(dek)
            throw CorruptedVaultException()
        }
        return dek
    }

    /** Déchiffre le contenu avec la clé du coffre [dek] (que l'appelant efface). */
    private fun open(vaultFile: VaultFile, dek: ByteArray): Vault {
        val key = AesGcm.key(dek)
        val content = try {
            AesGcm.decrypt(key, vaultFile.payload, PAYLOAD_AAD).useAndWipe { json ->
                VaultJson.decodeFromString<VaultContent>(json.decodeToString())
            }
        } catch (e: DecryptionException) {
            throw CorruptedVaultException(e)
        } catch (e: SerializationException) {
            throw CorruptedVaultException(e)
        } catch (e: IllegalArgumentException) {
            throw CorruptedVaultException(e)
        }
        return Vault(vaultFile.header, key, content.entries, clock)
    }

    private fun read(): VaultFile {
        if (!exists()) throw NoSuchFileException(file)
        return try {
            VaultJson.decodeFromString<VaultFile>(file.readText())
        } catch (e: SerializationException) {
            throw CorruptedVaultException(e)
        } catch (e: IllegalArgumentException) {
            throw CorruptedVaultException(e)
        }
    }

    /** Écriture atomique : un crash pendant la sauvegarde laisse l'ancien coffre intact. */
    private fun write(vaultFile: VaultFile) {
        val bytes = VaultJson.encodeToString(vaultFile).toByteArray()
        val tmp = File(file.parentFile, "${file.name}.tmp")
        FileOutputStream(tmp).use {
            it.write(bytes)
            it.fd.sync()
        }
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }

    private companion object {
        const val PASSWORD_LAYER = "password-slot"
        const val DEVICE_LAYER = "device-slot"
        const val BIOMETRIC_LAYER = "biometric-slot"
        val PAYLOAD_AAD = "secure-vault/v$FORMAT/payload".toByteArray()
    }
}
