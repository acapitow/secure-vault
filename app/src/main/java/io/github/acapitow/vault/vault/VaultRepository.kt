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
import javax.crypto.SecretKey

/**
 * Création, ouverture et sauvegarde du coffre (format décrit dans VaultFormat.kt).
 *
 * @param deviceKey clé matérielle de l'appareil ([DeviceKey] sous Android ;
 *   une clé logicielle dans les tests JVM).
 */
class VaultRepository(
    private val file: File,
    private val deviceKey: () -> SecretKey,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    fun exists(): Boolean = file.exists()

    /** Crée un coffre vide. Le mot de passe n'est pas modifié ; l'appelant l'efface. */
    fun create(password: CharArray, kdf: KdfParams = KdfParams()): Vault {
        check(!exists()) { "un coffre existe déjà" }
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
        val header = vaultFile.header
        return unwrap(header, password).useAndWipe { dek ->
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
            Vault(header, key, content.entries, clock)
        }
    }

    fun save(vault: Vault) {
        val payload = VaultJson.encodeToString(vault.content()).toByteArray().useAndWipe { json ->
            AesGcm.encrypt(vault.key(), json, PAYLOAD_AAD)
        }
        write(VaultJson.encodeToString(VaultFile(vault.header, payload)).toByteArray())
    }

    /**
     * Change le mot de passe maître (nouveau sel, mêmes données, même clé de
     * coffre). Le mot de passe actuel est redemandé : un coffre laissé ouvert
     * ne suffit pas pour en prendre le contrôle.
     */
    fun changePassword(vault: Vault, current: CharArray, new: CharArray, kdf: KdfParams = vault.header.kdf) {
        unwrap(vault.header, current).useAndWipe { dek ->
            val same = vault.key().encoded.useAndWipe { Secrets.constantTimeEquals(dek, it) }
            check(same) { "coffre et fichier ne correspondent pas" }
            vault.header = newHeader(new, dek, kdf)
        }
        save(vault)
    }

    /** Supprime définitivement le coffre (réinitialisation de l'application). */
    fun delete() {
        file.delete()
    }

    private fun newHeader(password: CharArray, dek: ByteArray, kdf: KdfParams): VaultHeader {
        val salt = Secrets.randomBytes(Argon2id.SALT_SIZE)
        val draft = VaultHeader(FORMAT, kdf.validate(), salt, ByteArray(0))
        val inner = Argon2id.deriveKey(password, salt, kdf).useAndWipe { kek ->
            AesGcm.encrypt(AesGcm.key(kek), dek, draft.aad(PASSWORD_LAYER))
        }
        val slot = AesGcm.encrypt(deviceKey(), inner, draft.aad(DEVICE_LAYER))
        return VaultHeader(FORMAT, kdf, salt, slot)
    }

    /** Retire les deux couches du slot. L'appelant doit effacer la clé retournée. */
    private fun unwrap(header: VaultHeader, password: CharArray): ByteArray {
        val inner = try {
            if (header.format != FORMAT || header.salt.size != Argon2id.SALT_SIZE) throw CorruptedVaultException()
            header.kdf.validate()
            AesGcm.decrypt(deviceKey(), header.passwordSlot, header.aad(DEVICE_LAYER))
        } catch (e: DecryptionException) {
            throw CorruptedVaultException(e)
        } catch (e: IllegalArgumentException) {
            throw CorruptedVaultException(e)
        }
        val dek = Argon2id.deriveKey(password, header.salt, header.kdf).useAndWipe { kek ->
            try {
                AesGcm.decrypt(AesGcm.key(kek), inner, header.aad(PASSWORD_LAYER))
            } catch (_: DecryptionException) {
                throw WrongPasswordException()
            }
        }
        if (dek.size != AesGcm.KEY_SIZE) {
            Secrets.wipe(dek)
            throw CorruptedVaultException()
        }
        return dek
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
    private fun write(bytes: ByteArray) {
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
        val PAYLOAD_AAD = "secure-vault/v$FORMAT/payload".toByteArray()
    }
}
