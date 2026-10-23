package io.github.acapitow.vault.vault

import io.github.acapitow.vault.crypto.AesGcm
import io.github.acapitow.vault.crypto.KdfParams
import io.github.acapitow.vault.crypto.Secrets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.InvalidKeyException
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Simule la clé biométrique du Keystore. Hors Android, rien n'exige
 * d'authentification : ces tests vérifient la logique des slots, pas BiometricPrompt.
 */
private class FakeBiometricKeys : BiometricKeyStore {
    var key: SecretKey? = null
    var invalidated = false

    override fun create(): SecretKey = AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE)).also { key = it }

    override fun get(): SecretKey? = key?.let { if (invalidated) InvalidatedKey else it }

    override fun delete() {
        key = null
    }

    /** Comme KeyPermanentlyInvalidatedException : refusée dès l'initialisation du Cipher. */
    private object InvalidatedKey : SecretKey by SecretKeySpec(ByteArray(3), "AES")
}

class BiometricRepositoryTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val fast = KdfParams(memoryKiB = KdfParams.MIN_MEMORY_KIB, iterations = 2, parallelism = 1)
    private val deviceKey = AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE))
    private val keys = FakeBiometricKeys()
    private val password = "mot de passe".toCharArray()
    private val repo by lazy { VaultRepository(File(tmp.root, "vault.json"), { deviceKey }, keys) }

    private fun createWithBiometric(): String {
        val vault = repo.create(password, fast)
        val id = vault.add(EntryFields("A")).id
        vault.setSecret(id, SecretField.PASSWORD, "secret".toCharArray())
        repo.enableBiometric(vault, repo.biometricEnrollment())
        vault.close()
        return id
    }

    @Test
    fun `deverrouillage biometrique`() {
        val id = createWithBiometric()
        assertTrue(repo.isBiometricEnabled)
        val cipher = repo.biometricUnlock()!!
        repo.unlockWithBiometric(cipher).use { vault ->
            assertArrayEquals("secret".toCharArray(), vault.reveal(id, SecretField.PASSWORD))
        }
    }

    @Test
    fun `pas de slot sans activation`() {
        repo.create(password, fast).close()
        assertFalse(repo.isBiometricEnabled)
        assertNull(repo.biometricUnlock())
    }

    @Test
    fun `nouvelle empreinte enregistree`() {
        createWithBiometric()
        keys.invalidated = true
        try {
            repo.biometricUnlock()
            fail("clé invalidée acceptée")
        } catch (e: BiometricInvalidatedException) {
            assertTrue(e.cause is InvalidKeyException)
        }
        assertNull(keys.key)
        assertNull("slot supprimé", repo.biometricUnlock())
        repo.unlock(password).close() // le mot de passe fonctionne toujours
    }

    @Test
    fun `cle biometrique disparue`() {
        createWithBiometric()
        keys.delete()
        assertNull(repo.biometricUnlock())
        assertFalse(repo.isBiometricEnabled)
    }

    @Test
    fun `desactivation`() {
        createWithBiometric()
        repo.unlock(password).use(repo::disableBiometric)
        assertNull(repo.biometricUnlock())
        assertNull(keys.key)
    }

    @Test
    fun `changement de mot de passe desactive la biometrie`() {
        createWithBiometric()
        repo.unlock(password).use { repo.changePassword(it, password, "nouveau".toCharArray()) }
        assertNull(repo.biometricUnlock())
        assertNull(keys.key)
    }

    @Test(expected = CorruptedVaultException::class)
    fun `slot biometrique lie a l'en-tete`() {
        createWithBiometric()
        val cipher = repo.biometricUnlock()!!
        // Sel remplacé dans l'en-tête : le slot biométrique doit être refusé.
        val other = File(tmp.root, "vault.json")
        val json = other.readText()
        val salt = VaultJson.decodeFromString<VaultFile>(json).header.salt
        other.writeText(json.replace(b64(salt), b64(Secrets.randomBytes(16))))
        repo.unlockWithBiometric(cipher)
    }
}
