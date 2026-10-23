package io.github.acapitow.vault.vault

import io.github.acapitow.vault.crypto.AesGcm
import io.github.acapitow.vault.crypto.KdfParams
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.totp.OtpAuthUri
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class VaultRepositoryTest {

    @get:Rule
    val tmp = TemporaryFolder()

    // Paramètres faibles mais valides, pour que les tests restent rapides.
    private val fast = KdfParams(memoryKiB = KdfParams.MIN_MEMORY_KIB, iterations = 2, parallelism = 1)
    private val deviceKey = AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE))
    private val password = "correct horse battery staple".toCharArray()

    private val file by lazy { File(tmp.root, "vault.json") }
    private fun repo(key: javax.crypto.SecretKey = deviceKey) = VaultRepository(file, { key }, clock = { 1_000L })

    private fun createSample(): String {
        val vault = repo().create(password, fast)
        val entry = vault.add(EntryFields("GitHub", "alice", "https://github.com"))
        vault.setSecret(entry.id, SecretField.PASSWORD, "hunter2-ÉÀ-🔑".toCharArray())
        vault.setSecret(entry.id, SecretField.NOTES, "codes de secours : 1234-5678".toCharArray())
        vault.setTotp(entry.id, OtpAuthUri.parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP"))
        repo().save(vault)
        vault.close()
        return entry.id
    }

    @Test
    fun `aller-retour complet`() {
        val id = createSample()
        repo().unlock(password).use { vault ->
            val entry = vault.get(id)
            assertEquals(EntryFields("GitHub", "alice", "https://github.com"), entry.fields)
            assertArrayEquals("hunter2-ÉÀ-🔑".toCharArray(), vault.reveal(id, SecretField.PASSWORD))
            assertArrayEquals("codes de secours : 1234-5678".toCharArray(), vault.reveal(id, SecretField.NOTES))
            val totp = vault.totp(id)!!
            assertEquals("GitHub", totp.issuer)
            assertEquals(
                OtpAuthUri.parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP").code(59),
                totp.code(59),
            )
        }
    }

    @Test
    fun `aucun texte clair dans le fichier`() {
        createSample()
        val raw = file.readText()
        for (needle in listOf("GitHub", "alice", "github.com", "hunter2", "secours", "JBSWY3DP")) {
            assertFalse("trouvé : $needle", raw.contains(needle, ignoreCase = true))
        }
        assertFalse(File(tmp.root, "vault.json.tmp").exists())
    }

    @Test(expected = WrongPasswordException::class)
    fun `mauvais mot de passe refuse`() {
        createSample()
        repo().unlock("Correct horse battery staple".toCharArray())
    }

    @Test(expected = CorruptedVaultException::class)
    fun `fichier inutilisable sans la cle de l'appareil`() {
        createSample()
        repo(AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE))).unlock(password)
    }

    @Test
    fun `alteration de l'en-tete detectee avant la derivation`() {
        createSample()
        val tampered = listOf<(JsonObject) -> JsonObject>(
            { it.withHeader("kdf", it.header("kdf").replacing("memoryKiB", JsonPrimitive(19_457))) },
            { it.withHeader("kdf", it.header("kdf").replacing("iterations", JsonPrimitive(1))) }, // dégradation sous le plancher
            { it.withHeader("salt", JsonPrimitive(b64(ByteArray(16)))) },
            { it.withHeader("format", JsonPrimitive(2)) },
            { it.replacing("payload", JsonPrimitive(b64(ByteArray(64)))) },
        )
        val original = file.readText()
        for (change in tampered) {
            val json = VaultJson.parseToJsonElement(original).jsonObject
            file.writeText(change(json).toString())
            try {
                repo().unlock(password)
                fail("altération acceptée")
            } catch (_: CorruptedVaultException) {
            }
        }
    }

    @Test
    fun `fichier tronque ou non JSON refuse`() {
        createSample()
        val original = file.readText()
        for (content in listOf("", "{}", "null", original.dropLast(10))) {
            file.writeText(content)
            try {
                repo().unlock(password)
                fail("accepté : $content")
            } catch (_: CorruptedVaultException) {
            }
        }
    }

    @Test
    fun `changement de mot de passe`() {
        val id = createSample()
        val newPassword = "nouveau mot de passe".toCharArray()
        repo().unlock(password).use { vault ->
            try {
                repo().changePassword(vault, "faux".toCharArray(), newPassword)
                fail("ancien mot de passe non vérifié")
            } catch (_: WrongPasswordException) {
            }
            repo().changePassword(vault, password, newPassword)
        }
        try {
            repo().unlock(password)
            fail("l'ancien mot de passe ouvre encore le coffre")
        } catch (_: WrongPasswordException) {
        }
        repo().unlock(newPassword).use { vault ->
            assertArrayEquals("hunter2-ÉÀ-🔑".toCharArray(), vault.reveal(id, SecretField.PASSWORD))
        }
    }

    @Test
    fun `pas d'ecrasement d'un coffre existant`() {
        createSample()
        try {
            repo().create(password, fast)
            fail("coffre écrasé")
        } catch (_: IllegalStateException) {
        }
        assertTrue(repo().unlock(password).entries.isNotEmpty())
    }

    private fun JsonObject.header(key: String) = getValue("header").jsonObject.getValue(key).jsonObject

    private fun JsonObject.replacing(key: String, value: JsonElement) = JsonObject(this + (key to value))

    private fun JsonObject.withHeader(key: String, value: JsonElement) =
        replacing("header", getValue("header").jsonObject.replacing(key, value))
}
