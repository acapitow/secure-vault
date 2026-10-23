package io.github.acapitow.vault.vault

import io.github.acapitow.vault.crypto.AesGcm
import io.github.acapitow.vault.crypto.DecryptionException
import io.github.acapitow.vault.crypto.KdfParams
import io.github.acapitow.vault.crypto.Secrets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class VaultTest {

    private var now = 1_000L
    private val vault = Vault(
        VaultHeader(1, KdfParams(), ByteArray(16), ByteArray(0)),
        AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE)),
        emptyList(),
        clock = { now },
    )

    @Test
    fun `ajout, modification, suppression`() {
        val entry = vault.add(EntryFields("Banque"))
        assertEquals(1_000L, entry.createdAt)
        now = 2_000L
        val updated = vault.update(entry.id, EntryFields("Banque", username = "bob"))
        assertEquals("bob", updated.fields.username)
        assertEquals(1_000L, updated.createdAt)
        assertEquals(2_000L, updated.updatedAt)
        vault.remove(entry.id)
        assertTrue(vault.entries.isEmpty())
    }

    @Test
    fun `identifiants uniques`() {
        val ids = (1..50).map { vault.add(EntryFields("e$it")).id }
        assertEquals(50, ids.toSet().size)
    }

    @Test
    fun `secret chiffre en memoire et absent de toString`() {
        val entry = vault.setSecret(vault.add(EntryFields("Mail")).id, SecretField.PASSWORD, "s3cret!".toCharArray())
        assertTrue(entry.has(SecretField.PASSWORD))
        assertFalse(entry.has(SecretField.NOTES))
        assertFalse(entry.toString().contains("s3cret"))
        assertFalse(entry.secrets.getValue(SecretField.PASSWORD).decodeToString().contains("s3cret"))
        assertArrayEquals("s3cret!".toCharArray(), vault.reveal(entry.id, SecretField.PASSWORD))
        assertNull(vault.reveal(entry.id, SecretField.NOTES))
    }

    @Test
    fun `suppression d'un secret`() {
        val id = vault.add(EntryFields("Mail")).id
        vault.setSecret(id, SecretField.PASSWORD, "x".toCharArray())
        vault.setSecret(id, SecretField.PASSWORD, null)
        assertNull(vault.reveal(id, SecretField.PASSWORD))
    }

    @Test
    fun `un secret deplace vers une autre entree ou un autre champ est refuse`() {
        val a = vault.setSecret(vault.add(EntryFields("A")).id, SecretField.PASSWORD, "aaa".toCharArray())
        val b = vault.add(EntryFields("B"))
        val blob = a.secrets.getValue(SecretField.PASSWORD)
        val swapped = listOf(
            b.copy(secrets = mapOf(SecretField.PASSWORD to blob)) to SecretField.PASSWORD,
            a.copy(secrets = mapOf(SecretField.NOTES to blob)) to SecretField.NOTES,
        )
        for ((forged, field) in swapped) {
            val copy = Vault(vault.header, vault.key(), listOf(forged), clock = { now })
            try {
                copy.reveal(forged.id, field)
                fail("bloc déplacé accepté")
            } catch (_: DecryptionException) {
            }
        }
    }

    @Test
    fun `champs invalides refuses`() {
        for (fields in listOf(EntryFields(" "), EntryFields("t".repeat(EntryFields.MAX_TITLE + 1)))) {
            try {
                vault.add(fields)
                fail("accepté : $fields")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test(expected = NoSuchElementException::class)
    fun `entree inconnue`() {
        vault.reveal("inconnue", SecretField.PASSWORD)
    }

    @Test
    fun `coffre ferme inutilisable`() {
        val id = vault.add(EntryFields("A")).id
        vault.close()
        assertTrue(vault.isClosed)
        for (op in listOf<() -> Unit>({ vault.entries }, { vault.reveal(id, SecretField.PASSWORD) }, { vault.add(EntryFields("B")) })) {
            try {
                op()
                fail("opération sur un coffre fermé")
            } catch (_: IllegalStateException) {
            }
        }
    }
}
