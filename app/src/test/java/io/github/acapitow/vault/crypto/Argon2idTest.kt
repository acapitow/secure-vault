package io.github.acapitow.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class Argon2idTest {

    // Paramètres faibles mais valides, pour que les tests restent rapides.
    private val fast = KdfParams(memoryKiB = KdfParams.MIN_MEMORY_KIB, iterations = 2, parallelism = 1)
    private val salt = ByteArray(Argon2id.SALT_SIZE) { it.toByte() }

    @Test
    fun `vecteur de test RFC 9106 section 5_3`() {
        val tag = Argon2id.raw(
            password = ByteArray(32) { 0x01 },
            salt = ByteArray(16) { 0x02 },
            memoryKiB = 32,
            iterations = 3,
            parallelism = 4,
            outputSize = 32,
            secret = ByteArray(8) { 0x03 },
            associatedData = ByteArray(12) { 0x04 },
        )
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", tag.toHex())
    }

    @Test
    fun `la derivation est deterministe`() {
        val a = Argon2id.deriveKey("correct horse".toCharArray(), salt, fast)
        val b = Argon2id.deriveKey("correct horse".toCharArray(), salt, fast)
        assertArrayEquals(a, b)
        assertEquals(Argon2id.KEY_SIZE, a.size)
    }

    @Test
    fun `un autre sel ou un autre mot de passe donne une autre cle`() {
        val base = Argon2id.deriveKey("correct horse".toCharArray(), salt, fast)
        val otherSalt = Argon2id.deriveKey("correct horse".toCharArray(), salt.reversedArray(), fast)
        val otherPassword = Argon2id.deriveKey("correct hors3".toCharArray(), salt, fast)
        assertFalse(base.contentEquals(otherSalt))
        assertFalse(base.contentEquals(otherPassword))
    }

    @Test
    fun `le mot de passe est encode en UTF-8`() {
        val viaChars = Argon2id.deriveKey("mötdepässe€".toCharArray(), salt, fast)
        val viaBytes = Argon2id.raw("mötdepässe€".toByteArray(Charsets.UTF_8), salt, fast.memoryKiB, 2, 1, 32)
        assertArrayEquals(viaBytes, viaChars)
    }

    @Test
    fun `le mot de passe fourni n'est pas modifie`() {
        val password = "secret".toCharArray()
        Argon2id.deriveKey(password, salt, fast)
        assertArrayEquals("secret".toCharArray(), password)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `memoire trop faible refusee (attaque par degradation)`() {
        Argon2id.deriveKey("x".toCharArray(), salt, KdfParams(memoryKiB = 1024))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `une seule iteration refusee`() {
        Argon2id.deriveKey("x".toCharArray(), salt, KdfParams(iterations = 1))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `memoire excessive refusee (deni de service)`() {
        KdfParams(memoryKiB = 4 * 1024 * 1024).validate()
    }

    @Test(expected = IllegalArgumentException::class)
    fun `sel de mauvaise taille refuse`() {
        Argon2id.deriveKey("x".toCharArray(), ByteArray(8), fast)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `mot de passe vide refuse`() {
        Argon2id.deriveKey(CharArray(0), salt, fast)
    }

    @Test
    fun `les parametres par defaut sont valides`() {
        KdfParams().validate()
    }
}
