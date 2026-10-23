package io.github.acapitow.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

class AesGcmTest {

    private val key = AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE))
    private val plaintext = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP".toByteArray()
    private val aad = "entry-42".toByteArray()

    @Test
    fun `vecteur NIST GCM cas 13 (texte vide)`() {
        val zeroKey = AesGcm.key(ByteArray(32))
        val out = AesGcm.open(zeroKey, ByteArray(12), "530f8afbc74536b9a963b4f1c4cb738b".hex(), ByteArray(0))
        assertEquals(0, out.size)
    }

    @Test
    fun `vecteur NIST GCM cas 14`() {
        val zeroKey = AesGcm.key(ByteArray(32))
        val sealed = "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919".hex()
        assertArrayEquals(ByteArray(16), AesGcm.open(zeroKey, ByteArray(12), sealed, ByteArray(0)))
    }

    @Test
    fun `aller-retour`() {
        val blob = AesGcm.encrypt(key, plaintext, aad)
        assertEquals(plaintext.size + AesGcm.OVERHEAD, blob.size)
        assertEquals(AesGcm.VERSION, blob[0])
        assertArrayEquals(plaintext, AesGcm.decrypt(key, blob, aad))
    }

    @Test
    fun `texte vide accepte`() {
        val blob = AesGcm.encrypt(key, ByteArray(0))
        assertEquals(0, AesGcm.decrypt(key, blob).size)
    }

    @Test
    fun `chaque chiffrement utilise un nonce different`() {
        val nonces = (1..100).map { AesGcm.encrypt(key, plaintext).copyOfRange(1, 1 + AesGcm.NONCE_SIZE).toHex() }
        assertEquals(100, nonces.toSet().size)
    }

    @Test
    fun `toute alteration d'un octet est detectee`() {
        val blob = AesGcm.encrypt(key, plaintext, aad)
        for (i in blob.indices) {
            val tampered = blob.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            assertRejected("octet $i") { AesGcm.decrypt(key, tampered, aad) }
        }
    }

    @Test
    fun `mauvaise AAD refusee`() {
        val blob = AesGcm.encrypt(key, plaintext, aad)
        assertRejected("AAD") { AesGcm.decrypt(key, blob, "entry-43".toByteArray()) }
    }

    @Test
    fun `mauvaise cle refusee`() {
        val blob = AesGcm.encrypt(key, plaintext, aad)
        val other = AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE))
        assertRejected("clé") { AesGcm.decrypt(other, blob, aad) }
    }

    @Test
    fun `bloc tronque refuse`() {
        val blob = AesGcm.encrypt(key, plaintext, aad)
        for (size in listOf(0, 1, AesGcm.OVERHEAD - 1, blob.size - 1)) {
            assertRejected("taille $size") { AesGcm.decrypt(key, blob.copyOf(size), aad) }
        }
    }

    @Test
    fun `le texte clair n'apparait pas dans le bloc chiffre`() {
        val blob = AesGcm.encrypt(key, plaintext)
        assertFalse(blob.toHex().contains(plaintext.copyOf(8).toHex()))
    }

    @Test
    fun `API en deux temps compatible avec l'API simple`() {
        val blob = AesGcm.encrypt(AesGcm.encryptor(key), plaintext, aad)
        assertArrayEquals(plaintext, AesGcm.decrypt(key, blob, aad))
        assertArrayEquals(plaintext, AesGcm.decrypt(AesGcm.decryptor(key, blob), blob, aad))
        assertRejected("AAD") { AesGcm.decrypt(AesGcm.decryptor(key, blob), blob, "autre".toByteArray()) }
        assertRejected("bloc tronqué") { AesGcm.decryptor(key, blob.copyOf(AesGcm.OVERHEAD - 1)) }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `cle de 128 bits refusee`() {
        AesGcm.key(ByteArray(16))
    }

    private fun assertRejected(what: String, block: () -> Unit) {
        try {
            block()
            fail("$what : altération non détectée")
        } catch (_: DecryptionException) {
        }
    }
}
