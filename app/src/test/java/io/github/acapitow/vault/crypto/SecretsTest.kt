package io.github.acapitow.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecretsTest {

    @Test
    fun `utf8 sans String`() {
        assertEquals("61c3a9e282ac", Secrets.utf8("aé€".toCharArray()).toHex())
        assertEquals("f09f9491", Secrets.utf8("🔑".toCharArray()).toHex())
    }

    @Test
    fun `chars inverse de utf8`() {
        val text = "aé€🔑".toCharArray()
        assertArrayEquals(text, Secrets.chars(Secrets.utf8(text)))
    }

    @Test(expected = java.nio.charset.CharacterCodingException::class)
    fun `octets UTF-8 invalides refuses`() {
        Secrets.chars(byteArrayOf(0xff.toByte()))
    }

    @Test(expected = java.nio.charset.CharacterCodingException::class)
    fun `surrogate isole refuse plutot que remplace`() {
        Secrets.utf8(charArrayOf('a', '\uD83D'))
    }

    @Test
    fun `wipe met a zero`() {
        val a = byteArrayOf(1, 2, 3)
        val c = charArrayOf('x', 'y')
        Secrets.wipe(a, null)
        Secrets.wipe(c)
        assertArrayEquals(ByteArray(3), a)
        assertArrayEquals(CharArray(2), c)
    }

    @Test
    fun `useAndWipe efface meme en cas d'exception`() {
        val a = byteArrayOf(9, 9)
        runCatching { a.useAndWipe { error("boom") } }
        assertArrayEquals(ByteArray(2), a)
    }

    @Test
    fun `comparaison en temps constant`() {
        assertTrue(Secrets.constantTimeEquals(byteArrayOf(1, 2), byteArrayOf(1, 2)))
        assertFalse(Secrets.constantTimeEquals(byteArrayOf(1, 2), byteArrayOf(1, 3)))
        assertFalse(Secrets.constantTimeEquals(byteArrayOf(1, 2), byteArrayOf(1)))
    }

    @Test
    fun `octets aleatoires`() {
        assertEquals(32, Secrets.randomBytes(32).size)
        assertFalse(Secrets.randomBytes(32).contentEquals(Secrets.randomBytes(32)))
    }
}
