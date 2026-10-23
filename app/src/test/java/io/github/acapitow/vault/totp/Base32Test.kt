package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.toHex
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class Base32Test {

    private fun decode(s: String) = Base32.decode(s.toCharArray())

    @Test
    fun `vecteurs RFC 4648`() {
        val vectors = mapOf(
            "" to "",
            "MY======" to "f",
            "MZXQ====" to "fo",
            "MZXW6===" to "foo",
            "MZXW6YQ=" to "foob",
            "MZXW6YTB" to "fooba",
            "MZXW6YTBOI======" to "foobar",
        )
        for ((encoded, plain) in vectors) {
            assertEquals(encoded, plain, String(decode(encoded)))
        }
    }

    @Test
    fun `bourrage facultatif, casse et espaces toleres`() {
        assertEquals("foobar", String(decode("MZXW6YTBOI")))
        assertEquals("48656c6c6f21deadbeef", decode("jbsw y3dp ehpk 3pxp").toHex())
    }

    @Test
    fun `entrees invalides refusees`() {
        for (bad in listOf("MZXW6YT1", "MZXW6YT8", "MZXW-6YTB", "A", "ABC", "ABCDEF", "MY=A====", "MZXW6YTBé")) {
            try {
                decode(bad)
                fail("accepté : $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
    }
}
