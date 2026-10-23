package io.github.acapitow.vault.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordGeneratorTest {

    @Test
    fun `longueur et classes respectees`() {
        repeat(200) {
            val password = String(PasswordGenerator.generate())
            assertEquals(20, password.length)
            assertTrue(password, password.any(Char::isLowerCase))
            assertTrue(password, password.any(Char::isUpperCase))
            assertTrue(password, password.any(Char::isDigit))
            assertTrue(password, password.any { !it.isLetterOrDigit() })
        }
    }

    @Test
    fun `classes desactivees absentes`() {
        val options = PasswordGenerator.Options(length = 64, upper = false, digits = false, symbols = false)
        repeat(50) {
            assertTrue(String(PasswordGenerator.generate(options)).all { it in 'a'..'z' })
        }
    }

    @Test
    fun `pas de doublon sur 1000 tirages`() {
        assertEquals(1000, (1..1000).map { String(PasswordGenerator.generate()) }.toSet().size)
    }

    @Test
    fun `tous les caracteres de l'alphabet apparaissent`() {
        val seen = (1..500).flatMap { PasswordGenerator.generate().toList() }.toSet()
        assertEquals(26 + 26 + 10 + 14, seen.size)
    }

    @Test
    fun `entropie par defaut`() {
        assertEquals(124.9, PasswordGenerator.Options().entropyBits, 0.1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `longueur trop courte refusee`() {
        PasswordGenerator.generate(PasswordGenerator.Options(length = 7))
    }
}
