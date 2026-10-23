package io.github.acapitow.vault.totp

import org.junit.Assert.assertEquals
import org.junit.Test

class TotpTest {

    private val seed20 = "12345678901234567890".toByteArray()
    private val seed32 = "12345678901234567890123456789012".toByteArray()
    private val seed64 = "1234567890123456789012345678901234567890123456789012345678901234".toByteArray()

    @Test
    fun `vecteurs HOTP RFC 4226 annexe D`() {
        val expected = listOf(
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        )
        expected.forEachIndexed { counter, code ->
            assertEquals("compteur $counter", code, Totp.hotp(seed20, counter.toLong(), 6, OtpAlgorithm.SHA1))
        }
    }

    @Test
    fun `vecteurs TOTP RFC 6238 annexe B`() {
        // heure, SHA1, SHA256, SHA512
        val vectors = listOf(
            listOf(59L, "94287082", "46119246", "90693936"),
            listOf(1111111109L, "07081804", "68084774", "25091201"),
            listOf(1111111111L, "14050471", "67062674", "99943326"),
            listOf(1234567890L, "89005924", "91819424", "93441116"),
            listOf(2000000000L, "69279037", "90698825", "38618901"),
            listOf(20000000000L, "65353130", "77737706", "47863826"),
        )
        val seeds = mapOf(OtpAlgorithm.SHA1 to seed20, OtpAlgorithm.SHA256 to seed32, OtpAlgorithm.SHA512 to seed64)
        for (v in vectors) {
            val time = v[0] as Long
            OtpAlgorithm.entries.forEachIndexed { i, algorithm ->
                val params = TotpParams(algorithm, digits = 8, period = 30)
                assertEquals("$algorithm à $time", v[i + 1], Totp.code(seeds.getValue(algorithm), params, time))
            }
        }
    }

    @Test
    fun `zeros de tete conserves`() {
        assertEquals(8, Totp.code(seed20, TotpParams(digits = 8), 1111111109L).length)
        assertEquals("081804", Totp.code(seed20, TotpParams(), 1111111109L))
    }

    @Test
    fun `secondes restantes`() {
        val params = TotpParams()
        assertEquals(30, Totp.secondsRemaining(params, 0))
        assertEquals(1, Totp.secondsRemaining(params, 59))
        assertEquals(30, Totp.secondsRemaining(params, 60))
    }

    @Test
    fun `meme code sur toute la periode`() {
        val params = TotpParams()
        assertEquals(Totp.code(seed20, params, 60), Totp.code(seed20, params, 89))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `heure negative refusee`() {
        Totp.code(seed20, TotpParams(), -1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `cinq chiffres refuses`() {
        Totp.code(seed20, TotpParams(digits = 5), 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `periode nulle refusee`() {
        Totp.code(seed20, TotpParams(period = 0), 0)
    }
}
