package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.toHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

class OtpAuthUriTest {

    private val secret = "JBSWY3DPEHPK3PXP"

    @Test
    fun `exemple de la documentation Key Uri`() {
        val account = OtpAuthUri.parse("otpauth://totp/Example:alice@google.com?secret=$secret&issuer=Example")
        assertEquals("Example", account.issuer)
        assertEquals("alice@google.com", account.account)
        assertEquals("48656c6c6f21deadbeef", account.secret.toHex())
        assertEquals(TotpParams(), account.params)
    }

    @Test
    fun `tous les parametres`() {
        val account = OtpAuthUri.parse(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=$secret&issuer=ACME%20Co" +
                "&algorithm=SHA256&digits=8&period=60&image=https%3A%2F%2Fexample.com%2Flogo.png",
        )
        assertEquals("ACME Co", account.issuer)
        assertEquals("john.doe@email.com", account.account)
        assertEquals(TotpParams(OtpAlgorithm.SHA256, 8, 60), account.params)
    }

    @Test
    fun `libelle sans emetteur, espace apres les deux-points, schema en majuscules`() {
        assertEquals("", OtpAuthUri.parse("otpauth://totp/bob?secret=$secret").issuer)
        val account = OtpAuthUri.parse("OTPAUTH://TOTP/GitHub:%20bob?secret=$secret")
        assertEquals("GitHub", account.issuer)
        assertEquals("bob", account.account)
    }

    @Test
    fun `le secret n'apparait pas dans toString`() {
        val account = OtpAuthUri.parse("otpauth://totp/Example:alice?secret=$secret")
        assertFalse(account.toString().contains(secret, ignoreCase = true))
        assertFalse(account.toString().contains(account.secret.toHex()))
    }

    @Test
    fun `wipe efface le secret`() {
        val account = OtpAuthUri.parse("otpauth://totp/Example:alice?secret=$secret")
        account.wipe()
        assertArrayEquals(ByteArray(10), account.secret)
    }

    @Test
    fun `URI invalides refusees`() {
        val base = "otpauth://totp/Example:alice?secret=$secret"
        val bad = listOf(
            "https://totp/Example:alice?secret=$secret",
            "otpauth://hotp/Example:alice?secret=$secret&counter=0",
            "otpauth://totp/Example:alice",
            "otpauth://totp/Example:alice?secret=",
            "otpauth://totp/Example:alice?secret=JBSWY3DP", // 40 bits
            "otpauth://totp/Example:alice?secret=JBSW1",
            "otpauth://totp/?secret=$secret",
            "otpauth://totp/Example:?secret=$secret",
            "$base&issuer=Autre",
            "$base&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "$base&algorithm=MD5",
            "$base&digits=10",
            "$base&digits=-6",
            "$base&digits=99999999999",
            "$base&period=0",
            "$base#frag",
            "otpauth://totp/Ex%G1:alice?secret=$secret",
            "otpauth://totp/Ex%4?secret=$secret",
            "otpauth://totp/Ex%FF:alice?secret=$secret",
            "otpauth://totp/Example:alice?secret=$secret&x=" + "a".repeat(OtpAuthUri.MAX_LENGTH),
        )
        for (uri in bad) {
            try {
                OtpAuthUri.parse(uri)
                fail("accepté : $uri")
            } catch (_: IllegalArgumentException) {
            }
        }
    }
}
