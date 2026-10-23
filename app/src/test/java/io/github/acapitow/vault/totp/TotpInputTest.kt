package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.toHex
import org.junit.Assert.assertEquals
import org.junit.Test

class TotpInputTest {

    @Test
    fun `cle Base32 saisie a la main`() {
        val account = TotpInput.parse("jbsw y3dp ehpk 3pxp".toCharArray(), " GitHub ", "alice")
        assertEquals("GitHub", account.issuer)
        assertEquals("alice", account.account)
        assertEquals("48656c6c6f21deadbeef", account.secret.toHex())
    }

    @Test
    fun `lien otpauth, emetteur et compte du lien prioritaires`() {
        val account = TotpInput.parse("OTPAUTH://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP".toCharArray(), "Autre", "x")
        assertEquals("ACME", account.issuer)
        assertEquals("bob", account.account)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `cle invalide refusee`() {
        TotpInput.parse("pas une cle !".toCharArray(), "", "alice")
    }

    @Test(expected = IllegalArgumentException::class)
    fun `compte vide refuse`() {
        TotpInput.parse("JBSWY3DPEHPK3PXP".toCharArray(), "", " ")
    }
}
