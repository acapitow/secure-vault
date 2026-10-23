package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.Secrets
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Analyse des URI `otpauth://totp/...` contenues dans les QR codes
 * (format « Key Uri » de Google Authenticator).
 *
 * Un QR code est une entrée non fiable (MASVS-CODE-4) : l'analyse est stricte.
 * Un paramètre inconnu est ignoré, mais une valeur invalide, un paramètre
 * dupliqué ou un émetteur contradictoire entraîne un refus plutôt qu'un repli
 * silencieux sur une valeur par défaut, qui donnerait des codes faux.
 *
 * Limite assumée : l'URI arrive du lecteur de QR code sous forme de String,
 * qu'on ne peut pas effacer. Le secret décodé, lui, est un ByteArray.
 */
object OtpAuthUri {

    const val MAX_LENGTH = 2048

    private const val PREFIX = "otpauth://"

    /** @throws IllegalArgumentException si l'URI est invalide ou non prise en charge. */
    fun parse(uri: String): TotpAccount {
        require(uri.length <= MAX_LENGTH) { "URI trop longue" }
        require(uri.regionMatches(0, PREFIX, 0, PREFIX.length, ignoreCase = true)) { "schéma otpauth attendu" }
        require('#' !in uri) { "fragment interdit" }

        val rest = uri.substring(PREFIX.length)
        val type = rest.substringBefore('/', "")
        require(type.equals("totp", ignoreCase = true)) { "seul le type totp est pris en charge" }

        val label = percentDecode(rest.substringAfter('/').substringBefore('?'))
        val query = parseQuery(rest.substringAfter('?', ""))

        val labelIssuer = label.substringBefore(':', "").trim().ifEmpty { null }
        val account = label.substringAfter(':').trim()
        val paramIssuer = query["issuer"]?.trim()?.ifEmpty { null }
        require(labelIssuer == null || paramIssuer == null || labelIssuer == paramIssuer) { "émetteurs contradictoires" }

        val params = TotpParams(
            algorithm = query["algorithm"]?.let(::algorithm) ?: OtpAlgorithm.SHA1,
            digits = query["digits"]?.let(::integer) ?: 6,
            period = query["period"]?.let(::integer) ?: 30,
        )
        val secret = decodeSecret(requireNotNull(query["secret"]) { "secret manquant" })
        return try {
            TotpAccount(paramIssuer ?: labelIssuer ?: "", account, secret, params)
        } catch (e: IllegalArgumentException) {
            Secrets.wipe(secret)
            throw e
        }
    }

    private fun parseQuery(query: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val key = percentDecode(pair.substringBefore('=')).lowercase()
            require(key !in result) { "paramètre dupliqué : $key" }
            result[key] = percentDecode(pair.substringAfter('=', ""))
        }
        return result
    }

    private fun decodeSecret(value: String): ByteArray {
        val chars = value.toCharArray()
        return try {
            Base32.decode(chars)
        } finally {
            Secrets.wipe(chars)
        }
    }

    private fun algorithm(value: String): OtpAlgorithm =
        OtpAlgorithm.entries.firstOrNull { it.name.equals(value, ignoreCase = true) }
            ?: throw IllegalArgumentException("algorithme non pris en charge : $value")

    private fun integer(value: String): Int =
        requireNotNull(value.takeIf { it.length <= 9 && it.all(Char::isDigit) }?.toInt()) { "entier invalide : $value" }

    /** Décodage %XX strict (RFC 3986) ; `+` reste littéral. Les octets obtenus doivent former de l'UTF-8 valide. */
    private fun percentDecode(s: String): String {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream(bytes.size)
        var i = 0
        while (i < bytes.size) {
            if (bytes[i] == '%'.code.toByte()) {
                require(i + 2 < bytes.size) { "encodage % tronqué" }
                val hi = Character.digit(bytes[i + 1].toInt(), 16)
                val lo = Character.digit(bytes[i + 2].toInt(), 16)
                require(hi >= 0 && lo >= 0) { "encodage % invalide" }
                out.write((hi shl 4) or lo)
                i += 3
            } else {
                out.write(bytes[i].toInt())
                i++
            }
        }
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        return try {
            decoder.decode(ByteBuffer.wrap(out.toByteArray())).toString()
        } catch (e: CharacterCodingException) {
            throw IllegalArgumentException("UTF-8 invalide", e)
        }
    }
}
