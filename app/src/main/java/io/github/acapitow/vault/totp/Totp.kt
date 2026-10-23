package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.Secrets
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

enum class OtpAlgorithm(val macName: String) {
    SHA1("HmacSHA1"),
    SHA256("HmacSHA256"),
    SHA512("HmacSHA512"),
}

/** Paramètres d'un compte TOTP. Les valeurs par défaut sont celles de Google Authenticator. */
@Serializable
data class TotpParams(
    val algorithm: OtpAlgorithm = OtpAlgorithm.SHA1,
    val digits: Int = 6,
    val period: Int = 30,
) {
    fun validate(): TotpParams = apply {
        require(digits in MIN_DIGITS..MAX_DIGITS) { "nombre de chiffres hors bornes : $digits" }
        require(period in MIN_PERIOD..MAX_PERIOD) { "période hors bornes : $period s" }
    }

    companion object {
        const val MIN_DIGITS = 6 // RFC 4226 : au moins 6 chiffres.
        const val MAX_DIGITS = 8 // 10^8 tient dans les 31 bits de la troncature.
        const val MIN_PERIOD = 10
        const val MAX_PERIOD = 300
    }
}

/**
 * Mots de passe à usage unique : HOTP (RFC 4226) et TOTP (RFC 6238).
 *
 * L'heure est passée en paramètre (secondes Unix) plutôt que lue ici : le
 * calcul reste déterministe et testable avec les vecteurs des RFC.
 */
object Totp {

    private val POWERS = intArrayOf(1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)

    fun code(secret: ByteArray, params: TotpParams, epochSeconds: Long): String {
        params.validate()
        require(epochSeconds >= 0) { "heure négative" }
        return hotp(secret, epochSeconds / params.period, params.digits, params.algorithm)
    }

    /** Secondes avant le changement de code (entre 1 et `period`). */
    fun secondsRemaining(params: TotpParams, epochSeconds: Long): Int {
        params.validate()
        require(epochSeconds >= 0) { "heure négative" }
        return params.period - (epochSeconds % params.period).toInt()
    }

    /**
     * HOTP : HMAC(secret, compteur), puis troncature dynamique (RFC 4226 §5.3).
     * Le secret n'est pas modifié ; l'empreinte intermédiaire est effacée.
     */
    fun hotp(secret: ByteArray, counter: Long, digits: Int, algorithm: OtpAlgorithm): String {
        require(secret.isNotEmpty()) { "secret vide" }
        require(digits in TotpParams.MIN_DIGITS..TotpParams.MAX_DIGITS) { "nombre de chiffres hors bornes : $digits" }
        val mac = Mac.getInstance(algorithm.macName)
        mac.init(SecretKeySpec(secret, algorithm.macName))
        val hash = mac.doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(counter).array())
        try {
            val offset = hash[hash.size - 1].toInt() and 0x0f
            val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
                ((hash[offset + 1].toInt() and 0xff) shl 16) or
                ((hash[offset + 2].toInt() and 0xff) shl 8) or
                (hash[offset + 3].toInt() and 0xff)
            return (binary % POWERS[digits]).toString().padStart(digits, '0')
        } finally {
            Secrets.wipe(hash)
        }
    }
}
