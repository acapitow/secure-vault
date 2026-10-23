package io.github.acapitow.vault.crypto

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Outils de manipulation des secrets en mémoire (MASVS-STORAGE-2 / MASVS-CRYPTO-1).
 *
 * Les secrets transitent en ByteArray / CharArray, jamais en String : une String
 * est immuable, internée parfois, et reste en mémoire jusqu'au passage du GC.
 * Un tableau peut être écrasé dès qu'on n'en a plus besoin.
 */
object Secrets {

    private val random = SecureRandom()

    /** Octets aléatoires issus du CSPRNG du système (/dev/urandom sous Android). */
    fun randomBytes(size: Int): ByteArray {
        require(size > 0) { "taille invalide : $size" }
        return ByteArray(size).also(random::nextBytes)
    }

    /** Écrase le contenu des tableaux. À appeler dans un `finally`. */
    fun wipe(vararg arrays: ByteArray?) {
        for (array in arrays) array?.fill(0)
    }

    fun wipe(chars: CharArray?) {
        chars?.fill('\u0000')
    }

    /**
     * Comparaison en temps constant (indépendant de la position de la première
     * différence), pour ne pas offrir d'oracle temporel.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /**
     * Encode un mot de passe en UTF-8 sans passer par une String.
     * Le tampon intermédiaire de l'encodeur est effacé ; l'appelant doit
     * effacer le résultat.
     */
    fun utf8(chars: CharArray): ByteArray {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val buffer: ByteBuffer = encoder.encode(CharBuffer.wrap(chars))
        return try {
            ByteArray(buffer.remaining()).also(buffer::get)
        } finally {
            if (buffer.hasArray()) buffer.array().fill(0)
        }
    }
}

/** Exécute [block] puis efface le tableau, même en cas d'exception. */
inline fun <R> ByteArray.useAndWipe(block: (ByteArray) -> R): R =
    try {
        block(this)
    } finally {
        fill(0)
    }
