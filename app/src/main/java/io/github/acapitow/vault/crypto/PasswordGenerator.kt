package io.github.acapitow.vault.crypto

import java.security.SecureRandom
import kotlin.math.log2

/**
 * Générateur de mots de passe aléatoires (MASVS-CRYPTO-1 : CSPRNG uniquement).
 *
 * `SecureRandom.nextInt(n)` tire sans biais modulo. Au moins un caractère de
 * chaque classe choisie est garanti (exigence fréquente des sites), puis
 * l'ordre est mélangé (Fisher-Yates) pour que ces caractères imposés ne
 * soient pas toujours en tête.
 */
object PasswordGenerator {

    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 128

    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!#\$%&*+-=?@^_~"

    private val random = SecureRandom()

    data class Options(
        val length: Int = 20,
        val upper: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true,
    ) {
        internal val classes: List<String>
            get() = buildList {
                add(LOWER)
                if (upper) add(UPPER)
                if (digits) add(DIGITS)
                if (symbols) add(SYMBOLS)
            }

        /** Entropie approximative, en bits (≈ 124 avec les valeurs par défaut). */
        val entropyBits: Double get() = length * log2(classes.sumOf { it.length }.toDouble())
    }

    /** L'appelant doit effacer le tableau retourné. */
    fun generate(options: Options = Options()): CharArray {
        val classes = options.classes
        require(options.length in MIN_LENGTH..MAX_LENGTH) { "longueur hors bornes : ${options.length}" }
        val alphabet = classes.joinToString("")
        val out = CharArray(options.length)
        classes.forEachIndexed { i, chars -> out[i] = chars[random.nextInt(chars.length)] }
        for (i in classes.size until out.size) out[i] = alphabet[random.nextInt(alphabet.length)]
        for (i in out.size - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val tmp = out[i]
            out[i] = out[j]
            out[j] = tmp
        }
        return out
    }
}
