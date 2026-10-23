package io.github.acapitow.vault.totp

/**
 * Décodage Base32 (RFC 4648, alphabet standard), format des secrets TOTP.
 *
 * L'entrée est un CharArray pour que le secret saisi à la main puisse être
 * effacé après décodage. On tolère la casse, les espaces (affichage en groupes
 * de 4) et le bourrage `=` final ; tout autre caractère est refusé plutôt
 * qu'ignoré, pour ne jamais produire silencieusement un mauvais secret.
 */
object Base32 {

    /** Nombres de caractères utiles modulo 8 qui ne correspondent à aucun nombre entier d'octets. */
    private val INVALID_REMAINDERS = setOf(1, 3, 6)

    /** @throws IllegalArgumentException si l'entrée n'est pas du Base32 valide. */
    fun decode(input: CharArray): ByteArray {
        var count = 0
        var padding = false
        for (c in input) {
            when {
                c == ' ' -> continue
                c == '=' -> padding = true
                padding || value(c) < 0 -> throw IllegalArgumentException("caractère Base32 invalide")
                else -> count++
            }
        }
        require(count % 8 !in INVALID_REMAINDERS) { "longueur Base32 invalide" }

        val out = ByteArray(count * 5 / 8)
        var buffer = 0
        var bits = 0
        var index = 0
        for (c in input) {
            val v = value(c)
            if (v < 0) continue // espace ou bourrage, déjà validés
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out[index++] = (buffer shr bits).toByte()
                buffer = buffer and ((1 shl bits) - 1)
            }
        }
        return out
    }

    private fun value(c: Char): Int = when (c) {
        in 'A'..'Z' -> c - 'A'
        in 'a'..'z' -> c - 'a'
        in '2'..'7' -> c - '2' + 26
        else -> -1
    }
}
