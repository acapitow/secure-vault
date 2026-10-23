package io.github.acapitow.vault.crypto

import kotlinx.serialization.Serializable
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Paramètres Argon2id. Ils sont stockés en clair avec le coffre pour pouvoir
 * être relevés plus tard sans casser les coffres existants.
 *
 * Les valeurs lues depuis le disque passent par [validate] : un attaquant qui
 * modifierait le fichier ne doit pas pouvoir imposer des paramètres faibles
 * (attaque par dégradation).
 */
@Serializable
data class KdfParams(
    val memoryKiB: Int = 65_536, // 64 Mio
    val iterations: Int = 3,
    val parallelism: Int = 1,
) {
    fun validate(): KdfParams = apply {
        // Planchers OWASP (Password Storage Cheat Sheet) : 19 Mio / t=2 / p=1.
        require(memoryKiB in MIN_MEMORY_KIB..MAX_MEMORY_KIB) { "mémoire Argon2 hors bornes : $memoryKiB KiB" }
        require(iterations in MIN_ITERATIONS..MAX_ITERATIONS) { "itérations Argon2 hors bornes : $iterations" }
        require(parallelism in 1..MAX_PARALLELISM) { "parallélisme Argon2 hors bornes : $parallelism" }
    }

    companion object {
        const val MIN_MEMORY_KIB = 19_456
        const val MAX_MEMORY_KIB = 262_144 // 256 Mio : au-delà, risque d'OOM sur mobile.
        const val MIN_ITERATIONS = 2
        const val MAX_ITERATIONS = 10
        const val MAX_PARALLELISM = 4
    }
}

/**
 * Dérivation de clé à partir du mot de passe maître (MASVS-CRYPTO-2).
 *
 * Argon2id (RFC 9106) est résistant aux attaques GPU/ASIC grâce à son coût
 * mémoire. Android ne le fournit pas : on utilise l'implémentation Bouncy Castle.
 */
object Argon2id {

    const val SALT_SIZE = 16
    const val KEY_SIZE = 32

    /**
     * Dérive une clé de [KEY_SIZE] octets. Le mot de passe n'est pas modifié ;
     * l'appelant reste responsable de l'effacer, et d'effacer la clé retournée.
     */
    fun deriveKey(password: CharArray, salt: ByteArray, params: KdfParams = KdfParams()): ByteArray {
        require(password.isNotEmpty()) { "mot de passe vide" }
        require(salt.size == SALT_SIZE) { "le sel doit faire $SALT_SIZE octets" }
        params.validate()
        return Secrets.utf8(password).useAndWipe { bytes ->
            raw(bytes, salt, params.memoryKiB, params.iterations, params.parallelism, KEY_SIZE)
        }
    }

    /** Argon2id brut, sans garde-fous. Exposé pour les vecteurs de test de la RFC 9106. */
    internal fun raw(
        password: ByteArray,
        salt: ByteArray,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        outputSize: Int,
        secret: ByteArray? = null,
        associatedData: ByteArray? = null,
    ): ByteArray {
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withMemoryAsKB(memoryKiB)
            .withIterations(iterations)
            .withParallelism(parallelism)
        secret?.let(builder::withSecret)
        associatedData?.let(builder::withAdditional)

        val generator = Argon2BytesGenerator()
        generator.init(builder.build())
        val out = ByteArray(outputSize)
        generator.generateBytes(password, out)
        return out
    }
}
