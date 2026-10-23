package io.github.acapitow.vault.session

/** Persistance des échecs (SharedPreferences sous Android). Ne contient aucun secret. */
interface AttemptStore {
    var failures: Int
    var lastFailureAt: Long
}

/**
 * Délai croissant après des mots de passe incorrects (MASVS-AUTH-1).
 *
 * Les [FREE_ATTEMPTS] premiers échecs sont sans pénalité (fautes de frappe),
 * puis le délai double à chaque échec : 30 s, 1 min, 2 min… jusqu'à 1 h.
 * Le compteur est persistant : tuer l'application ne le remet pas à zéro.
 *
 * L'heure murale est utilisée car elle survit au redémarrage. Si elle recule
 * (horloge modifiée pour contourner le délai), le délai complet est réappliqué.
 *
 * Ce n'est qu'un frein contre un attaquant qui a le téléphone en main : face
 * à un appareil rooté, la vraie protection reste le coût d'Argon2id combiné à
 * la clé matérielle, qui interdit toute attaque hors de l'appareil.
 */
class UnlockThrottle(
    private val store: AttemptStore,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    /** Millisecondes avant la prochaine tentative autorisée (0 si aucune attente). */
    fun remainingMs(): Long {
        val delay = delayFor(store.failures)
        if (delay == 0L) return 0
        val now = clock()
        val last = store.lastFailureAt
        return if (now < last) delay else (last + delay - now).coerceAtLeast(0)
    }

    /** Enregistre un échec et retourne le délai imposé avant la tentative suivante. */
    fun recordFailure(): Long {
        store.failures = (store.failures + 1).coerceAtMost(MAX_COUNTED)
        store.lastFailureAt = clock()
        return delayFor(store.failures)
    }

    fun reset() {
        store.failures = 0
        store.lastFailureAt = 0
    }

    companion object {
        const val FREE_ATTEMPTS = 5
        const val BASE_DELAY_MS = 30_000L
        const val MAX_DELAY_MS = 3_600_000L
        private const val MAX_COUNTED = 1_000

        fun delayFor(failures: Int): Long {
            if (failures < FREE_ATTEMPTS) return 0
            val doublings = (failures - FREE_ATTEMPTS).coerceAtMost(20)
            return (BASE_DELAY_MS shl doublings).coerceAtMost(MAX_DELAY_MS)
        }
    }
}
