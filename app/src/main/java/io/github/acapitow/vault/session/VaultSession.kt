package io.github.acapitow.vault.session

import io.github.acapitow.vault.crypto.KdfParams
import io.github.acapitow.vault.security.Threat
import io.github.acapitow.vault.vault.CorruptedVaultException
import io.github.acapitow.vault.vault.Vault
import io.github.acapitow.vault.vault.VaultRepository
import io.github.acapitow.vault.vault.WrongPasswordException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

sealed interface SessionState {
    data object NoVault : SessionState
    data object Locked : SessionState
    class Unlocked(val vault: Vault) : SessionState
}

sealed interface UnlockResult {
    data object Success : UnlockResult

    /** @param lockoutMs délai imposé avant la tentative suivante (0 si aucun). */
    data class WrongPassword(val lockoutMs: Long) : UnlockResult

    data class LockedOut(val remainingMs: Long) : UnlockResult
    data object Corrupted : UnlockResult

    /** Environnement hostile (débogueur, instrumentation, APK modifié) : ouverture refusée. */
    data class Compromised(val threats: Set<Threat>) : UnlockResult
}

/**
 * Délais de verrouillage automatique (MASVS-AUTH-2 / MASVS-STORAGE-2).
 *
 * @param backgroundMs délai après le passage en arrière-plan, pour tolérer un
 *   aller-retour rapide (copier un code dans une autre application).
 * @param idleMs délai d'inactivité au premier plan.
 */
data class AutoLockPolicy(
    val backgroundMs: Long = 15_000,
    val idleMs: Long = 5 * 60_000,
)

/**
 * Session du coffre : unique détentrice du [Vault] déverrouillé.
 *
 * Toutes les méthodes s'appellent depuis le thread principal ; le travail
 * coûteux (Argon2id, E/S) part sur [worker].
 *
 * Le verrouillage ferme le coffre (la clé et les métadonnées sortent de la
 * mémoire). En arrière-plan, Android peut geler le processus : un minuteur
 * ne suffit donc pas. On mémorise aussi l'instant du passage en arrière-plan
 * et on vérifie l'écoulé au retour, sur une horloge monotone ([elapsed],
 * SystemClock.elapsedRealtime sous Android) que l'utilisateur ne peut pas
 * reculer.
 *
 * [blockingThreats] est consulté avant chaque ouverture : un environnement
 * hostile n'obtient jamais la clé du coffre (MASVS-RESILIENCE).
 */
class VaultSession(
    private val repository: VaultRepository,
    private val throttle: UnlockThrottle,
    private val scope: CoroutineScope,
    private val elapsed: () -> Long,
    private val policy: AutoLockPolicy = AutoLockPolicy(),
    private val worker: CoroutineDispatcher = Dispatchers.Default,
    private val blockingThreats: () -> Set<Threat> = { emptySet() },
) {

    private val _state = MutableStateFlow(if (repository.exists()) SessionState.Locked else SessionState.NoVault)
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private var lastInteraction = 0L
    private var backgroundAt: Long? = null
    private var idleJob: Job? = null
    private var backgroundJob: Job? = null

    private val vault: Vault
        get() = (state.value as? SessionState.Unlocked)?.vault ?: error("coffre verrouillé")

    /** Crée le coffre et l'ouvre. Le mot de passe n'est pas modifié ; l'appelant l'efface. */
    suspend fun create(password: CharArray, kdf: KdfParams = KdfParams()) {
        check(state.value == SessionState.NoVault) { "un coffre existe déjà" }
        check(withContext(worker) { blockingThreats() }.isEmpty()) { "environnement compromis" }
        opened(withContext(worker) { repository.create(password, kdf) })
    }

    /** Le mot de passe n'est pas modifié ; l'appelant l'efface. */
    suspend fun unlock(password: CharArray): UnlockResult {
        check(state.value == SessionState.Locked) { "coffre absent ou déjà ouvert" }
        throttle.remainingMs().let { if (it > 0) return UnlockResult.LockedOut(it) }
        withContext(worker) { blockingThreats() }.let { if (it.isNotEmpty()) return UnlockResult.Compromised(it) }
        return try {
            opened(withContext(worker) { repository.unlock(password) })
            throttle.reset()
            UnlockResult.Success
        } catch (_: WrongPasswordException) {
            UnlockResult.WrongPassword(throttle.recordFailure())
        } catch (_: CorruptedVaultException) {
            UnlockResult.Corrupted
        }
    }

    /** Voir [VaultRepository.biometricUnlock]. */
    fun biometricUnlockCipher(): Cipher? = repository.biometricUnlock()

    /** [cipher] : celui de [biometricUnlockCipher], débloqué par BiometricPrompt. */
    suspend fun unlockWithBiometric(cipher: Cipher): UnlockResult {
        check(state.value == SessionState.Locked) { "coffre absent ou déjà ouvert" }
        withContext(worker) { blockingThreats() }.let { if (it.isNotEmpty()) return UnlockResult.Compromised(it) }
        return try {
            opened(withContext(worker) { repository.unlockWithBiometric(cipher) })
            throttle.reset()
            UnlockResult.Success
        } catch (_: CorruptedVaultException) {
            UnlockResult.Corrupted
        }
    }

    val isBiometricEnabled: Boolean get() = repository.isBiometricEnabled

    fun biometricEnrollmentCipher(): Cipher {
        check(state.value is SessionState.Unlocked) { "coffre verrouillé" }
        return repository.biometricEnrollment()
    }

    suspend fun enableBiometric(cipher: Cipher) {
        val v = vault
        withContext(worker) { repository.enableBiometric(v, cipher) }
    }

    suspend fun disableBiometric() {
        val v = vault
        withContext(worker) { repository.disableBiometric(v) }
    }

    /** Enregistre les modifications du coffre ouvert. */
    suspend fun save() {
        val v = vault
        withContext(worker) { repository.save(v) }
    }

    /** Les mots de passe ne sont pas modifiés ; l'appelant les efface. */
    suspend fun changePassword(current: CharArray, new: CharArray) {
        val v = vault
        withContext(worker) { repository.changePassword(v, current, new) }
    }

    fun lock() {
        idleJob?.cancel()
        backgroundJob?.cancel()
        val current = state.value
        if (current is SessionState.Unlocked) {
            current.vault.close()
            _state.value = SessionState.Locked
        }
    }

    // --- Cycle de vie (branché sur ProcessLifecycleOwner et l'activité) ------------------------

    fun onUserInteraction() {
        if (state.value !is SessionState.Unlocked) return
        lastInteraction = elapsed()
        idleJob?.cancel()
        idleJob = scope.launch {
            delay(policy.idleMs)
            lock()
        }
    }

    fun onBackground() {
        if (state.value !is SessionState.Unlocked) return
        backgroundAt = elapsed()
        backgroundJob = scope.launch {
            delay(policy.backgroundMs)
            lock()
        }
    }

    fun onForeground() {
        backgroundJob?.cancel()
        val now = elapsed()
        val since = backgroundAt
        backgroundAt = null
        if (state.value !is SessionState.Unlocked) return
        if ((since != null && now - since >= policy.backgroundMs) || now - lastInteraction >= policy.idleMs) {
            lock()
        }
    }

    private fun opened(vault: Vault) {
        _state.value = SessionState.Unlocked(vault)
        onUserInteraction()
    }
}
