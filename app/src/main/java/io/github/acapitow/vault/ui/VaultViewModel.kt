package io.github.acapitow.vault.ui

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.acapitow.vault.VaultApp
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.security.Threat
import io.github.acapitow.vault.session.SessionState
import io.github.acapitow.vault.session.UnlockResult
import io.github.acapitow.vault.session.VaultSession
import io.github.acapitow.vault.totp.Totp
import io.github.acapitow.vault.totp.TotpAccount
import io.github.acapitow.vault.vault.EntryFields
import io.github.acapitow.vault.vault.SecretField
import io.github.acapitow.vault.vault.Vault
import io.github.acapitow.vault.vault.VaultEntry
import io.github.acapitow.vault.vault.WrongPasswordException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.GeneralSecurityException
import javax.crypto.Cipher

sealed interface Screen {
    data object Entries : Screen
    data class Detail(val id: String) : Screen
    data class Edit(val id: String?) : Screen
    data object Settings : Screen
}

/** Modification du TOTP d'une entrée en cours d'édition. */
sealed interface TotpChange {
    data object Keep : TotpChange
    data object Remove : TotpChange
    class Set(val account: TotpAccount) : TotpChange
}

class TotpDisplay(val code: String, val remaining: Int, val period: Int)

/**
 * État de l'interface. Le coffre lui-même reste dans [VaultSession] : le
 * ViewModel n'en garde aucune référence, et la liste [entries] (sans secret
 * en clair) est vidée au verrouillage.
 */
class VaultViewModel(app: Application) : AndroidViewModel(app) {

    private val vaultApp = app as VaultApp
    val session: VaultSession = vaultApp.session

    /** Menaces détectées sur l'appareil (avertissements ou blocage). */
    var threats by mutableStateOf<Set<Threat>>(emptySet())
        private set

    /** Ouverture interdite : menace bloquante en build release. */
    val blocked: Boolean
        get() = vaultApp.enforceIntegrity && threats.any { it.blocking }

    var screen by mutableStateOf<Screen>(Screen.Entries)
        private set
    var entries by mutableStateOf<List<VaultEntry>>(emptyList())
        private set
    var busy by mutableStateOf(false)
        private set
    var message by mutableStateOf<String?>(null)

    private val vault: Vault?
        get() = (session.state.value as? SessionState.Unlocked)?.vault

    init {
        checkEnvironment()
        viewModelScope.launch {
            session.state.collect { state ->
                if (state is SessionState.Unlocked) {
                    refresh()
                } else {
                    entries = emptyList()
                    screen = Screen.Entries
                }
            }
        }
    }

    fun checkEnvironment() {
        viewModelScope.launch {
            threats = withContext(Dispatchers.Default) { vaultApp.integrity.check() }
        }
    }

    fun navigate(to: Screen) {
        screen = to
    }

    fun back() {
        screen = when (val current = screen) {
            is Screen.Edit -> current.id?.let(Screen::Detail) ?: Screen.Entries
            else -> Screen.Entries
        }
    }

    fun entry(id: String): VaultEntry? = entries.firstOrNull { it.id == id }

    // --- Ouverture ------------------------------------------------------------------------------

    /** [password] est effacé. */
    fun create(password: CharArray) = work {
        try {
            session.create(password)
        } finally {
            Secrets.wipe(password)
        }
    }

    /** [password] est effacé. */
    fun unlock(password: CharArray, onResult: (UnlockResult) -> Unit) = work {
        val result = try {
            session.unlock(password)
        } finally {
            Secrets.wipe(password)
        }
        onResult(result)
    }

    fun unlockWithBiometric(cipher: Cipher, onResult: (UnlockResult) -> Unit) = work {
        onResult(session.unlockWithBiometric(cipher))
    }

    fun lock() = session.lock()

    // --- Entrées --------------------------------------------------------------------------------

    /** Secret déchiffré, que l'appelant doit effacer. */
    fun reveal(id: String, field: SecretField): CharArray? = vault?.reveal(id, field)

    fun totp(id: String, epochSeconds: Long): TotpDisplay? {
        val account = vault?.totp(id) ?: return null
        return try {
            TotpDisplay(account.code(epochSeconds), Totp.secondsRemaining(account.params, epochSeconds), account.params.period)
        } finally {
            account.wipe()
        }
    }

    /**
     * Crée ou met à jour une entrée puis enregistre le coffre. [password] et
     * [notes] (vides = supprimés) sont effacés ; le compte TOTP reste à la
     * charge de l'écran d'édition, qui l'efface en le quittant.
     */
    fun saveEntry(id: String?, fields: EntryFields, password: CharArray, notes: CharArray, totp: TotpChange) = work {
        val v = vault ?: return@work
        try {
            // Validation complète avant toute modification : pas d'entrée à moitié écrite.
            fields.validate()
            require(password.size <= Vault.MAX_SECRET_CHARS && notes.size <= Vault.MAX_SECRET_CHARS) { "texte trop long" }
            val entryId = if (id == null) v.add(fields).id else v.update(id, fields).id
            v.setSecret(entryId, SecretField.PASSWORD, password.takeIf { it.isNotEmpty() })
            v.setSecret(entryId, SecretField.NOTES, notes.takeIf { it.isNotEmpty() })
            when (totp) {
                TotpChange.Keep -> Unit
                TotpChange.Remove -> v.setTotp(entryId, null)
                is TotpChange.Set -> v.setTotp(entryId, totp.account)
            }
            session.save()
            refresh()
            screen = Screen.Detail(entryId)
        } catch (e: IllegalArgumentException) {
            message = "Entrée invalide : ${e.message}"
        } finally {
            Secrets.wipe(password)
            Secrets.wipe(notes)
        }
    }

    fun delete(id: String) = work {
        val v = vault ?: return@work
        v.remove(id)
        session.save()
        refresh()
        screen = Screen.Entries
    }

    // --- Réglages -------------------------------------------------------------------------------

    fun enableBiometric(cipher: Cipher, onDone: () -> Unit) = work {
        session.enableBiometric(cipher)
        message = "Déverrouillage biométrique activé"
        onDone()
    }

    fun disableBiometric(onDone: () -> Unit) = work {
        session.disableBiometric()
        onDone()
    }

    /** Les deux mots de passe sont effacés. [onDone] reçoit `false` si le mot de passe actuel est faux. */
    fun changePassword(current: CharArray, new: CharArray, onDone: (Boolean) -> Unit) = work {
        try {
            session.changePassword(current, new)
            message = "Mot de passe maître modifié"
            onDone(true)
        } catch (_: WrongPasswordException) {
            onDone(false)
        } finally {
            Secrets.wipe(current)
            Secrets.wipe(new)
        }
    }

    private fun refresh() {
        entries = vault?.entries?.sortedBy { it.fields.title.lowercase() }.orEmpty()
    }

    /** Une opération à la fois ; les erreurs deviennent un message plutôt qu'un crash. */
    private fun work(block: suspend () -> Unit) {
        if (busy) return
        busy = true
        viewModelScope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (_: IOException) {
                message = "Erreur d'écriture du coffre"
            } catch (_: GeneralSecurityException) {
                message = "Opération cryptographique refusée"
            } catch (_: IllegalStateException) {
                message = "Coffre verrouillé"
            } finally {
                busy = false
            }
        }
    }
}
