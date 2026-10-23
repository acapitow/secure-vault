package io.github.acapitow.vault.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Presse-papiers pour les secrets (MASVS-PLATFORM-1 / MASVS-STORAGE-2).
 *
 * - marqué sensible : Android 13+ masque l'aperçu, et les claviers qui
 *   respectent ce drapeau ne le mémorisent pas ;
 * - effacé après [CLEAR_DELAY_MS], sauf si l'utilisateur a copié autre chose
 *   entre-temps.
 *
 * Limite : si Android gèle l'application en arrière-plan, l'effacement est
 * retardé jusqu'à son réveil (Android 13+ vide de toute façon le
 * presse-papiers au bout d'une heure).
 */
object SecureClipboard {

    const val CLEAR_DELAY_MS = 30_000L

    private const val LABEL = "Secure Vault"

    // ClipDescription.EXTRA_IS_SENSITIVE (API 33) ; même clé lue par certains claviers sur les versions antérieures.
    private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

    private var clearJob: Job? = null

    fun copy(context: Context, text: CharSequence, sensitive: Boolean) {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        val clip = ClipData.newPlainText(LABEL, text)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
        }
        clipboard.setPrimaryClip(clip)
        clearJob?.cancel()
        if (!sensitive) return
        clearJob = ProcessLifecycleOwner.get().lifecycleScope.launch {
            delay(CLEAR_DELAY_MS)
            // En arrière-plan, la description peut être illisible (null) : on efface par prudence.
            val current = clipboard.primaryClipDescription
            if (current == null || current.label == LABEL) clipboard.clearPrimaryClip()
        }
    }
}
