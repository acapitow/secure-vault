package io.github.acapitow.vault.session

import android.content.Context
import androidx.core.content.edit

/**
 * Compteur d'échecs dans les SharedPreferences privées de l'application.
 * Écriture synchrone (`commit`) : tuer l'application juste après un échec ne
 * doit pas permettre d'effacer cet échec.
 */
class PrefsAttemptStore(context: Context) : AttemptStore {

    private val prefs = context.getSharedPreferences("unlock_attempts", Context.MODE_PRIVATE)

    override var failures: Int
        get() = prefs.getInt(FAILURES, 0)
        set(value) = prefs.edit(commit = true) { putInt(FAILURES, value) }

    override var lastFailureAt: Long
        get() = prefs.getLong(LAST_FAILURE_AT, 0)
        set(value) = prefs.edit(commit = true) { putLong(LAST_FAILURE_AT, value) }

    private companion object {
        const val FAILURES = "failures"
        const val LAST_FAILURE_AT = "last_failure_at"
    }
}
