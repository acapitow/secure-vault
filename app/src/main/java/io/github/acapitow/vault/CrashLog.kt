package io.github.acapitow.vault

import android.content.Context
import java.io.File

/**
 * Journal du dernier plantage, **build debug uniquement** (appelé derrière
 * `BuildConfig.DEBUG`, donc retiré du release par R8).
 *
 * Permet de récupérer une trace sur le téléphone sans adb : elle est écrite
 * dans le stockage privé de l'application, puis affichée au lancement suivant.
 * Le coffre debug est un coffre de test, distinct de celui du release.
 */
object CrashLog {

    private fun file(context: Context) = File(context.filesDir, "last_crash.txt")

    fun install(context: Context) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching { file(context).writeText("Thread ${thread.name}\n${error.stackTraceToString()}") }
            previous?.uncaughtException(thread, error)
        }
    }

    /** Lit puis supprime la trace du dernier plantage, s'il y en a une. */
    fun consume(context: Context): String? {
        val f = file(context)
        if (!f.exists()) return null
        return runCatching { f.readText() }.getOrNull().also { f.delete() }
    }
}
