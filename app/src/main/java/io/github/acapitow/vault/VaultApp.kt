package io.github.acapitow.vault

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycleScope
import io.github.acapitow.vault.session.PrefsAttemptStore
import io.github.acapitow.vault.session.UnlockThrottle
import io.github.acapitow.vault.session.VaultSession
import io.github.acapitow.vault.vault.BiometricKey
import io.github.acapitow.vault.vault.DeviceKey
import io.github.acapitow.vault.vault.VaultRepository
import java.io.File

class VaultApp : Application() {

    lateinit var session: VaultSession
        private set

    override fun onCreate() {
        super.onCreate()
        // noBackupFilesDir : exclu de toute sauvegarde, en plus d'allowBackup=false.
        val repository = VaultRepository(File(noBackupFilesDir, "vault.json"), DeviceKey::getOrCreate, BiometricKey)
        val process = ProcessLifecycleOwner.get()
        session = VaultSession(
            repository = repository,
            throttle = UnlockThrottle(PrefsAttemptStore(this)),
            scope = process.lifecycleScope,
            elapsed = SystemClock::elapsedRealtime,
        )
        // onStart / onStop de l'ensemble du processus : au moins une activité visible ou aucune.
        process.lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) = session.onForeground()
                override fun onStop(owner: LifecycleOwner) = session.onBackground()
            },
        )
    }
}
