package io.github.acapitow.vault

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycleScope
import io.github.acapitow.vault.security.AndroidProbe
import io.github.acapitow.vault.security.IntegrityChecker
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

    lateinit var integrity: IntegrityChecker
        private set

    /** En debug, les menaces sont signalées mais ne bloquent pas (sinon impossible de déboguer). */
    val enforceIntegrity: Boolean = !BuildConfig.DEBUG

    override fun onCreate() {
        super.onCreate()
        integrity = IntegrityChecker(AndroidProbe(this), BuildConfig.EXPECTED_SIGNER)
        // noBackupFilesDir : exclu de toute sauvegarde, en plus d'allowBackup=false.
        val repository = VaultRepository(File(noBackupFilesDir, "vault.json"), DeviceKey::getOrCreate, BiometricKey)
        val process = ProcessLifecycleOwner.get()
        session = VaultSession(
            repository = repository,
            throttle = UnlockThrottle(PrefsAttemptStore(this)),
            scope = process.lifecycleScope,
            elapsed = SystemClock::elapsedRealtime,
            blockingThreats = {
                if (enforceIntegrity) integrity.check().filterTo(mutableSetOf()) { it.blocking } else emptySet()
            },
        )
        // onStart / onStop de l'ensemble du processus : au moins une activité visible ou aucune.
        process.lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) = session.onForeground()
                override fun onStop(owner: LifecycleOwner) = session.onBackground()
            },
        )
        // Écran éteint : verrouillage immédiat, sans attendre le délai d'arrière-plan.
        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = session.lock()
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }
}
