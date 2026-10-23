package io.github.acapitow.vault.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import io.github.acapitow.vault.VaultApp

/**
 * Activity unique. Hérite de FragmentActivity car BiometricPrompt l'exige.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        // MASVS-PLATFORM-3 : pas de capture d'écran ni d'aperçu dans les applis récentes.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            VaultTheme {
                AppRoot()
            }
        }
    }

    /** Toute interaction relance le minuteur de verrouillage pour inactivité. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        (application as VaultApp).session.onUserInteraction()
    }
}
