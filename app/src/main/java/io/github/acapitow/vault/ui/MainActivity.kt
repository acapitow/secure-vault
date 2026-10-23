package io.github.acapitow.vault.ui

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    Box(contentAlignment = Alignment.Center) {
                        Text("Secure Vault")
                    }
                }
            }
        }
    }

    /** Toute interaction relance le minuteur de verrouillage pour inactivité. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        (application as VaultApp).session.onUserInteraction()
    }
}
