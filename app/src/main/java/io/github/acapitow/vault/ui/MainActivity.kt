package io.github.acapitow.vault.ui

import android.os.Build
import android.os.Bundle
import android.view.View
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
        harden()
        enableEdgeToEdge()
        setContent {
            VaultTheme {
                AppRoot()
            }
        }
    }

    /** Protections de plateforme (MASVS-PLATFORM-3). */
    private fun harden() {
        val root = window.decorView
        // Tapjacking : les touchers traversant une fenêtre superposée sont ignorés.
        root.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Masque les fenêtres superposées des autres applications (permission HIDE_OVERLAY_WINDOWS).
            window.setHideOverlayWindows(true)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Pas de capture dans l'écran des applications récentes (en plus de FLAG_SECURE).
            setRecentsScreenshotEnabled(false)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Contenu invisible pour les services d'accessibilité qui ne sont pas de vrais
            // outils d'accessibilité (malwares bancaires) ; TalkBack fonctionne toujours.
            root.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
        // Le service d'autoremplissage du système ne doit ni lire ni proposer
        // d'enregistrer le mot de passe maître ou les secrets affichés.
        root.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

    /** Toute interaction relance le minuteur de verrouillage pour inactivité. */
    override fun onUserInteraction() {
        super.onUserInteraction()
        (application as VaultApp).session.onUserInteraction()
    }
}
