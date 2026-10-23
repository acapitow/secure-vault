package io.github.acapitow.vault.ui

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.key
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.acapitow.vault.BuildConfig
import io.github.acapitow.vault.CrashLog
import io.github.acapitow.vault.session.SessionState

/** Racine : l'écran affiché découle de l'état de la session, puis de la navigation. */
@Composable
fun AppRoot(vm: VaultViewModel = viewModel()) {
    val state by vm.session.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // Debug uniquement : trace du dernier plantage, à copier pour le diagnostic.
    var crash by remember { mutableStateOf(if (BuildConfig.DEBUG) CrashLog.consume(context) else null) }
    crash?.let { trace ->
        AlertDialog(
            onDismissRequest = { crash = null },
            title = { Text("Plantage précédent (debug)") },
            text = { Text(trace, style = MaterialTheme.typography.bodySmall, modifier = Modifier.verticalScroll(rememberScrollState())) },
            confirmButton = {
                TextButton(onClick = {
                    SecureClipboard.copy(context, trace, sensitive = false)
                    crash = null
                }) { Text("Copier") }
            },
            dismissButton = { TextButton(onClick = { crash = null }) { Text("Fermer") } },
        )
    }

    LaunchedEffect(vm.message) {
        vm.message?.let {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
            vm.message = null
        }
    }

    if (vm.blocked && state !is SessionState.Unlocked) {
        CompromisedScreen(vm)
        return
    }
    when (state) {
        SessionState.NoVault -> SetupScreen(vm)
        SessionState.Locked -> UnlockScreen(vm)
        is SessionState.Unlocked -> {
            val screen = vm.screen
            BackHandler(enabled = screen != Screen.Entries) { vm.back() }
            when (screen) {
                Screen.Entries -> EntryListScreen(vm)
                is Screen.Detail -> EntryDetailScreen(vm, screen.id)
                // key : un nouvel écran d'édition (états vierges) par entrée.
                is Screen.Edit -> key(screen.id) { EntryEditScreen(vm, screen.id) }
                Screen.Settings -> SettingsScreen(vm)
            }
        }
    }
}
