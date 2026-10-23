package io.github.acapitow.vault.ui

import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.acapitow.vault.session.SessionState

/** Racine : l'écran affiché découle de l'état de la session, puis de la navigation. */
@Composable
fun AppRoot(vm: VaultViewModel = viewModel()) {
    val state by vm.session.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LaunchedEffect(vm.message) {
        vm.message?.let {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
            vm.message = null
        }
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
