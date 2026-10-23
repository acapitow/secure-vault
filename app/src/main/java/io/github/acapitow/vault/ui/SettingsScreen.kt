@file:OptIn(ExperimentalMaterial3Api::class)

package io.github.acapitow.vault.ui

import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import java.security.GeneralSecurityException
import java.security.ProviderException

@Composable
fun SettingsScreen(vm: VaultViewModel) {
    val activity = LocalActivity.current as FragmentActivity
    val scope = rememberCoroutineScope()
    val available = remember { BiometricAuth.isAvailable(activity) }
    var biometric by remember { mutableStateOf(runCatching { vm.session.isBiometricEnabled }.getOrDefault(false)) }

    fun enableBiometric() {
        scope.launch {
            try {
                // Activation confirmée par une authentification : prouve que la clé fonctionne.
                val cipher = vm.session.biometricEnrollmentCipher()
                val unlocked = BiometricAuth.authenticate(activity, cipher, "Activer le déverrouillage biométrique", "Annuler")
                vm.enableBiometric(unlocked) { biometric = true }
            } catch (e: BiometricException) {
                if (!e.isCancellation) vm.message = e.message
            } catch (_: GeneralSecurityException) {
                vm.message = "Impossible de créer la clé biométrique"
            } catch (_: ProviderException) {
                vm.message = "Impossible de créer la clé biométrique"
            }
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Réglages") }, navigationIcon = { BackButton(vm) }) },
    ) { padding ->
        Column(
            Modifier.padding(padding).imePadding().padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Déverrouillage biométrique", style = MaterialTheme.typography.titleMedium)
                    Text(
                        if (available) {
                            "Empreinte ou visage (biométrie forte). Désactivé automatiquement si une empreinte est ajoutée."
                        } else {
                            "Aucune biométrie forte configurée sur cet appareil."
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Switch(
                    checked = biometric,
                    enabled = available && !vm.busy,
                    onCheckedChange = { on -> if (on) enableBiometric() else vm.disableBiometric { biometric = false } },
                )
            }
            HorizontalDivider()
            ChangePassword(vm) { biometric = false }
            HorizontalDivider()
            Text("Verrouillage automatique", style = MaterialTheme.typography.titleMedium)
            Text(
                "Après 5 minutes d'inactivité, ou 15 secondes après être passé dans une autre application. " +
                    "Les secrets copiés sont effacés du presse-papiers après 30 secondes.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedButton(onClick = vm::lock, modifier = Modifier.fillMaxWidth()) { Text("Verrouiller maintenant") }
        }
    }
}

@Composable
private fun ChangePassword(vm: VaultViewModel, onChanged: () -> Unit) {
    val current = remember { TextFieldState() }
    val new = remember { TextFieldState() }
    val confirm = remember { TextFieldState() }
    var error by remember { mutableStateOf<String?>(null) }
    DisposableEffect(Unit) {
        onDispose { listOf(current, new, confirm).forEach { it.clearText() } }
    }
    val tooShort = new.text.length < MIN_MASTER_PASSWORD
    val mismatch = !new.text.contentEquals(confirm.text)

    Text("Changer le mot de passe maître", style = MaterialTheme.typography.titleMedium)
    PasswordField(current, "Mot de passe actuel", isError = error != null, supportingText = error)
    PasswordField(new, "Nouveau mot de passe", supportingText = "$MIN_MASTER_PASSWORD caractères minimum")
    PasswordField(confirm, "Confirmation", isError = confirm.text.isNotEmpty() && mismatch)
    Text(
        "Le déverrouillage biométrique sera désactivé et devra être réactivé.",
        style = MaterialTheme.typography.bodySmall,
    )
    Button(
        enabled = current.text.isNotEmpty() && !tooShort && !mismatch && !vm.busy,
        onClick = {
            vm.changePassword(current.toCharArray(), new.toCharArray()) { ok ->
                if (ok) {
                    error = null
                    listOf(current, new, confirm).forEach { it.clearText() }
                    onChanged()
                } else {
                    error = "Mot de passe actuel incorrect"
                }
            }
        },
        modifier = Modifier.fillMaxWidth(),
    ) { Text("Changer le mot de passe") }
}
