package io.github.acapitow.vault.ui

import android.os.SystemClock
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import io.github.acapitow.vault.security.Threat
import io.github.acapitow.vault.session.UnlockResult
import io.github.acapitow.vault.vault.BiometricInvalidatedException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.security.GeneralSecurityException
import java.security.ProviderException

const val MIN_MASTER_PASSWORD = 12

@Composable
private fun CenteredColumn(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) { content() }
}

/** Menaces non bloquantes : l'utilisateur est informé, mais garde l'accès à ses données. */
@Composable
private fun ThreatWarnings(threats: Set<Threat>) {
    if (threats.isEmpty()) return
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Environnement à risque", style = MaterialTheme.typography.titleSmall)
            threats.forEach { Text("• ${it.label}", style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** Menace bloquante en release : pas de champ de mot de passe, la clé du coffre n'est jamais dérivée. */
@Composable
fun CompromisedScreen(vm: VaultViewModel) {
    CenteredColumn {
        Text("Ouverture bloquée", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Secure Vault refuse de s'ouvrir dans cet environnement. Tes données restent chiffrées " +
                "et intactes : elles seront de nouveau accessibles une fois la cause supprimée.",
            style = MaterialTheme.typography.bodyMedium,
        )
        ThreatWarnings(vm.threats.filterTo(mutableSetOf()) { it.blocking })
        OutlinedButton(onClick = vm::checkEnvironment, modifier = Modifier.fillMaxWidth()) { Text("Vérifier à nouveau") }
    }
}

/** Vide les champs secrets quand l'écran disparaît. */
@Composable
private fun ClearOnDispose(vararg states: TextFieldState) {
    DisposableEffect(Unit) {
        onDispose { states.forEach { it.clearText() } }
    }
}

@Composable
fun SetupScreen(vm: VaultViewModel) {
    val password = remember { TextFieldState() }
    val confirm = remember { TextFieldState() }
    ClearOnDispose(password, confirm)
    val tooShort = password.text.length < MIN_MASTER_PASSWORD
    val mismatch = !password.text.contentEquals(confirm.text)

    CenteredColumn {
        Text("Créer le coffre", style = MaterialTheme.typography.headlineMedium)
        ThreatWarnings(vm.threats)
        Text(
            "Choisis un mot de passe maître d'au moins $MIN_MASTER_PASSWORD caractères, par exemple " +
                "une phrase de plusieurs mots. Il ne peut pas être récupéré : sans lui, le coffre est perdu. " +
                "Le coffre est lié à cet appareil.",
            style = MaterialTheme.typography.bodyMedium,
        )
        PasswordField(
            password,
            "Mot de passe maître",
            revealable = true,
            supportingText = "${password.text.length} / $MIN_MASTER_PASSWORD caractères minimum",
        )
        PasswordField(
            confirm,
            "Confirmation",
            isError = confirm.text.isNotEmpty() && mismatch,
            supportingText = if (confirm.text.isNotEmpty() && mismatch) "Les mots de passe diffèrent" else null,
        )
        if (vm.busy) {
            CircularProgressIndicator()
            Text("Création du coffre…")
        } else {
            Button(
                onClick = { vm.create(password.toCharArray()) },
                enabled = !tooShort && !mismatch,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Créer le coffre") }
        }
    }
}

@Composable
fun UnlockScreen(vm: VaultViewModel) {
    val activity = LocalActivity.current as FragmentActivity
    val scope = rememberCoroutineScope()
    val password = remember { TextFieldState() }
    ClearOnDispose(password)
    var error by remember { mutableStateOf<String?>(null) }
    var lockoutUntil by remember { mutableLongStateOf(0L) }
    var now by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    val biometric = remember {
        BiometricAuth.isAvailable(activity) && runCatching { vm.session.isBiometricEnabled }.getOrDefault(false)
    }

    // Compte à rebours du blocage après trop d'essais.
    LaunchedEffect(lockoutUntil) {
        while (SystemClock.elapsedRealtime() < lockoutUntil) {
            now = SystemClock.elapsedRealtime()
            delay(250)
        }
        now = SystemClock.elapsedRealtime()
    }
    val lockedSeconds = ((lockoutUntil - now + 999) / 1000).coerceAtLeast(0)

    fun handle(result: UnlockResult) {
        when (result) {
            UnlockResult.Success -> error = null
            is UnlockResult.WrongPassword -> {
                error = "Mot de passe incorrect"
                if (result.lockoutMs > 0) lockoutUntil = SystemClock.elapsedRealtime() + result.lockoutMs
            }
            is UnlockResult.LockedOut -> lockoutUntil = SystemClock.elapsedRealtime() + result.remainingMs
            UnlockResult.Corrupted -> error = "Coffre illisible : fichier altéré ou clé de l'appareil indisponible."
            is UnlockResult.Compromised -> vm.checkEnvironment()
        }
    }

    fun unlockWithBiometric() {
        scope.launch {
            try {
                val cipher = vm.session.biometricUnlockCipher() ?: return@launch
                val unlocked = BiometricAuth.authenticate(activity, cipher, "Déverrouiller Secure Vault", "Utiliser le mot de passe")
                vm.unlockWithBiometric(unlocked, ::handle)
            } catch (_: BiometricInvalidatedException) {
                error = "La biométrie de l'appareil a changé : déverrouillage biométrique désactivé, utilise ton mot de passe."
            } catch (e: BiometricException) {
                if (!e.isCancellation) error = e.message
            } catch (_: GeneralSecurityException) {
                error = "Déverrouillage biométrique impossible : utilise ton mot de passe."
            } catch (_: ProviderException) {
                error = "Déverrouillage biométrique impossible : utilise ton mot de passe."
            }
        }
    }

    LaunchedEffect(Unit) { if (biometric) unlockWithBiometric() }

    CenteredColumn {
        Text("Secure Vault", style = MaterialTheme.typography.headlineMedium)
        ThreatWarnings(vm.threats)
        PasswordField(password, "Mot de passe maître", isError = error != null, supportingText = error)
        when {
            vm.busy -> CircularProgressIndicator()
            lockedSeconds > 0 -> Text("Trop d'essais : réessaie dans $lockedSeconds s", color = MaterialTheme.colorScheme.error)
            else -> Button(
                onClick = {
                    vm.unlock(password.toCharArray(), ::handle)
                    password.clearText()
                },
                enabled = password.text.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Déverrouiller") }
        }
        if (biometric && !vm.busy) {
            OutlinedButton(onClick = ::unlockWithBiometric, modifier = Modifier.fillMaxWidth()) {
                Text("Déverrouiller avec la biométrie")
            }
        }
    }
}
