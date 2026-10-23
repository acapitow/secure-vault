@file:OptIn(ExperimentalMaterial3Api::class)

package io.github.acapitow.vault.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.github.acapitow.vault.crypto.PasswordGenerator
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.totp.TotpInput
import io.github.acapitow.vault.vault.EntryFields
import io.github.acapitow.vault.vault.SecretField

@Composable
fun EntryEditScreen(vm: VaultViewModel, id: String?) {
    val existing = id?.let(vm::entry)
    var title by remember { mutableStateOf(existing?.fields?.title.orEmpty()) }
    var username by remember { mutableStateOf(existing?.fields?.username.orEmpty()) }
    var url by remember { mutableStateOf(existing?.fields?.url.orEmpty()) }
    val password = remember { TextFieldState() }
    val notes = remember { TextFieldState() }
    val totpInput = remember { TextFieldState() }
    var totpChange by remember { mutableStateOf<TotpChange>(TotpChange.Keep) }
    var totpError by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }

    // Pré-remplissage des secrets existants, déchiffrés directement dans les champs.
    LaunchedEffect(id) {
        if (id == null) return@LaunchedEffect
        for ((field, state) in listOf(SecretField.PASSWORD to password, SecretField.NOTES to notes)) {
            vm.reveal(id, field)?.let { chars ->
                state.setChars(chars)
                Secrets.wipe(chars)
            }
        }
    }

    // En quittant l'écran (enregistrement, retour ou verrouillage) : tout effacer.
    val pendingTotp by rememberUpdatedState(totpChange)
    DisposableEffect(Unit) {
        onDispose {
            listOf(password, notes, totpInput).forEach { it.clearText() }
            (pendingTotp as? TotpChange.Set)?.account?.wipe()
        }
    }

    fun applyTotp(input: CharArray) {
        try {
            val account = TotpInput.parse(input, title, username.ifBlank { title })
            (totpChange as? TotpChange.Set)?.account?.wipe()
            totpChange = TotpChange.Set(account)
            totpError = null
            totpInput.clearText()
        } catch (e: IllegalArgumentException) {
            totpError = "QR code ou clé invalide (${e.message})"
        } finally {
            Secrets.wipe(input)
        }
    }

    if (scanning) {
        BackHandler { scanning = false }
        QrScanner(
            onResult = { text ->
                scanning = false
                applyTotp(text.toCharArray())
            },
            onCancel = { scanning = false },
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (id == null) "Nouvelle entrée" else "Modifier") },
                navigationIcon = { BackButton(vm) },
                actions = {
                    TextButton(
                        enabled = title.isNotBlank() && !vm.busy,
                        onClick = {
                            vm.saveEntry(
                                id,
                                EntryFields(title.trim(), username.trim(), url.trim()),
                                password.toCharArray(),
                                notes.toCharArray(),
                                totpChange,
                            )
                        },
                    ) { Text("Enregistrer") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).imePadding().padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text("Titre") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Identifiant") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("Site") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            PasswordField(password, "Mot de passe", revealable = true)
            TextButton(onClick = {
                val generated = PasswordGenerator.generate()
                password.setChars(generated)
                Secrets.wipe(generated)
            }) { Text("Générer un mot de passe (20 caractères, ≈ 125 bits)") }

            Text("Notes", style = MaterialTheme.typography.labelMedium)
            OutlinedTextField(
                state = notes,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            )

            Text("Double authentification (TOTP)", style = MaterialTheme.typography.titleSmall)
            val current = totpChange
            val configured = when (current) {
                TotpChange.Keep -> existing?.totp?.let { "${it.issuer} ${it.account}".trim() }
                TotpChange.Remove -> null
                is TotpChange.Set -> "${current.account.issuer} ${current.account.account}".trim()
            }
            if (configured != null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Configurée : $configured", Modifier.weight(1f))
                    TextButton(onClick = {
                        (totpChange as? TotpChange.Set)?.account?.wipe()
                        totpChange = TotpChange.Remove
                    }) { Text("Retirer") }
                }
            } else {
                PasswordField(
                    totpInput,
                    "Lien otpauth:// ou clé secrète",
                    revealable = true,
                    isError = totpError != null,
                    supportingText = totpError,
                )
                Row {
                    TextButton(onClick = { scanning = true }) { Text("Scanner un QR code") }
                    TextButton(
                        enabled = totpInput.text.isNotEmpty(),
                        onClick = { applyTotp(totpInput.toCharArray()) },
                    ) { Text("Valider la clé") }
                }
            }
        }
    }
}
