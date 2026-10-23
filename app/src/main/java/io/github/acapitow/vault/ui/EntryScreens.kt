@file:OptIn(ExperimentalMaterial3Api::class)

package io.github.acapitow.vault.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.vault.SecretField
import kotlinx.coroutines.delay
import java.nio.CharBuffer

@Composable
fun BackButton(vm: VaultViewModel) {
    IconButton(onClick = vm::back) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Retour") }
}

@Composable
fun EntryListScreen(vm: VaultViewModel) {
    var query by remember { mutableStateOf("") }
    val shown = vm.entries.filter { entry ->
        query.isBlank() || listOf(entry.fields.title, entry.fields.username, entry.fields.url).any { it.contains(query.trim(), ignoreCase = true) }
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Coffre") },
                actions = {
                    IconButton(onClick = { vm.navigate(Screen.Settings) }) { Icon(Icons.Default.Settings, contentDescription = "Réglages") }
                    IconButton(onClick = vm::lock) { Icon(Icons.Default.Lock, contentDescription = "Verrouiller") }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { vm.navigate(Screen.Edit(null)) }) { Icon(Icons.Default.Add, contentDescription = "Ajouter") }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("Rechercher") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )
            if (vm.entries.isEmpty()) {
                Text("Aucune entrée. Appuie sur + pour en ajouter une.", Modifier.padding(16.dp))
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(shown, key = { it.id }) { entry ->
                    ListItem(
                        headlineContent = { Text(entry.fields.title) },
                        supportingContent = if (entry.fields.username.isNotEmpty()) {
                            { Text(entry.fields.username) }
                        } else {
                            null
                        },
                        trailingContent = if (entry.totp != null) {
                            { Text("2FA", style = MaterialTheme.typography.labelMedium) }
                        } else {
                            null
                        },
                        modifier = Modifier.clickable { vm.navigate(Screen.Detail(entry.id)) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun EntryDetailScreen(vm: VaultViewModel, id: String) {
    val entry = vm.entry(id) ?: return
    val context = LocalContext.current
    var confirmDelete by remember { mutableStateOf(false) }

    /** Déchiffre un secret, le passe à [use], puis l'efface. */
    fun withSecret(field: SecretField, use: (CharArray) -> Unit) {
        val chars = vm.reveal(id, field) ?: return
        try {
            use(chars)
        } finally {
            Secrets.wipe(chars)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(entry.fields.title) },
                navigationIcon = { BackButton(vm) },
                actions = {
                    IconButton(onClick = { vm.navigate(Screen.Edit(id)) }) { Icon(Icons.Default.Edit, contentDescription = "Modifier") }
                    IconButton(onClick = { confirmDelete = true }) { Icon(Icons.Default.Delete, contentDescription = "Supprimer") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).padding(16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (entry.totp != null) TotpCard(vm, id)
            if (entry.fields.username.isNotEmpty()) {
                FieldRow("Identifiant", entry.fields.username) {
                    TextButton(onClick = { SecureClipboard.copy(context, entry.fields.username, sensitive = false) }) { Text("Copier") }
                }
            }
            if (entry.fields.url.isNotEmpty()) {
                FieldRow("Site", entry.fields.url) {
                    TextButton(onClick = { SecureClipboard.copy(context, entry.fields.url, sensitive = false) }) { Text("Copier") }
                }
            }
            if (entry.has(SecretField.PASSWORD)) SecretRow(vm, id, SecretField.PASSWORD, "Mot de passe", ::withSecret)
            if (entry.has(SecretField.NOTES)) SecretRow(vm, id, SecretField.NOTES, "Notes", ::withSecret)
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Supprimer « ${entry.fields.title} » ?") },
            text = { Text("Cette action est définitive.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    vm.delete(id)
                }) { Text("Supprimer") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Annuler") } },
        )
    }
}

@Composable
private fun FieldRow(label: String, value: String, action: @Composable () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium)
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
        action()
    }
}

/**
 * Secret masqué par défaut. Affiché, il passe forcément par une String (le
 * composant Text l'exige) : elle n'existe que tant que le secret est visible.
 */
@Composable
private fun SecretRow(
    vm: VaultViewModel,
    id: String,
    field: SecretField,
    label: String,
    withSecret: (SecretField, (CharArray) -> Unit) -> Unit,
) {
    val context = LocalContext.current
    var shown by remember(id, field) { mutableStateOf<String?>(null) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium)
            Text(shown ?: "••••••••", style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace)
        }
        TextButton(onClick = {
            shown = if (shown == null) vm.reveal(id, field)?.let { chars -> String(chars).also { Secrets.wipe(chars) } } else null
        }) { Text(if (shown == null) "Afficher" else "Masquer") }
        TextButton(onClick = {
            withSecret(field) { SecureClipboard.copy(context, CharBuffer.wrap(it), sensitive = true) }
        }) { Text("Copier") }
    }
}

@Composable
private fun TotpCard(vm: VaultViewModel, id: String) {
    val context = LocalContext.current
    var display by remember(id) { mutableStateOf<TotpDisplay?>(null) }
    LaunchedEffect(id) {
        while (true) {
            val now = System.currentTimeMillis()
            display = vm.totp(id, now / 1000)
            delay(1000 - now % 1000)
        }
    }
    val current = display ?: return
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Code de vérification", style = MaterialTheme.typography.labelMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    formatCode(current.code),
                    style = MaterialTheme.typography.headlineLarge,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.weight(1f),
                )
                Text("${current.remaining} s", style = MaterialTheme.typography.labelLarge)
                TextButton(onClick = { SecureClipboard.copy(context, current.code, sensitive = true) }) { Text("Copier") }
            }
            LinearProgressIndicator(progress = { current.remaining / current.period.toFloat() }, modifier = Modifier.fillMaxWidth())
        }
    }
}
