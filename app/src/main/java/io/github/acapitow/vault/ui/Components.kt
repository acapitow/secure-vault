package io.github.acapitow.vault.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import java.nio.CharBuffer

@Composable
fun VaultTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

/*
 * Champs secrets : TextFieldState plutôt que String, et jamais d'état
 * sauvegardé (rememberSaveable) : le Bundle d'état d'une activité peut être
 * écrit sur disque par le système. Les rotations ne recréent pas l'activité
 * (configChanges), donc rien n'est perdu.
 *
 * Limite : le tampon interne de Compose ne peut pas être effacé, seulement
 * vidé ; il disparaît avec l'écran.
 */

/** Copie le contenu sans passer par une String. L'appelant doit effacer le résultat. */
fun TextFieldState.toCharArray(): CharArray {
    val text = this.text
    return CharArray(text.length) { text[it] }
}

fun TextFieldState.setChars(chars: CharArray) {
    edit { replace(0, length, CharBuffer.wrap(chars)) }
}

/**
 * Champ de mot de passe : copier/couper désactivés, clavier en mode mot de
 * passe (pas d'apprentissage ni de suggestions).
 */
@Composable
fun PasswordField(
    state: TextFieldState,
    label: String,
    modifier: Modifier = Modifier.fillMaxWidth(),
    revealable: Boolean = false,
    isError: Boolean = false,
    supportingText: String? = null,
) {
    var visible by remember { mutableStateOf(false) }
    OutlinedSecureTextField(
        state = state,
        modifier = modifier,
        label = { Text(label) },
        isError = isError,
        supportingText = if (supportingText != null) {
            { Text(supportingText) }
        } else {
            null
        },
        textObfuscationMode = if (visible) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
        trailingIcon = if (revealable) {
            { TextButton(onClick = { visible = !visible }) { Text(if (visible) "Masquer" else "Afficher") } }
        } else {
            null
        },
    )
}

/** « 123456 » → « 123 456 », « 12345678 » → « 1234 5678 ». */
fun formatCode(code: String): String = code.chunked((code.length + 1) / 2).joinToString(" ")
