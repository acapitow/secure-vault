package io.github.acapitow.vault.vault

import io.github.acapitow.vault.totp.TotpParams
import kotlinx.serialization.Serializable

/** Champs secrets d'une entrée, chiffrés individuellement. */
enum class SecretField { PASSWORD, NOTES }

/** Métadonnées d'une entrée : chiffrées sur disque, en clair en mémoire une fois le coffre ouvert. */
@Serializable
data class EntryFields(
    val title: String,
    val username: String = "",
    val url: String = "",
) {
    fun validate(): EntryFields = apply {
        require(title.isNotBlank()) { "titre vide" }
        require(title.length <= MAX_TITLE) { "titre trop long" }
        require(username.length <= MAX_USERNAME) { "identifiant trop long" }
        require(url.length <= MAX_URL) { "URL trop longue" }
    }

    companion object {
        const val MAX_TITLE = 256
        const val MAX_USERNAME = 256
        const val MAX_URL = 2048
    }
}

/** Compte TOTP dont seul le secret est chiffré. */
@Serializable
class SealedTotp(
    val issuer: String,
    val account: String,
    val params: TotpParams,
    @Serializable(with = Base64Serializer::class) internal val secret: ByteArray,
)

/**
 * Une entrée du coffre. Les secrets n'y figurent que chiffrés : on peut lister,
 * afficher ou journaliser une entrée sans exposer de mot de passe.
 */
@Serializable
data class VaultEntry(
    val id: String,
    val fields: EntryFields,
    internal val secrets: Map<SecretField, @Serializable(with = Base64Serializer::class) ByteArray> = emptyMap(),
    val totp: SealedTotp? = null,
    val createdAt: Long,
    val updatedAt: Long,
) {
    fun has(field: SecretField): Boolean = field in secrets
}
