package io.github.acapitow.vault.vault

import io.github.acapitow.vault.crypto.KdfParams
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import java.security.GeneralSecurityException
import java.util.Base64

/*
 * Format du fichier coffre (JSON, version 1) :
 *
 *     {
 *       "header": { "format": 1, "kdf": {…}, "salt": b64, "passwordSlot": b64 },
 *       "payload": b64
 *     }
 *
 * Hiérarchie de clés :
 *
 *   - la clé du coffre (DEK, 256 bits aléatoires) chiffre le contenu ;
 *   - passwordSlot = AES-GCM(clé appareil, AES-GCM(Argon2id(mot de passe), DEK)).
 *
 * La clé appareil vit dans l'Android Keystore et ne quitte jamais le matériel :
 * un fichier copié hors du téléphone ne permet pas de tester des mots de passe
 * hors ligne. L'en-tête (paramètres KDF, sel) sert d'AAD aux deux couches :
 * toute modification est détectée avant même la dérivation Argon2id.
 *
 * Le contenu déchiffré (titres, identifiants, URL) reste en clair en mémoire ;
 * les secrets (mots de passe, notes, secrets TOTP) y restent chiffrés
 * individuellement et ne sont déchiffrés qu'à la demande (voir [Vault]).
 */

internal const val FORMAT = 1

@Serializable
internal class VaultHeader(
    val format: Int,
    val kdf: KdfParams,
    @Serializable(with = Base64Serializer::class) val salt: ByteArray,
    @Serializable(with = Base64Serializer::class) val passwordSlot: ByteArray,
) {
    /** Données associées des deux couches du slot : tout l'en-tête sauf le slot lui-même. */
    fun aad(layer: String): ByteArray =
        "secure-vault/v$format/$layer;m=${kdf.memoryKiB};t=${kdf.iterations};p=${kdf.parallelism};salt=${b64(salt)}"
            .toByteArray()
}

@Serializable
internal class VaultFile(
    val header: VaultHeader,
    @Serializable(with = Base64Serializer::class) val payload: ByteArray,
)

@Serializable
internal class VaultContent(val entries: List<VaultEntry>)

internal val VaultJson = Json { encodeDefaults = true }

internal fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

internal object Base64Serializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("io.github.acapitow.vault.Base64", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(b64(value))

    override fun deserialize(decoder: Decoder): ByteArray =
        try {
            Base64.getDecoder().decode(decoder.decodeString())
        } catch (e: IllegalArgumentException) {
            throw SerializationException("Base64 invalide", e)
        }
}

/** Mot de passe maître incorrect. */
class WrongPasswordException : GeneralSecurityException("mot de passe incorrect")

/** Fichier altéré, tronqué, d'un format inconnu, ou chiffré par la clé d'un autre appareil. */
class CorruptedVaultException(cause: Throwable? = null) : GeneralSecurityException("coffre illisible", cause)
