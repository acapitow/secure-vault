package io.github.acapitow.vault.vault

import io.github.acapitow.vault.crypto.AesGcm
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.crypto.useAndWipe
import io.github.acapitow.vault.totp.TotpAccount
import java.io.Closeable
import java.util.UUID
import javax.crypto.SecretKey
import javax.security.auth.Destroyable

/**
 * Coffre déverrouillé, en mémoire.
 *
 * Chaque secret est chiffré par la clé du coffre avec pour AAD l'identifiant
 * de l'entrée et le nom du champ : un bloc copié d'une entrée ou d'un champ à
 * l'autre est refusé au déchiffrement. Les secrets ne sont déchiffrés qu'à la
 * demande ([reveal], [totp]), dans des tableaux que l'appelant doit effacer.
 *
 * Les modifications restent en mémoire jusqu'à [VaultRepository.save].
 * Après [close], toute opération lève IllegalStateException.
 *
 * Limite assumée : le fournisseur JCA garde une copie interne de la clé
 * (SecretKeySpec) qu'on ne peut pas effacer ; elle devient inaccessible à la
 * fermeture et sera libérée par le GC.
 */
class Vault internal constructor(
    internal var header: VaultHeader,
    key: SecretKey,
    entries: List<VaultEntry>,
    private val clock: () -> Long,
) : Closeable {

    private var key: SecretKey? = key
    private val byId = LinkedHashMap<String, VaultEntry>().apply { entries.forEach { put(it.id, it) } }

    val isClosed: Boolean get() = key == null

    val entries: List<VaultEntry> get() = open().let { byId.values.toList() }

    fun get(id: String): VaultEntry {
        open()
        return byId[id] ?: throw NoSuchElementException("entrée inconnue : $id")
    }

    fun add(fields: EntryFields): VaultEntry {
        open()
        fields.validate()
        val now = clock()
        val entry = VaultEntry(UUID.randomUUID().toString(), fields, createdAt = now, updatedAt = now)
        byId[entry.id] = entry
        return entry
    }

    fun update(id: String, fields: EntryFields): VaultEntry = modify(id) { it.copy(fields = fields.validate()) }

    fun remove(id: String) {
        open()
        if (byId.remove(id) == null) throw NoSuchElementException("entrée inconnue : $id")
    }

    /** Remplace (ou supprime si `null`) un secret. [value] n'est pas modifié ; l'appelant l'efface. */
    fun setSecret(id: String, field: SecretField, value: CharArray?): VaultEntry = modify(id) { entry ->
        if (value == null) {
            entry.copy(secrets = entry.secrets - field)
        } else {
            require(value.size <= MAX_SECRET_CHARS) { "secret trop long" }
            val blob = Secrets.utf8(value).useAndWipe { AesGcm.encrypt(open(), it, aad(id, field.name)) }
            entry.copy(secrets = entry.secrets + (field to blob))
        }
    }

    /** Déchiffre un secret. L'appelant doit effacer le tableau retourné. */
    fun reveal(id: String, field: SecretField): CharArray? {
        val blob = get(id).secrets[field] ?: return null
        return AesGcm.decrypt(open(), blob, aad(id, field.name)).useAndWipe(Secrets::chars)
    }

    /** Associe (ou retire si `null`) un compte TOTP. [account] n'est pas modifié ; l'appelant l'efface. */
    fun setTotp(id: String, account: TotpAccount?): VaultEntry = modify(id) { entry ->
        entry.copy(
            totp = account?.let {
                SealedTotp(it.issuer, it.account, it.params, AesGcm.encrypt(open(), it.secret, aad(id, TOTP)))
            },
        )
    }

    /** Compte TOTP avec son secret déchiffré. L'appelant doit appeler [TotpAccount.wipe]. */
    fun totp(id: String): TotpAccount? {
        val sealed = get(id).totp ?: return null
        val secret = AesGcm.decrypt(open(), sealed.secret, aad(id, TOTP))
        return try {
            TotpAccount(sealed.issuer, sealed.account, secret, sealed.params)
        } catch (e: IllegalArgumentException) {
            Secrets.wipe(secret)
            throw e
        }
    }

    override fun close() {
        val k = key ?: return
        key = null
        byId.clear()
        // SecretKeySpec n'implémente pas destroy() sur toutes les versions.
        runCatching { (k as? Destroyable)?.destroy() }
    }

    internal fun key(): SecretKey = open()

    internal fun content(): VaultContent = VaultContent(entries)

    private fun open(): SecretKey = checkNotNull(key) { "coffre verrouillé" }

    private inline fun modify(id: String, change: (VaultEntry) -> VaultEntry): VaultEntry {
        val updated = change(get(id)).copy(updatedAt = clock())
        byId[id] = updated
        return updated
    }

    private fun aad(id: String, field: String): ByteArray = "secure-vault/entry/$id/$field".toByteArray()

    companion object {
        const val MAX_SECRET_CHARS = 10_000
        private const val TOTP = "TOTP"
    }
}
