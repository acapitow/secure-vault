package io.github.acapitow.vault.totp

import io.github.acapitow.vault.crypto.Secrets

/**
 * Un compte TOTP. Le secret est validé à la construction, que le compte vienne
 * d'un QR code ou d'une saisie manuelle.
 *
 * Pas de `data class` : `toString()` exposerait le secret dans les logs ou
 * les rapports de crash (MASVS-STORAGE-2), et `equals` comparerait les
 * tableaux par référence.
 */
class TotpAccount(
    val issuer: String,
    val account: String,
    val secret: ByteArray,
    val params: TotpParams = TotpParams(),
) {
    init {
        require(account.isNotBlank()) { "nom de compte vide" }
        // RFC 4226 recommande 160 bits et exige 128 ; on accepte 80 bits,
        // encore courants chez les services en ligne.
        require(secret.size in MIN_SECRET_SIZE..MAX_SECRET_SIZE) { "taille de secret invalide : ${secret.size} octets" }
        params.validate()
    }

    fun code(epochSeconds: Long): String = Totp.code(secret, params, epochSeconds)

    fun wipe() = Secrets.wipe(secret)

    override fun toString(): String = "TotpAccount(issuer=$issuer, account=$account, params=$params)"

    companion object {
        const val MIN_SECRET_SIZE = 10
        const val MAX_SECRET_SIZE = 128
    }
}
