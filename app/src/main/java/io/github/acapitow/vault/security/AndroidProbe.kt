package io.github.acapitow.vault.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.io.IOException
import java.security.MessageDigest

class AndroidProbe(private val context: Context) : DeviceProbe {

    override fun fileExists(path: String): Boolean = File(path).exists()

    override fun readText(path: String): String? =
        try {
            File(path).readText()
        } catch (_: IOException) {
            null
        }

    override fun classExists(name: String): Boolean =
        try {
            Class.forName(name, false, ClassLoader.getSystemClassLoader())
            true
        } catch (_: ClassNotFoundException) {
            false
        }

    override val buildTags: String? get() = Build.TAGS
    override val buildFingerprint: String? get() = Build.FINGERPRINT
    override val buildHardware: String? get() = Build.HARDWARE
    override val debuggerConnected: Boolean get() = Debug.isDebuggerConnected() || Debug.waitingForDebugger()

    override fun signerDigests(): List<String> {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        } else {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        }
        val signers = info.signingInfo?.apkContentsSigners.orEmpty()
        return signers.map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
        }
    }
}
