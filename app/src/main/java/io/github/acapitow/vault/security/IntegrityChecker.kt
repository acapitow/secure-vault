package io.github.acapitow.vault.security

/**
 * Menaces détectables sur l'environnement d'exécution (MASVS-RESILIENCE).
 *
 * @param blocking en release, interdit l'ouverture du coffre. Le root et
 *   l'émulateur ne sont qu'un avertissement : bloquer priverait un utilisateur
 *   légitime de ses propres données, alors que la clé matérielle et Argon2id
 *   restent les vraies protections.
 */
enum class Threat(val label: String, val blocking: Boolean) {
    ROOT("Appareil rooté : un attaquant avec les droits root peut lire la mémoire de l'application.", false),
    EMULATOR("Émulateur : pas de stockage matériel des clés.", false),
    DEBUGGER("Un débogueur est attaché à l'application.", true),
    HOOKING("Outil d'instrumentation détecté (Frida, Xposed…).", true),
    TAMPERED("L'application a été modifiée ou re-signée.", true),
}

/** Accès au système, abstrait pour tester la logique de détection sur JVM. */
interface DeviceProbe {
    fun fileExists(path: String): Boolean
    fun readText(path: String): String?
    fun classExists(name: String): Boolean
    val buildTags: String?
    val buildFingerprint: String?
    val buildHardware: String?
    val debuggerConnected: Boolean

    /** SHA-256 (hex) des certificats qui signent l'APK installé. */
    fun signerDigests(): List<String>
}

/**
 * Détection d'un environnement hostile.
 *
 * Toute vérification faite dans le processus peut être contournée par un
 * attaquant qui contrôle l'appareil (hook de cette classe, Magisk DenyList,
 * Frida renommé…). C'est une défense en profondeur qui élève le coût de
 * l'attaque ; elle ne remplace pas la cryptographie.
 *
 * @param expectedSigner SHA-256 du certificat de la CI (BuildConfig) ; `null`
 *   pour un build local sans clé stable, auquel cas la signature n'est pas vérifiée.
 */
class IntegrityChecker(private val probe: DeviceProbe, private val expectedSigner: String?) {

    fun check(): Set<Threat> = buildSet {
        if (isRooted()) add(Threat.ROOT)
        if (isEmulator()) add(Threat.EMULATOR)
        if (isDebugged()) add(Threat.DEBUGGER)
        if (isHooked()) add(Threat.HOOKING)
        if (isTampered()) add(Threat.TAMPERED)
    }

    internal fun isRooted(): Boolean =
        SU_PATHS.any(probe::fileExists) || probe.buildTags?.contains("test-keys") == true

    internal fun isEmulator(): Boolean {
        val fingerprint = probe.buildFingerprint.orEmpty()
        val hardware = probe.buildHardware.orEmpty()
        return fingerprint.startsWith("generic") || fingerprint.contains("emulator") ||
            hardware in EMULATOR_HARDWARE
    }

    /** Débogueur Java (JDWP) ou natif (ptrace : TracerPid non nul). */
    internal fun isDebugged(): Boolean = probe.debuggerConnected || tracerPid(probe.readText("/proc/self/status")) != 0

    /** Bibliothèques d'instrumentation chargées dans le processus. */
    internal fun isHooked(): Boolean {
        val maps = probe.readText("/proc/self/maps").orEmpty().lowercase()
        return HOOK_LIBRARIES.any { it in maps } || HOOK_CLASSES.any(probe::classExists)
    }

    internal fun isTampered(): Boolean {
        val expected = expectedSigner?.takeIf { it.isNotBlank() } ?: return false
        return probe.signerDigests().none { it.equals(expected, ignoreCase = true) }
    }

    companion object {
        private val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/system/app/Superuser.apk", "/system/bin/.ext/su", "/cache/su",
        )
        private val EMULATOR_HARDWARE = setOf("goldfish", "ranchu", "vbox86")
        private val HOOK_LIBRARIES = listOf("frida", "libsubstrate", "xposed", "lspd", "edxp")
        private val HOOK_CLASSES = listOf("de.robv.android.xposed.XposedBridge", "com.saurik.substrate.MS")

        /** Valeur de « TracerPid: » dans /proc/self/status (0 si absente ou illisible). */
        internal fun tracerPid(status: String?): Int =
            status?.lineSequence()
                ?.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(':')?.trim()?.toIntOrNull()
                ?: 0
    }
}
