package io.github.acapitow.vault.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeProbe(
    val files: Set<String> = emptySet(),
    val texts: Map<String, String> = mapOf("/proc/self/status" to "Name:\tvault\nTracerPid:\t0\n"),
    val classes: Set<String> = emptySet(),
    override val buildTags: String? = "release-keys",
    override val buildFingerprint: String? = "google/husky/husky:16/BP2A/1:user/release-keys",
    override val buildHardware: String? = "husky",
    override val debuggerConnected: Boolean = false,
    val signers: List<String> = listOf(SIGNER),
) : DeviceProbe {
    override fun fileExists(path: String) = path in files
    override fun readText(path: String) = texts[path]
    override fun classExists(name: String) = name in classes
    override fun signerDigests() = signers
}

private const val SIGNER = "ab12cd34"

class IntegrityCheckerTest {

    private fun check(probe: FakeProbe, expected: String? = SIGNER) = IntegrityChecker(probe, expected).check()

    @Test
    fun `appareil sain`() {
        assertEquals(emptySet<Threat>(), check(FakeProbe()))
    }

    @Test
    fun root() {
        assertEquals(setOf(Threat.ROOT), check(FakeProbe(files = setOf("/system/xbin/su"))))
        assertEquals(setOf(Threat.ROOT), check(FakeProbe(buildTags = "test-keys")))
    }

    @Test
    fun emulateur() {
        assertEquals(setOf(Threat.EMULATOR), check(FakeProbe(buildHardware = "ranchu")))
        assertEquals(setOf(Threat.EMULATOR), check(FakeProbe(buildFingerprint = "generic/sdk_gphone64/emu64a:16")))
    }

    @Test
    fun debogueur() {
        assertEquals(setOf(Threat.DEBUGGER), check(FakeProbe(debuggerConnected = true)))
        val ptraced = mapOf("/proc/self/status" to "Name:\tvault\nTracerPid:\t4242\n")
        assertEquals(setOf(Threat.DEBUGGER), check(FakeProbe(texts = ptraced)))
    }

    @Test
    fun `TracerPid illisible ou absent`() {
        assertEquals(0, IntegrityChecker.tracerPid(null))
        assertEquals(0, IntegrityChecker.tracerPid("Name:\tvault\n"))
        assertEquals(17, IntegrityChecker.tracerPid("TracerPid:   17"))
    }

    @Test
    fun instrumentation() {
        val frida = mapOf("/proc/self/maps" to "7f00-7f10 r-xp 00000000 fd:01 1 /data/local/tmp/re.frida.server/frida-agent-64.so")
        assertEquals(setOf(Threat.HOOKING), check(FakeProbe(texts = frida)))
        assertEquals(setOf(Threat.HOOKING), check(FakeProbe(classes = setOf("de.robv.android.xposed.XposedBridge"))))
    }

    @Test
    fun `signature inattendue`() {
        assertEquals(setOf(Threat.TAMPERED), check(FakeProbe(signers = listOf("ffff"))))
        assertEquals(setOf(Threat.TAMPERED), check(FakeProbe(signers = emptyList())))
        assertEquals(emptySet<Threat>(), check(FakeProbe(signers = listOf("AB12CD34"))))
    }

    @Test
    fun `build local sans empreinte attendue`() {
        assertEquals(emptySet<Threat>(), check(FakeProbe(signers = listOf("ffff")), expected = null))
        assertEquals(emptySet<Threat>(), check(FakeProbe(signers = listOf("ffff")), expected = ""))
    }

    @Test
    fun `seules certaines menaces bloquent`() {
        assertTrue(Threat.DEBUGGER.blocking && Threat.HOOKING.blocking && Threat.TAMPERED.blocking)
        assertTrue(!Threat.ROOT.blocking && !Threat.EMULATOR.blocking)
    }
}
