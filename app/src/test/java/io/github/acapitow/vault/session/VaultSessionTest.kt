package io.github.acapitow.vault.session

import io.github.acapitow.vault.crypto.AesGcm
import io.github.acapitow.vault.crypto.KdfParams
import io.github.acapitow.vault.crypto.Secrets
import io.github.acapitow.vault.security.Threat
import io.github.acapitow.vault.vault.EntryFields
import io.github.acapitow.vault.vault.VaultRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class VaultSessionTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val fast = KdfParams(memoryKiB = KdfParams.MIN_MEMORY_KIB, iterations = 2, parallelism = 1)
    private val deviceKey = AesGcm.key(Secrets.randomBytes(AesGcm.KEY_SIZE))
    private val policy = AutoLockPolicy(backgroundMs = 15_000, idleMs = 60_000)
    private val password = "mot de passe".toCharArray()

    /** Horloge monotone réglable ; simule aussi le temps passé processus gelé. */
    private var frozenOffset = 0L

    private fun TestScope.session(
        store: AttemptStore = MemoryAttemptStore(),
        threats: Set<Threat> = emptySet(),
    ): VaultSession {
        val repository = VaultRepository(File(tmp.root, "vault.json"), { deviceKey })
        return VaultSession(
            repository,
            UnlockThrottle(store) { testScheduler.currentTime + frozenOffset },
            backgroundScope,
            elapsed = { testScheduler.currentTime + frozenOffset },
            policy = policy,
            worker = UnconfinedTestDispatcher(testScheduler),
            blockingThreats = { threats },
        )
    }

    private fun VaultSession.isUnlocked() = state.value is SessionState.Unlocked

    @Test
    fun `creation, verrouillage, deverrouillage`() = runTest {
        val session = session()
        assertEquals(SessionState.NoVault, session.state.value)
        session.create(password, fast)
        val vault = (session.state.value as SessionState.Unlocked).vault
        vault.add(EntryFields("A"))
        session.save()
        session.lock()
        assertEquals(SessionState.Locked, session.state.value)
        assertTrue("le coffre fermé doit être inutilisable", vault.isClosed)
        assertEquals(UnlockResult.Success, session.unlock(password))
        assertEquals(1, (session.state.value as SessionState.Unlocked).vault.entries.size)
    }

    @Test
    fun `mots de passe incorrects puis blocage temporaire`() = runTest {
        val store = MemoryAttemptStore()
        session().apply { create(password, fast); lock() }
        val session = session(store)
        repeat(4) { assertEquals(UnlockResult.WrongPassword(0), session.unlock("faux".toCharArray())) }
        assertEquals(UnlockResult.WrongPassword(30_000), session.unlock("faux".toCharArray()))
        // Même le bon mot de passe est refusé pendant le délai, sans même être testé.
        assertTrue(session.unlock(password) is UnlockResult.LockedOut)
        advanceTimeBy(30_001)
        assertEquals(UnlockResult.Success, session.unlock(password))
        assertEquals(0, store.failures)
    }

    @Test
    fun `verrouillage apres inactivite`() = runTest {
        val session = session()
        session.create(password, fast)
        advanceTimeBy(50_000)
        session.onUserInteraction()
        advanceTimeBy(50_000)
        assertTrue(session.isUnlocked())
        advanceTimeBy(10_001)
        runCurrent()
        assertTrue(!session.isUnlocked())
    }

    @Test
    fun `aller-retour rapide en arriere-plan tolere`() = runTest {
        val session = session()
        session.create(password, fast)
        session.onBackground()
        advanceTimeBy(5_000)
        session.onForeground()
        advanceTimeBy(20_000)
        assertTrue(session.isUnlocked())
    }

    @Test
    fun `verrouillage en arriere-plan`() = runTest {
        val session = session()
        session.create(password, fast)
        session.onBackground()
        advanceTimeBy(15_001)
        runCurrent()
        assertTrue(!session.isUnlocked())
    }

    @Test
    fun `processus gele en arriere-plan, verrouille au retour`() = runTest {
        val session = session()
        session.create(password, fast)
        session.onBackground()
        // Le minuteur n'a pas pu s'exécuter (processus gelé), mais l'horloge monotone a avancé.
        frozenOffset = 10 * 60_000
        session.onForeground()
        assertTrue(!session.isUnlocked())
    }

    @Test
    fun `environnement compromis, coffre jamais ouvert`() = runTest {
        session().apply { create(password, fast); lock() }
        val store = MemoryAttemptStore()
        val session = session(store, threats = setOf(Threat.HOOKING))
        assertEquals(UnlockResult.Compromised(setOf(Threat.HOOKING)), session.unlock(password))
        assertEquals(SessionState.Locked, session.state.value)
        assertEquals("pas compté comme un échec de mot de passe", 0, store.failures)
    }
}
