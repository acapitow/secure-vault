package io.github.acapitow.vault.session

import org.junit.Assert.assertEquals
import org.junit.Test

class MemoryAttemptStore : AttemptStore {
    override var failures = 0
    override var lastFailureAt = 0L
}

class UnlockThrottleTest {

    private var now = 1_000_000L
    private val store = MemoryAttemptStore()
    private val throttle = UnlockThrottle(store) { now }

    @Test
    fun `progression des delais`() {
        assertEquals(listOf(0L, 0L, 0L, 0L, 30_000L, 60_000L, 120_000L), (1..7).map { UnlockThrottle.delayFor(it) })
        assertEquals(UnlockThrottle.MAX_DELAY_MS, UnlockThrottle.delayFor(12))
        assertEquals(UnlockThrottle.MAX_DELAY_MS, UnlockThrottle.delayFor(Int.MAX_VALUE))
    }

    @Test
    fun `premiers echecs sans attente puis delai`() {
        repeat(4) { assertEquals(0L, throttle.recordFailure()) }
        assertEquals(0L, throttle.remainingMs())
        assertEquals(30_000L, throttle.recordFailure())
        assertEquals(30_000L, throttle.remainingMs())
        now += 10_000
        assertEquals(20_000L, throttle.remainingMs())
        now += 20_000
        assertEquals(0L, throttle.remainingMs())
    }

    @Test
    fun `horloge reculee pour contourner le delai`() {
        repeat(5) { throttle.recordFailure() }
        now -= 3_600_000
        assertEquals(30_000L, throttle.remainingMs())
    }

    @Test
    fun `compteur persistant et remis a zero apres succes`() {
        repeat(6) { throttle.recordFailure() }
        val restarted = UnlockThrottle(store) { now } // application relancée
        assertEquals(60_000L, restarted.remainingMs())
        restarted.reset()
        assertEquals(0, store.failures)
        assertEquals(0L, throttle.remainingMs())
    }
}
