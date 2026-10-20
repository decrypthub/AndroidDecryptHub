package com.adh.manager.data

import com.adh.core.ScopeConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScopeWriterTest {
    @Test
    fun aNewerEditReplacesOneThatIsStillWriting() = runBlocking {
        val written = mutableListOf<Set<String>>()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val writer = ScopeWriter { config ->
            if (config.packages == setOf("com.old")) {
                entered.complete(Unit)
                release.await()
            }
            written += config.packages
            Result.success(Unit)
        }
        val first = async { writer.submit(ScopeConfig(packages = setOf("com.old"))) }
        entered.await()
        val second = async { writer.submit(ScopeConfig(packages = setOf("com.old", "com.new"))) }
        yield()
        release.complete(Unit)
        assertNull(first.await())
        assertTrue(second.await()!!.isSuccess)
        assertEquals(setOf("com.old", "com.new"), written.last())
    }
}
