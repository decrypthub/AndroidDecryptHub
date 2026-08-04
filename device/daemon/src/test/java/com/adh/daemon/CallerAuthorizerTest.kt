package com.adh.daemon

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CallerAuthorizerTest {
    @Test
    fun acceptsOnlyManagerUidWithPinnedSigner() {
        val expected = "AA:BB:CC"
        assertTrue(
            CallerAuthorizer.isAuthorized(
                10_123,
                setOf("com.adh.manager"),
                setOf("AABBCC"),
                "com.adh.manager",
                expected,
            )
        )
        assertFalse(
            CallerAuthorizer.isAuthorized(
                10_123,
                setOf("com.adh.manager"),
                setOf("112233"),
                "com.adh.manager",
                expected,
            )
        )
        assertFalse(
            CallerAuthorizer.isAuthorized(
                10_123,
                setOf("com.example.fake"),
                setOf("AABBCC"),
                "com.adh.manager",
                expected,
            )
        )
        assertFalse(
            CallerAuthorizer.isAuthorized(
                0,
                setOf("com.adh.manager"),
                setOf("AABBCC"),
                "com.adh.manager",
                expected,
            )
        )
    }
}
