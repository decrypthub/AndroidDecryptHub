package com.adh.core
import org.junit.Assert.assertEquals
import org.junit.Test
class LanProofTest {
    @Test fun matchesJsonStringifyBytesIncludingAndroidSlashAndSurrogates(){
        val proof=String(DeviceRpc.lanProof(listOf("adh.device/1","lan-auth/1","x\\y\"z\n\t\u0001","中文😀",String(charArrayOf('\ud800')))),Charsets.UTF_8)
        assertEquals("[\"adh.device/1\",\"lan-auth/1\",\"x\\\\y\\\"z\\n\\t\\u0001\",\"中文😀\",\"\\ud800\"]",proof)
    }
}
