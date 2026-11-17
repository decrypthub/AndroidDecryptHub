package com.adh.core
import org.junit.Test
import org.junit.Assert.*
import java.io.*

class DeviceStdioTest {
    private fun frame(n:Int)=ByteArrayOutputStream().also{out->DataOutputStream(out).apply{writeInt(n);write(ByteArray(n){it.toByte()})}}.toByteArray()
    @Test fun allHeaderLowBytesAndBinaryPayloadsSurviveWindowsLines(){
        val bytes=ByteArrayOutputStream();val frames=(1..256).map{frame(it)}
        frames.forEach{DeviceStdio.write(bytes,it)}
        val windows=bytes.toString("US-ASCII").replace("\n","\r\n").byteInputStream()
        frames.forEach{assertArrayEquals(it,DeviceStdio.read(windows))};assertNull(DeviceStdio.read(windows))
    }
    @Test fun maximumFrameSurvivesWithoutTruncation(){val expected=frame(DeviceRpc.MAX_FRAME);val encoded=ByteArrayOutputStream();DeviceStdio.write(encoded,expected);assertArrayEquals(expected,DeviceStdio.read(encoded.toByteArray().inputStream()))}
    @Test fun malformedTruncatedAndOversizeFramesAreRefused(){
        for(text in listOf("!!!!\n","AAAAAA==\n","AAAAAQ==\n","AAAAAwAB\n","AAAAAQE=","A".repeat(1_400_000)+"\n"))assertTrue(text.take(24),runCatching{DeviceStdio.read(text.byteInputStream())}.isFailure)
    }
}
