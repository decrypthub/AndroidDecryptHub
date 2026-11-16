package com.adh.core
import java.io.*
import java.util.Base64

/** stdio/2 armor only; the inner adh.device/1 frame is byte-for-byte unchanged. */
object DeviceStdio {
    private const val MAX_LINE=((DeviceRpc.MAX_FRAME+4+2)/3)*4
    fun frame(input:InputStream):ByteArray? {
        val first=input.read();if(first<0)return null
        val data=DataInputStream(input);val size=(first shl 24) or (data.readUnsignedByte() shl 16) or (data.readUnsignedByte() shl 8) or data.readUnsignedByte()
        require(size in 1..DeviceRpc.MAX_FRAME)
        val bytes=ByteArray(size+4);bytes[0]=first.toByte();bytes[1]=(size ushr 16).toByte();bytes[2]=(size ushr 8).toByte();bytes[3]=size.toByte();data.readFully(bytes,4,size);return bytes
    }
    fun read(input:InputStream):ByteArray? {
        val line=ByteArrayOutputStream();while(true){val b=input.read();if(b<0){if(line.size()==0)return null;throw EOFException("partial stdio frame")};if(b==10)break;require(line.size()<MAX_LINE+1);line.write(b)}
        var text=line.toString("US-ASCII");if(text.endsWith("\r"))text=text.dropLast(1)
        require(text.length in 4..MAX_LINE&&text.length%4==0&&text.matches(Regex("[A-Za-z0-9+/]+={0,2}")))
        val bytes=Base64.getDecoder().decode(text);require(Base64.getEncoder().encodeToString(bytes)==text)
        val inputFrame=ByteArrayInputStream(bytes);require(frame(inputFrame)?.size==bytes.size&&inputFrame.available()==0);return bytes
    }
    fun write(output:OutputStream,frame:ByteArray){output.write(Base64.getEncoder().encode(frame));output.write(10);output.flush()}
}
