package com.adh.daemon

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Inspects the actual release .dynsym; an embedded marker or local symbol is insufficient. */
internal object AgentEarlyAbi {
    fun exported(file:File,symbol:String="adh_agent_apply_early_v1"):Boolean=runCatching{RandomAccessFile(file,"r").use{input->
        require(input.length()<=128L*1024*1024)
        fun bytes(offset:Long,count:Int):ByteArray{require(offset>=0&&count>=0&&offset<=input.length()-count);return ByteArray(count).also{input.seek(offset);input.readFully(it)}}
        val head=ByteBuffer.wrap(bytes(0,64)).order(ByteOrder.LITTLE_ENDIAN);require(head.getInt(0)==0x464c457f&&head.get(4).toInt()==2&&head.get(5).toInt()==1&&head.getShort(18).toInt()==183)
        val offset=head.getLong(40);val size=head.getShort(58).toInt()and 65535;val count=head.getShort(60).toInt()and 65535;require(size==64&&count in 1..4096)
        for(n in 0 until count){val section=ByteBuffer.wrap(bytes(offset+n*size,64)).order(ByteOrder.LITTLE_ENDIAN);if(section.getInt(4)!=11)continue
            val table=section.getLong(24);val length=section.getLong(32);val linked=section.getInt(40);val entry=section.getLong(56);require(entry==24L&&length>=0&&length/entry<=200000&&linked in 0 until count)
            val strings=ByteBuffer.wrap(bytes(offset+linked*size,64)).order(ByteOrder.LITTLE_ENDIAN);val stringOffset=strings.getLong(24);val stringSize=strings.getLong(32)
            for(i in 0 until length/entry){val row=ByteBuffer.wrap(bytes(table+i*entry,24)).order(ByteOrder.LITTLE_ENDIAN);val name=row.getInt(0).toLong()and 0xffffffffL
                if(name>=stringSize||row.getShort(6).toInt()==0||row.get(4).toInt()ushr 4 !in setOf(1,2)||row.get(5).toInt()and 3 !=0)continue
                val text=bytes(stringOffset+name,minOf(symbol.length+1L,stringSize-name).toInt());if(text.size==symbol.length+1&&text.last()==0.toByte()&&String(text,0,symbol.length,Charsets.US_ASCII)==symbol)return@use true
            }
        };false
    }}.getOrDefault(false)
}
