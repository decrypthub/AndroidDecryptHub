package com.adh.daemon

import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class AgentEarlyAbiTest {
    @Test fun actualReleaseAgentExportsEarlyEntryAndKeepsInternalHelpersHidden(){
        val agent=File("../../agent/build/libadh_agent.so").canonicalFile
        assumeTrue("isolated native release build unavailable; run tools/build_agent.sh without deploy",agent.isFile)
        assertTrue("early entry must survive the production export map",AgentEarlyAbi.exported(agent))
        assertFalse(AgentEarlyAbi.exported(agent,"adh_agent_copy_owner"))
        assertFalse(AgentEarlyAbi.exported(agent,"adh_early_status_json"))
    }
    @Test fun markerAloneOrMalformedElfCannotAdvertiseSupport(){
        val file=Files.createTempFile("adh-p5-abi-",".bin").toFile()
        try{file.writeText("ADH_EARLY_PLAN_V1 adh_agent_apply_early_v1");assertFalse(AgentEarlyAbi.exported(file));file.writeBytes(ByteArray(128));assertFalse(AgentEarlyAbi.exported(file))}finally{file.delete()}
    }
}
