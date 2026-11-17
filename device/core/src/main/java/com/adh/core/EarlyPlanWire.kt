package com.adh.core

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest

/** Bounded, non-executable wire for post-specialize/before-agent-start operations. */
object EarlyPlanWire {
    const val MAX_BYTES = 32768
    const val MARKER = "ADH_EARLY_PLAN_V1"
    val FAMILIES = listOf("digest", "hmac", "symmetric", "asymmetric", "tls", "aead", "system")
    fun validate(plan: JSONObject) {
        require(plan.getInt("schemaVersion") == 1)
        val families = plan.getJSONObject("families"); require(families.length() == 7)
        for (key in FAMILIES) require(families.get(key) is Boolean)
        val steps = plan.getJSONArray("steps"); require(steps.length() in 1..16)
        for (i in 0 until steps.length()) {
            val step=steps.getJSONObject(i); require(step.optLong("waitMs",0)==0L)
            val args=step.getJSONObject("arguments")
            when(step.getString("tool")) {
                "capture_start" -> {require(args.keys().asSequence().all { it in setOf("cryptoModule","fileModule","sysModule") });for(key in listOf("cryptoModule","fileModule","sysModule")) module(args.getString(key),key!="cryptoModule")}
                "native_hook" -> {require(args.keys().asSequence().all { it in setOf("action","mode","module","symbol","mem") });require(args.getString("action")=="hook"&&args.getString("mode")=="got");module(args.getString("module"),false);require(Regex("[A-Za-z_][A-Za-z0-9_.$@]{0,126}").matches(args.getString("symbol")));require(args.optString("mem") in setOf("","auto"))}
                else -> throw IllegalArgumentException("early tool unsupported; live Host plan remains available")
            }
        }
    }
    private fun module(value:String,empty:Boolean){require((empty&&value.isEmpty())||value.length in 1..63&&value.split(',').size<=8&&Regex("[A-Za-z0-9_./+,-]+").matches(value))}
    fun encode(plan:JSONObject,binding:JSONObject,deploymentId:String,planDigest:String,expiresAt:Long):ByteArray{
        validate(plan)
        val bytes=ByteArrayOutputStream();val out=DataOutputStream(bytes)
        fun text(value:String){val data=value.toByteArray(Charsets.US_ASCII);require(data.size<=255);out.writeShort(data.size);out.write(data)}
        out.write("ADHEP1\r\n".toByteArray());text(deploymentId);text(planDigest);text(plan.getString("package"));out.writeInt(binding.getInt("uid"));text(binding.getString("agentSha256"));out.writeLong(expiresAt)
        var mask=0;for((n,key)in FAMILIES.withIndex())if(plan.getJSONObject("families").getBoolean(key))mask=mask or (1 shl n)
        out.writeByte(mask);out.writeByte(plan.getJSONArray("steps").length())
        for(i in 0 until plan.getJSONArray("steps").length()){
            val step=plan.getJSONArray("steps").getJSONObject(i);val args=step.getJSONObject("arguments");val capture=step.getString("tool")=="capture_start"
            out.writeByte(if(capture)1 else 2);text(args.getString(if(capture)"cryptoModule" else "module"));text(args.getString(if(capture)"fileModule" else "symbol"));text(if(capture)args.getString("sysModule")else args.optString("mem"))
        }
        out.flush();val body=bytes.toByteArray();require(body.size+32<=MAX_BYTES);return MessageDigest.getInstance("SHA-256").digest(body)+body
    }
}
