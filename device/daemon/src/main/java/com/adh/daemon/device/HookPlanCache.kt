package com.adh.daemon.device

import com.adh.core.DeviceRpc
import com.adh.core.EarlyPlanWire
import org.json.JSONObject
import java.io.File
import java.util.Base64
import java.util.UUID

internal fun interface HookBindingProbe { fun inspect(packageName:String):JSONObject }
/** Authoritative root cache; staging, authorization and consumption are distinct states. */
internal class HookPlanCache(private val operations:DeviceOperations,private val files:DeviceFiles,private val scope:ScopeDocuments,private val probe:HookBindingProbe){
    val methods=setOf("early.prepare","early.status","early.stage","early.revoke","hooks.migration.preview","hooks.migration.apply","hooks.migration.rollback")
    private val file=File(files.directory,"hook-cache.json")
    private var state=if(file.exists()){check(file.length()<=2*1024*1024);JSONObject(file.readText()).also{check(it.getInt("schemaVersion")==1&&it.getLong("revision")>=0)}}else JSONObject().put("schemaVersion",1).put("revision",0L).put("entries",JSONObject()).put("migrations",JSONObject())
    private var unavailable=false
    init {val entries=state.getJSONObject("entries");val migrations=state.getJSONObject("migrations")
        for(key in entries.keys()){val entry=entries.getJSONObject(key);require(key==entry.getString("package"));val wire=Base64.getDecoder().decode(entry.getString("wire"));require(wire.size<=EarlyPlanWire.MAX_BYTES&&DeviceRpc.sha256(wire)==entry.getString("wireSha256"));entry.getJSONObject("binding")}
        for(key in migrations.keys()){val migration=migrations.getJSONObject(key);require(key==migration.getString("package")&&DeviceRpc.sha256(migration.getString("beforeRaw").toByteArray())==migration.getString("beforeHash"))}
        operations.hookCache=this}
    private fun commit(candidate:JSONObject){if(unavailable)throw DeviceFault("CACHE_STORAGE_UNAVAILABLE","cache persistence requires inspection");val text=candidate.toString();if(text.toByteArray().size>2*1024*1024)throw DeviceFault("CACHE_FULL","cache history requires explicit archival");try{files.write(file,text);state=candidate}catch(_:Exception){unavailable=true;throw DeviceFault("CACHE_STORAGE_UNAVAILABLE","cache persistence unconfirmed",true)}}
    private fun revision()=state.getLong("revision")
    private fun next()=JSONObject(state.toString()).put("revision",revision()+1)
    private fun pkg(value:String):String{if(!Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+").matches(value)||value in setOf("com.adh.manager","com.adh.daemon"))throw DeviceFault("INVALID_ARGUMENT","explicit third-party package required");return value}
    private fun requireRevision(params:JSONObject){if(params.getLong("expectedCacheRevision")!=revision())throw DeviceFault("STALE_EARLY_CACHE","cache changed; observe before new intent")}
    fun validate(method:String,params:JSONObject){
        when(method){
            "early.stage"->{val plan=params.getJSONObject("plan");pkg(plan.getString("package"));val canonicalPlan=params.getString("canonicalPlan");require(canonicalPlan.toByteArray().size<=128*1024);if(DeviceRpc.canonical(JSONObject(canonicalPlan))!=DeviceRpc.canonical(plan)||DeviceRpc.sha256(canonicalPlan.toByteArray())!=params.getString("digest"))throw DeviceFault("PLAN_DIGEST_MISMATCH","plan body differs from immutable digest");try{EarlyPlanWire.validate(plan)}catch(_:Exception){throw DeviceFault("UNSUPPORTED_EARLY_PLAN","early supports named capture modules and observe-only GOT hooks, no waits/Java/inline/replay")};requireRevision(params);require(params.getString("offline")=="keep-until-expiry");val ttl=params.getLong("expiresAt")-System.currentTimeMillis()/1000;require(ttl in 1..86400)}
            "early.revoke"->{pkg(params.getString("package"));requireRevision(params);require(params.getString("deploymentId").length==36)}
            "hooks.migration.apply"->{pkg(params.getString("package"));require(Regex("[a-f0-9]{64}").matches(params.getString("planDigest")))}
            "hooks.migration.rollback"->require(params.getString("migrationId").length==36)
        }
    }
    @Synchronized fun execute(method:String,params:JSONObject,sourceGrant:String?=null):JSONObject{
        val packageName=params.optString("package")
        return when(method){
            "early.prepare"->{val binding=probe.inspect(pkg(packageName));JSONObject().put("binding",binding).put("cacheRevision",revision()).put("phase","post-specialize-before-agent-start").put("supported",binding.optBoolean("earlySupported")).put("maxTtlSeconds",86400)}
            "early.status"->{JSONObject().put("cacheRevision",revision()).put("available",!unavailable).put("entry",state.getJSONObject("entries").optJSONObject(packageName)?:JSONObject.NULL).put("migration",state.getJSONObject("migrations").optJSONObject(packageName)?:JSONObject.NULL).put("scopeRevision",scope.snapshot().getString("scopeRevision")).put("applied",JSONObject.NULL).put("note","staged/validated is not installed; runtime receipts are agent-reported")}
            "early.stage"->{validate(method,params);val plan=params.getJSONObject("plan");val name=plan.getString("package");val snapshot=scope.snapshot();val authority=snapshot.getJSONObject("document").optJSONObject("hookPlans")?.optJSONObject(name)
                if(authority?.optString("authority")!="host-plans/1")throw DeviceFault("MIGRATION_REQUIRED","preserve and migrate legacy policy before staging")
                val actual=probe.inspect(name);if(!actual.optBoolean("earlySupported"))throw DeviceFault("UNSUPPORTED_AGENT","installed agent lacks early-plan/1 export")
                if(DeviceRpc.canonical(actual)!=DeviceRpc.canonical(params.getJSONObject("binding")))throw DeviceFault("TARGET_CHANGED","APK/UID/version/signer/agent binding changed")
                val deployment=UUID.randomUUID().toString();val wire=EarlyPlanWire.encode(plan,actual,deployment,params.getString("digest"),params.getLong("expiresAt"));val candidate=next()
                candidate.getJSONObject("entries").put(name,JSONObject().put("deploymentId",deployment).put("digest",params.getString("digest")).put("package",name).put("binding",actual).put("expiresAt",params.getLong("expiresAt")).put("offline","keep-until-expiry").put("state","validated-cache").put("sourceGrant",sourceGrant?:JSONObject.NULL).put("wireSha256",DeviceRpc.sha256(wire)).put("wire",Base64.getEncoder().encodeToString(wire)))
                commit(candidate);execute("early.status",JSONObject().put("package",name)).put("ok",true)
            }
            "early.revoke"->{validate(method,params);val old=state.getJSONObject("entries").optJSONObject(packageName)?:throw DeviceFault("EARLY_NOT_FOUND","no cache for package");if(old.getString("deploymentId")!=params.getString("deploymentId"))throw DeviceFault("TARGET_CHANGED","another deployment replaced this cache");val candidate=next();candidate.getJSONObject("entries").getJSONObject(packageName).put("state","revoked").put("revokedAt",System.currentTimeMillis());commit(candidate);JSONObject().put("ok",true).put("cacheRevision",revision()).put("existingProcessesUnaffected",true)}
            "hooks.migration.preview"->{pkg(packageName);val raw=scope.raw();require(raw.toByteArray().size<=128*1024);JSONObject().put("scopeRaw",raw).put("scopeRevision",DeviceRpc.sha256(raw.toByteArray())).put("package",packageName).put("cacheRevision",revision()).put("willApply",false)}
            "hooks.migration.apply"->{validate(method,params);val before=scope.snapshot();if(params.getString("scopeRevision")!=before.getString("scopeRevision"))throw DeviceFault("STALE_SCOPE","scope changed")
                val doc=before.getJSONObject("document");if(!doc.getJSONArray("packages").toString().contains(JSONObject.quote(packageName)))throw DeviceFault("TARGET_DENIED","package not in scope")
                if(doc.optJSONObject("hookPlans")?.has(packageName)==true)throw DeviceFault("ALREADY_MIGRATED","package already managed; inspect previous backup")
                val raw=scope.raw();require(raw.toByteArray().size<=128*1024);val id=UUID.randomUUID().toString();val managed=JSONObject(doc.toString());val map=managed.optJSONObject("hookPlans")?:JSONObject();map.put(packageName,JSONObject().put("authority","host-plans/1").put("migrationId",id).put("sourcePlanDigest",params.getString("planDigest")));managed.put("hookPlans",map)
                val after=managed.toString(2);val backup=JSONObject().put("migrationId",id).put("package",packageName).put("beforeRaw",raw).put("beforeHash",before.getString("scopeRevision")).put("afterHash",DeviceRpc.sha256(after.toByteArray())).put("state","prepared")
                val reserved=next();reserved.getJSONObject("migrations").put(packageName,backup);commit(reserved)
                scope.restoreExact(after,before.getString("scopeRevision"));val complete=next();complete.getJSONObject("migrations").getJSONObject(packageName).put("state","migrated");commit(complete)
                JSONObject().put("ok",true).put("migrationId",id).put("scopeRevision",backup.getString("afterHash")).put("cacheRevision",revision()).put("applied",false)
            }
            "hooks.migration.rollback"->{validate(method,params);val match=state.getJSONObject("migrations").keys().asSequence().map{state.getJSONObject("migrations").getJSONObject(it)}.firstOrNull{it.getString("migrationId")==params.getString("migrationId")}?:throw DeviceFault("MIGRATION_NOT_FOUND","backup not found")
                if(params.getString("scopeRevision")!=match.getString("afterHash"))throw DeviceFault("STALE_SCOPE","later scope edits prevent exact rollback")
                if(DeviceRpc.sha256(match.getString("beforeRaw").toByteArray())!=match.getString("beforeHash"))throw DeviceFault("CACHE_CORRUPT","original scope backup differs")
                scope.restoreExact(match.getString("beforeRaw"),params.getString("scopeRevision"));val candidate=next();candidate.getJSONObject("migrations").getJSONObject(match.getString("package")).put("state","rolled-back");candidate.getJSONObject("entries").optJSONObject(match.getString("package"))?.put("state","revoked");commit(candidate)
                JSONObject().put("ok",true).put("scopeRevision",match.getString("beforeHash")).put("cacheRevision",revision()).put("existingProcessesUnaffected",true)
            }
            else->throw DeviceFault("UNSUPPORTED_METHOD","unknown hook cache capability")
        }
    }
    @Synchronized fun forProcess(packageName:String,uid:Int):ByteArray?{
        if(unavailable)return null;val entry=state.getJSONObject("entries").optJSONObject(packageName)?:return null
        if(entry.optString("state")!="validated-cache"||entry.getLong("expiresAt")<=System.currentTimeMillis()/1000)return null
        val grant=entry.optString("sourceGrant").takeIf{it.isNotEmpty()&&it!="null"};if(grant!=null&&runCatching{operations.network?.pairings?.authorize(grant,"early.stage")?:throw DeviceFault("AUTH_REVOKED","authorization unavailable")}.isFailure)return null
        val scopeDoc=scope.snapshot().getJSONObject("document");if(scopeDoc.optJSONObject("hookPlans")?.optJSONObject(packageName)?.optString("authority")!="host-plans/1"||(0 until scopeDoc.getJSONArray("packages").length()).none{scopeDoc.getJSONArray("packages").getString(it)==packageName})return null
        val actual=probe.inspect(packageName);if(actual.getInt("uid")!=uid||DeviceRpc.canonical(actual)!=DeviceRpc.canonical(entry.getJSONObject("binding")))return null
        val wire=Base64.getDecoder().decode(entry.getString("wire"));if(DeviceRpc.sha256(wire)!=entry.getString("wireSha256"))return null;return wire
    }
}
