package com.adh.daemon.device

import com.adh.core.DeviceRpc
import com.adh.core.ScopeConfig
import com.adh.core.ScopeJson
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

internal class ScopeDocuments(private val file: File, private val files: DeviceFiles) {
    fun raw():String {check(!file.exists()||file.length()<=512*1024);return (if(file.exists())file.readText()else ScopeJson.encode(ScopeConfig.EMPTY)).also{ScopeJson.decode(it)}}
    fun restoreExact(raw:String,expected:String){if(snapshot().getString("scopeRevision")!=expected)throw DeviceFault("STALE_SCOPE","scope changed before exact restore");ScopeJson.decode(raw);files.write(file,raw,420)}
    fun snapshot(): JSONObject {
        check(!file.exists() || file.length() <= 512 * 1024) { "scope document too large" }
        val raw = if (file.exists()) file.readText() else ScopeJson.encode(ScopeConfig.EMPTY)
        ScopeJson.decode(raw) // Malformed existing state is never replaced by an empty allowlist.
        return JSONObject().put("document", JSONObject(raw)).put("scopeRevision", DeviceRpc.sha256(raw.toByteArray()))
    }
    fun patch(params: JSONObject): JSONObject {
        val before = snapshot()
        if (params.optString("scopeRevision") != before.getString("scopeRevision")) throw DeviceFault("STALE_SCOPE", "scope changed outside this request")
        val doc = before.getJSONObject("document")
        val packages = doc.optJSONArray("packages") ?: JSONArray()
        val current = (0 until packages.length()).map { packages.getString(it) }.toMutableSet()
        fun values(name: String): List<String> {
            if (!params.has(name)) return emptyList()
            val array = params.optJSONArray(name) ?: throw DeviceFault("INVALID_ARGUMENT", "scope package values must be arrays")
            require(array.length() <= 4096)
            return (0 until array.length()).map { array.getString(it) }.onEach { require(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+").matches(it) && it != "com.adh.manager" && it != "com.adh.daemon") }
        }
        if (params.has("set")) { current.clear(); current.addAll(values("set")) }
        current.removeAll(values("remove").toSet()); current.addAll(values("add"))
        doc.put("packages", JSONArray(current.sorted())) // Preserve the COMPLETE policy and unknown fields.
        files.write(file, doc.toString(2), 420)
        return snapshot().put("ok", true)
    }
    fun replace(raw: String, expected: String? = null): JSONObject {
        val before = snapshot()
        if (expected != null && expected != before.getString("scopeRevision")) throw DeviceFault("STALE_SCOPE", "scope changed outside this request")
        val input = JSONObject(raw)
        val original=JSONObject(before.getJSONObject("document").toString())
        val authorities=original.optJSONObject("hookPlans")?:JSONObject()
        if(input.has("hookPlans")&&DeviceRpc.canonical(input.get("hookPlans"))!=DeviceRpc.canonical(authorities))throw DeviceFault("HOOK_PLANS_MANAGED","authority changes require reversible Host migration")
        for(pkg in authorities.keys()){
            val beforeConfig=ScopeJson.decode(original.toString());val nextConfig=ScopeJson.decode(raw)
            if(beforeConfig.contains(pkg)&&nextConfig.contains(pkg)&&beforeConfig.familiesFor(pkg)!=nextConfig.familiesFor(pkg))throw DeviceFault("HOOK_PLANS_MANAGED","fixed phone Hook policy is managed by Host plans")
        }
        val normalized = JSONObject(ScopeJson.encode(ScopeJson.decode(raw)))
        val merged = before.getJSONObject("document")
        for (key in input.keys()) if (key !in setOf("version", "mode", "packages", "policy")) merged.put(key, input.get(key))
        for (key in listOf("version", "mode", "packages")) merged.put(key, normalized.get(key))
        // Manager edits known policy keys. Preserve future keys while allowing known keys to reset.
        val oldPolicy = merged.optJSONObject("policy") ?: JSONObject()
        val policy = JSONObject()
        for (pkg in oldPolicy.keys()) {
            val entry = oldPolicy.optJSONObject(pkg)
            if (entry == null) { policy.put(pkg, oldPolicy.get(pkg)); continue }
            val kept = JSONObject(entry.toString()).apply { remove("c"); remove("b") }
            val c = entry.optJSONObject("c")
            val unknown = JSONObject()
            if (c != null) for (key in c.keys()) if (key !in setOf("d", "h", "s", "a", "t", "e", "y")) unknown.put(key, c.get(key))
            if (unknown.length() > 0) kept.put("c", unknown)
            if (kept.length() > 0) policy.put(pkg, kept)
        }
        val next = normalized.optJSONObject("policy") ?: JSONObject()
        // Preserve/accept future fields in an explicit RPC document too; normalize only known keys.
        val requested = input.optJSONObject("policy") ?: JSONObject()
        for (pkg in requested.keys()) {
            val requestedEntry = requested.optJSONObject(pkg) ?: continue
            val entry = policy.optJSONObject(pkg) ?: JSONObject()
            for (key in requestedEntry.keys()) if (key !in setOf("c", "b")) entry.put(key, requestedEntry.get(key))
            val c = entry.optJSONObject("c") ?: JSONObject()
            val requestedC = requestedEntry.optJSONObject("c")
            if (requestedC != null) for (key in requestedC.keys()) if (key !in setOf("d", "h", "s", "a", "t", "e", "y")) c.put(key, requestedC.get(key))
            if (c.length() > 0) entry.put("c", c)
            if (entry.length() > 0) policy.put(pkg, entry)
        }
        for (pkg in next.keys()) {
            val entry = policy.optJSONObject(pkg) ?: JSONObject()
            val c = entry.optJSONObject("c") ?: JSONObject()
            val known = next.getJSONObject(pkg).getJSONObject("c")
            for (key in known.keys()) c.put(key, known.get(key))
            policy.put(pkg, entry.put("c", c))
        }
        if (policy.length() > 0) merged.put("policy", policy) else merged.remove("policy")
        for(pkg in authorities.keys())original.optJSONObject("policy")?.opt(pkg)?.let{val current=merged.optJSONObject("policy")?:JSONObject();current.put(pkg,it);merged.put("policy",current)}
        files.write(file, merged.toString(2), 420)
        return snapshot().put("ok", true)
    }
}
