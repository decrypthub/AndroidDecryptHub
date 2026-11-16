package com.adh.daemon.device

import com.adh.core.DeviceRpc
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class DeviceNetworkTest {
    private fun root() = Files.createTempDirectory("adh-p4-unit-").toFile()
    private fun key() = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private fun request(publicKey: java.security.PublicKey, vararg permissions: String) = JSONObject().put("publicKey", Base64.getEncoder().encodeToString(publicKey.encoded)).put("permissions", JSONArray(permissions.toList())).put("label", "fixture")
    @Test fun grantsArePersistentScopedAndRevokedWithoutErasingHistory() {
        val dir=root();val pairings=DevicePairings(DeviceFiles(dir));val key=key();val grant=pairings.grant(request(key.public,"read"));val id=grant.getString("grantId")
        pairings.authorize(id,"scope.get")
        assertEquals("PERMISSION_DENIED",(runCatching { pairings.authorize(id,"scope.patch") }.exceptionOrNull() as DeviceFault).code)
        assertEquals("PERMISSION_DENIED",(runCatching { pairings.authorize(id,"pairings.list") }.exceptionOrNull() as DeviceFault).code)
        assertEquals("PAIRING_EXISTS",(runCatching { pairings.grant(request(key.public,"read")) }.exceptionOrNull() as DeviceFault).code)
        var closed="";pairings.revoked={closed=it};pairings.revoke(JSONObject().put("grantId",id));assertEquals(id,closed)
        val restored=DevicePairings(DeviceFiles(dir));assertEquals("AUTH_REVOKED",(runCatching { restored.authorize(id,"scope.get") }.exceptionOrNull() as DeviceFault).code)
        assertTrue(restored.list().getJSONArray("grants").getJSONObject(0).has("revokedAt"));assertFalse(restored.list().toString().contains("publicKey"))
    }
    @Test fun proofIsBoundToTheWholeChallengeAndGrant() {
        val pairings=DevicePairings(DeviceFiles(root()));val key=key();val grant=pairings.grant(request(key.public,"read","write"));val message="fixture-challenge".toByteArray()
        val proof=Signature.getInstance("SHA256withRSA").run { initSign(key.private);update(message);sign() }
        val auth=JSONObject().put("grantId",grant.getString("grantId")).put("clientId",grant.getString("clientId")).put("signature",Base64.getEncoder().encodeToString(proof))
        assertEquals(grant.getString("grantId"),pairings.authenticate(auth,message))
        assertEquals("AUTH_FAILED",(runCatching { pairings.authenticate(auth,"other-challenge".toByteArray()) }.exceptionOrNull() as DeviceFault).code)
        pairings.revoke(JSONObject().put("grantId",grant.getString("grantId")))
        assertEquals("AUTH_FAILED",(runCatching { pairings.authenticate(auth,message) }.exceptionOrNull() as DeviceFault).code)
    }
    @Test fun storageFailureClosesAuthorizationAndCorruptionIsNeverRebuilt() {
        val dir=root();var fail=false;val files=DeviceFiles(dir,{_,_->if(fail)throw java.io.IOException("fixture")});val pairings=DevicePairings(files);val key=key();val grant=pairings.grant(request(key.public,"read"));fail=true
        assertEquals("AUTH_STORAGE_UNAVAILABLE",(runCatching { pairings.revoke(JSONObject().put("grantId",grant.getString("grantId"))) }.exceptionOrNull() as DeviceFault).code)
        assertEquals("AUTH_STORAGE_UNAVAILABLE",(runCatching { pairings.authorize(grant.getString("grantId"),"scope.get") }.exceptionOrNull() as DeviceFault).code)
        File(dir,"pairings.json").writeText("corrupt");assertTrue(runCatching { DevicePairings(DeviceFiles(dir)) }.isFailure);assertEquals("corrupt",File(dir,"pairings.json").readText())
    }
    @Test fun tlsIdentityPersistsAndListenerIsDisabledUntilAnExplicitConfiguration() {
        val dir=root();val files=DeviceFiles(dir);val identity=DeviceIdentity(files,"00000000-0000-4000-8000-000000000001")
        val ops=DeviceOperations(identity,files,DeviceBackend{_,_->JSONObject()});val network=DeviceNetwork(ops,files,true)
        try {
            assertFalse(network.execute("lan.status",JSONObject()).getBoolean("listening"));assertFalse(File(dir,"tls-certificate.der.b64").exists())
            val configured=network.execute("lan.configure",JSONObject().put("enabled",true).put("address","127.0.0.1").put("port",0));assertTrue(configured.getInt("port")>0)
            val cert=File(dir,"tls-certificate.der.b64").readText();DeviceTls.context(identity,files);assertEquals(cert,File(dir,"tls-certificate.der.b64").readText())
            val before=File(dir,"lan.json").readText()
            assertEquals("INVALID_ARGUMENT",(runCatching { network.execute("lan.configure",JSONObject().put("enabled",true).put("address","invalid.invalid").put("port",0)) }.exceptionOrNull() as DeviceFault).code)
            assertEquals(before,File(dir,"lan.json").readText())
            for (params in listOf(JSONObject().put("enabled",true).put("address","deadbeef").put("port",8762),JSONObject().put("enabled",true).put("address","127.0.0.1").put("port",1.5))) {
                assertEquals("INVALID_ARGUMENT",(runCatching { network.execute("lan.configure",params) }.exceptionOrNull() as DeviceFault).code)
            }
        } finally { network.close() }
    }
    @Test fun requestAuthorizationRunsInsideTheDomainBeforeIdempotencyOrEffects() {
        val dir=root();val files=DeviceFiles(dir);var hits=0;val ops=DeviceOperations(DeviceIdentity(files,"00000000-0000-4000-8000-000000000001"),files,DeviceBackend{_,_->hits++;JSONObject().put("ok",true)})
        val first=ops.write("host.set",JSONObject(),"same-id",0,"ai",1000);assertEquals("succeeded",first.getString("state"))
        val denied=runCatching { ops.write("host.set",JSONObject(),"same-id",0,"ai",1000,authorize={throw DeviceFault("AUTH_REVOKED","fixture")}) }.exceptionOrNull() as DeviceFault
        assertEquals("AUTH_REVOKED",denied.code);assertEquals(1,hits)
        val facts=ops.read("operations.reconcile",JSONObject().put("operationIds",JSONArray(listOf("same-id","not-present"))))
        assertFalse(facts.getBoolean("replayed"));assertTrue(facts.getBoolean("notFoundDoesNotProveUnsent"));assertFalse(facts.getJSONArray("operations").getJSONObject(1).getBoolean("found"))
    }
}
