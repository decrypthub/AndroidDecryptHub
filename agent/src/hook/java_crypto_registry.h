#ifndef ADH_JAVA_CRYPTO_REGISTRY_H
#define ADH_JAVA_CRYPTO_REGISTRY_H
#include "../capture/capture_methods.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Bounded execution policy, not analysis. Caller serializes access; LSPlant/JNI work
// happens outside the policy lock and is committed against the current generation.
struct AdhCryptoMethod {
    std::string cls, method, params, id, error;
    int mode = 0, hookId = 0, active = 0;
    uint32_t families = 0;
    uint64_t dependencies = 0;
    bool dependencyUnavailable = false;
    bool selected = true;
};
struct AdhCryptoRegistry {
    static constexpr size_t limit = 40;
    std::vector<AdhCryptoMethod> methods;
    std::string catalog, error;
    uint32_t revision = 1;
    uint64_t generation = 1;
    uint32_t families = ADH_CF_DIGEST|ADH_CF_HMAC|ADH_CF_SYMMETRIC|ADH_CF_ASYMMETRIC|ADH_CF_TLS|ADH_CF_AEAD;
    bool discovered = false, running = false, truncated = false;

    const char *publish(std::vector<AdhCryptoMethod> found, bool capped) {
        if (discovered) return "CATALOG_ALREADY_BOUND";
        if (found.empty()) return "CATALOG_EMPTY";
        for (auto &m : found) m.id = "java." + m.cls + "#" + m.method + "(" + m.params + ")";
        std::sort(found.begin(), found.end(), [](const auto &a,const auto &b){return a.id < b.id;});
        found.erase(std::unique(found.begin(), found.end(), [](const auto &a,const auto &b){return a.id == b.id;}),found.end());
        if (found.size() > limit) { found.resize(limit); capped = true; }
        for (const auto &m : found) if (m.id.size() > 768 || !m.families) return "INVALID_CATALOG";
        methods = std::move(found); truncated = capped;
        uint64_t digest = UINT64_C(14695981039346656037);
        for (size_t i = 0; i < methods.size(); i++) {
            auto &m = methods[i];
            const char *init = m.cls == "javax.crypto.Cipher" && m.method == "doFinal" ? "init" :
                m.cls == "javax.crypto.Mac" && m.method == "doFinal" ? "init" :
                m.cls == "java.security.Signature" && m.method == "sign" ? "initSign" :
                m.cls == "java.security.Signature" && m.method == "verify" ? "initVerify" : nullptr;
            if (init) for (size_t j = 0; j < methods.size(); j++)
                if (methods[j].cls == m.cls && methods[j].method == init) m.dependencies |= UINT64_C(1) << j;
            m.dependencyUnavailable = init && !m.dependencies;
            const std::string row=m.id+":"+std::to_string(m.mode)+":"+std::to_string(m.families)+":"+std::to_string(m.dependencies)+"\n";
            for (unsigned char c : row) { digest ^= c; digest *= UINT64_C(1099511628211); }
        }
        char version[64]; std::snprintf(version,sizeof(version),"java-crypto/1:%016llx",(unsigned long long)digest);
        catalog = version; discovered = true; revision++; generation++;
        return nullptr;
    }
    uint64_t effective() const {
        uint64_t allowed = 0, wanted = 0;
        for (size_t i = 0; i < methods.size(); i++) {
            if (!methods[i].dependencyUnavailable && (methods[i].families & families)) { allowed |= UINT64_C(1)<<i; if(methods[i].selected) wanted |= UINT64_C(1)<<i; }
        }
        for (size_t pass = 0; pass < methods.size(); pass++) {
            uint64_t next = wanted;
            for (size_t i = 0; i < methods.size(); i++) if (wanted & (UINT64_C(1)<<i)) next |= methods[i].dependencies & allowed;
            if (next == wanted) break; wanted = next;
        }
        return wanted;
    }
    const char *select(const char *version,const char *expected,const char *bits,bool settling) {
        uint32_t r;
        if (!discovered) return "CATALOG_NOT_READY";
        if (!version || catalog != version) return "CATALOG_MISMATCH";
        if (!adh_capture_revision(expected,&r)) return "INVALID_REVISION";
        if (r != revision) return "REVISION_CONFLICT";
        if (running) return "CAPTURE_ACTIVE";
        if (settling) return "JAVA_SETTLING";
        if (!bits || std::strlen(bits) != methods.size()) return "INVALID_SELECTION";
        for(size_t i=0;i<methods.size();i++)if(bits[i]!='0'&&bits[i]!='1')return "INVALID_SELECTION";
        if (revision == UINT32_MAX) return "REVISION_EXHAUSTED";
        bool changed=false;
        for(size_t i=0;i<methods.size();i++)if(methods[i].selected != (bits[i]=='1'))changed=true;
        if(changed) { for(size_t i=0;i<methods.size();i++)methods[i].selected=bits[i]=='1';revision++;generation++; }
        return nullptr;
    }
    void set_families(uint32_t value) { if(families!=value){families=value;if(revision<UINT32_MAX)revision++;generation++;} }
    void set_running(bool value) { if(running!=value){running=value;generation++;} }
    bool want(size_t i) const { return running && !!(effective() & (UINT64_C(1)<<i)); }
};
#endif
