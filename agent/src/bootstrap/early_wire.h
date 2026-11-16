#ifndef ADH_EARLY_WIRE_H
#define ADH_EARLY_WIRE_H
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <unistd.h>

// SHA-256 for integrity/binary identity only; authorization belongs to the root broker.
struct AdhSha256 {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t buffer[64]{};size_t used=0;uint64_t length=0;
    static uint32_t r(uint32_t x,unsigned n){return(x>>n)|(x<<(32-n));}
    void block(const uint8_t* p){
        static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];for(int i=0;i<16;i++)w[i]=(uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|(uint32_t(p[i*4+2])<<8)|p[i*4+3];
        for(int i=16;i<64;i++)w[i]=w[i-16]+(r(w[i-15],7)^r(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(r(w[i-2],17)^r(w[i-2],19)^(w[i-2]>>10));
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
        for(int i=0;i<64;i++){uint32_t t=v+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t u=(r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c));v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
    }
    void update(const void* data,size_t size){const auto* p=static_cast<const uint8_t*>(data);length+=size;while(size){size_t n=64-used;if(n>size)n=size;memcpy(buffer+used,p,n);used+=n;p+=n;size-=n;if(used==64){block(buffer);used=0;}}}
    void final(uint8_t out[32]){uint64_t bits=length*8;buffer[used++]=0x80;if(used>56){while(used<64)buffer[used++]=0;block(buffer);used=0;}while(used<56)buffer[used++]=0;for(int i=7;i>=0;i--)buffer[used++]=uint8_t(bits>>(i*8));block(buffer);for(int i=0;i<32;i++)out[i]=uint8_t(h[i/4]>>(24-8*(i%4)));}
};
inline std::string adh_hex(const uint8_t* data,size_t n){static const char d[]="0123456789abcdef";std::string s;for(size_t i=0;i<n;i++){s+=d[data[i]>>4];s+=d[data[i]&15];}return s;}
inline std::string adh_sha_fd(int fd){auto old=lseek(fd,0,SEEK_CUR);if(lseek(fd,0,SEEK_SET)<0)return{};AdhSha256 hash;uint8_t data[8192];size_t total=0;bool ok=true;for(;;){auto n=read(fd,data,sizeof(data));if(n<0){ok=false;break;}if(!n)break;total+=size_t(n);if(total>128*1024*1024){ok=false;break;}hash.update(data,size_t(n));}if(old>=0)lseek(fd,old,SEEK_SET);if(!ok)return{};uint8_t out[32];hash.final(out);return adh_hex(out,32);}
constexpr size_t ADH_EARLY_MAX=32768;
struct AdhEarlyStep {uint8_t type=0;char a[160]{},b[160]{},c[160]{};};
struct AdhEarlyPlan {char deployment[40]{},digest[65]{},package[256]{},agentSha[65]{};uint32_t uid=0;uint64_t expires=0;uint8_t families=0,count=0;AdhEarlyStep steps[16]{};};
struct AdhEarlyReader {const uint8_t* data;size_t size,pos=0;bool ok=true;
    uint64_t num(size_t n){if(n>8||pos+n>size){ok=false;return 0;}uint64_t v=0;while(n--)v=(v<<8)|data[pos++];return v;}
    bool text(char* out,size_t cap){size_t n=size_t(num(2));if(!ok||n>=cap||pos+n>size){ok=false;return false;}for(size_t i=0;i<n;i++)if(data[pos+i]<32||data[pos+i]>126){ok=false;return false;}memcpy(out,data+pos,n);out[n]=0;pos+=n;return true;}
};
inline bool adh_hash_string(const char* s){if(strlen(s)!=64)return false;for(int i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;return true;}
inline bool adh_module_string(const char* s,bool empty){if(!s[0])return empty;if(strlen(s)>63)return false;unsigned commas=0;for(const char* p=s;*p;p++){char c=*p;if(c==',')commas++;if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||strchr("_./+,-",c)))return false;}return commas<8;}
inline bool adh_early_parse(const void* value,size_t size,const char* package,uint32_t uid,const char* agentSha,uint64_t now,AdhEarlyPlan& plan){
    if(!value||size<40||size>ADH_EARLY_MAX)return false;const auto* bytes=static_cast<const uint8_t*>(value);AdhSha256 hash;uint8_t actual[32];hash.update(bytes+32,size-32);hash.final(actual);if(memcmp(actual,bytes,32)||memcmp(bytes+32,"ADHEP1\r\n",8))return false;
    AdhEarlyReader r{bytes+40,size-40};if(!r.text(plan.deployment,sizeof(plan.deployment))||strlen(plan.deployment)!=36||!r.text(plan.digest,sizeof(plan.digest))||!adh_hash_string(plan.digest)||!r.text(plan.package,sizeof(plan.package)))return false;
    plan.uid=uint32_t(r.num(4));if(!r.text(plan.agentSha,sizeof(plan.agentSha))||!adh_hash_string(plan.agentSha))return false;plan.expires=r.num(8);plan.families=uint8_t(r.num(1));plan.count=uint8_t(r.num(1));
    if(!r.ok||strcmp(plan.package,package)||plan.uid!=uid||strcmp(plan.agentSha,agentSha)||plan.expires<=now||plan.expires-now>86400||plan.families>127||plan.count<1||plan.count>16)return false;
    for(unsigned i=0;i<plan.count;i++){auto& s=plan.steps[i];s.type=uint8_t(r.num(1));if(!r.text(s.a,sizeof(s.a))||!r.text(s.b,sizeof(s.b))||!r.text(s.c,sizeof(s.c)))return false;
        if(s.type==1){if(!adh_module_string(s.a,false)||!adh_module_string(s.b,true)||!adh_module_string(s.c,true))return false;}
        else if(s.type==2){if(!adh_module_string(s.a,false)||!s.b[0]||(strcmp(s.c,"")&&strcmp(s.c,"auto")))return false;for(const char* p=s.b;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||strchr("_.$@",*p)))return false;}
        else return false;
    }return r.ok&&r.pos==r.size;
}
struct AdhEarlyReceipt {int attempted=0,confirmed=0;int counts[16]{},hookIds[16]{};bool applied=false;};
using AdhEarlyApply=int(*)(const AdhEarlyStep&,int*,void*);
inline AdhEarlyReceipt adh_early_run(const AdhEarlyPlan& plan,AdhEarlyApply apply,void* context){AdhEarlyReceipt result;for(unsigned n=0;n<plan.count;n++){result.attempted++;result.counts[n]=apply(plan.steps[n],&result.hookIds[n],context);if(result.counts[n]<=0)break;result.confirmed++;}result.applied=result.confirmed==plan.count;return result;}
#endif
