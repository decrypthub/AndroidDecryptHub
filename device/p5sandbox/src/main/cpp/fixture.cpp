#include <jni.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
#include "early_wire.h"
static void (*start_agent)()=nullptr;
static int (*system_probe)(const char*)=nullptr;
static jstring fail(JNIEnv* env,const char* message){env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),message);return nullptr;}
extern "C" JNIEXPORT jstring JNICALL Java_com_adh_p5sandbox_ProbeService_bootstrap(JNIEnv* env,jclass,jstring dir,jstring wire,jstring sha,jboolean deferred){
    const char* d=env->GetStringUTFChars(dir,nullptr);const char* w=env->GetStringUTFChars(wire,nullptr);const char* expected=env->GetStringUTFChars(sha,nullptr);
    std::string directory=d,path=w,wanted=expected;env->ReleaseStringUTFChars(dir,d);env->ReleaseStringUTFChars(wire,w);env->ReleaseStringUTFChars(sha,expected);
    // Hash the actual loaded file, never trust the test driver's supplied digest.
    int fd=open((directory+"/libadh_agent.so").c_str(),O_RDONLY|O_CLOEXEC);if(fd<0)return fail(env,"open Agent failed");std::string actual=adh_sha_fd(fd);close(fd);
    if(actual.empty()||actual!=wanted)return fail(env,"actual Agent SHA mismatch");
    void* target=dlopen((directory+"/libp5target.so").c_str(),RTLD_NOW);void* agent=dlopen((directory+"/libadh_agent.so").c_str(),RTLD_NOW);
    if(!target||!agent)return fail(env,dlerror());
    auto probe=reinterpret_cast<long(*)()>(dlsym(target,"p5_target_probe"));system_probe=reinterpret_cast<int(*)(const char*)>(dlsym(target,"p5_system_probe"));auto package=reinterpret_cast<void(*)(const char*)>(dlsym(agent,"adh_agent_set_package"));auto policy=reinterpret_cast<void(*)(const char*)>(dlsym(agent,"adh_agent_set_policy"));auto early=reinterpret_cast<int(*)(const void*,size_t,const char*,const char*)>(dlsym(agent,"adh_agent_apply_early_v1"));start_agent=reinterpret_cast<void(*)()>(dlsym(agent,"adh_agent_start"));
    if(!probe||!system_probe||!package||!policy||!early||!start_agent)return fail(env,"missing fixture exports");
    std::ifstream input(path,std::ios::binary);std::vector<char> bytes((std::istreambuf_iterator<char>(input)),std::istreambuf_iterator<char>());if(bytes.size()>32768)return fail(env,"wire too large");
    package("com.adh.p5sandbox");policy("d=0,h=0,s=0,a=0,t=0,e=0,y=0");int result=bytes.empty()?-1:early(bytes.data(),bytes.size(),"com.adh.p5sandbox",actual.c_str());long value=probe();
    char receipt[512];snprintf(receipt,sizeof(receipt),"{\"pid\":%d,\"uid\":%d,\"wireBytes\":%zu,\"earlyApply\":%d,\"probeReturn\":%ld,\"actualAgentSha\":\"%s\",\"probeBeforeAgentStart\":true}",getpid(),getuid(),bytes.size(),result,value,actual.c_str());
    if(!deferred)start_agent();return env->NewStringUTF(receipt);
}
extern "C" JNIEXPORT void JNICALL Java_com_adh_p5sandbox_ProbeService_startAgent(JNIEnv*,jclass){if(start_agent)start_agent();}
extern "C" JNIEXPORT jint JNICALL Java_com_adh_p5sandbox_ProbeService_systemProbe(JNIEnv* env,jclass,jstring path){const char* p=env->GetStringUTFChars(path,nullptr);int rc=system_probe?system_probe(p):-9;env->ReleaseStringUTFChars(path,p);return rc;}
