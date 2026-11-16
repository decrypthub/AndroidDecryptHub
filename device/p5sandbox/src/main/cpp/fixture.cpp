#include <jni.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>
extern "C" JNIEXPORT jstring JNICALL Java_com_adh_p5sandbox_ProbeService_bootstrap(JNIEnv* env,jclass,jstring dir,jstring wire,jstring sha){
    const char* d=env->GetStringUTFChars(dir,nullptr);const char* w=env->GetStringUTFChars(wire,nullptr);const char* hash=env->GetStringUTFChars(sha,nullptr);
    std::string directory=d;void* target=dlopen((directory+"/libp5target.so").c_str(),RTLD_NOW);void* agent=dlopen((directory+"/libadh_agent.so").c_str(),RTLD_NOW);
    if(!target||!agent){env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),dlerror());return nullptr;}
    auto probe=reinterpret_cast<long(*)()>(dlsym(target,"p5_target_probe"));auto package=reinterpret_cast<void(*)(const char*)>(dlsym(agent,"adh_agent_set_package"));auto policy=reinterpret_cast<void(*)(const char*)>(dlsym(agent,"adh_agent_set_policy"));auto early=reinterpret_cast<int(*)(const void*,size_t,const char*,const char*)>(dlsym(agent,"adh_agent_apply_early_v1"));auto start=reinterpret_cast<void(*)()>(dlsym(agent,"adh_agent_start"));
    if(!probe||!package||!policy||!early||!start){env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),"missing fixture exports");return nullptr;}
    std::ifstream input(w,std::ios::binary);std::vector<char> bytes((std::istreambuf_iterator<char>(input)),std::istreambuf_iterator<char>());
    package("com.adh.p5sandbox");policy("d=0,h=0,s=0,a=0,t=0,e=0,y=0");int result=bytes.empty()?-1:early(bytes.data(),bytes.size(),"com.adh.p5sandbox",hash);
    // The only getpid import in the target is exercised before starting any Host channel.
    long value=probe();char receipt[256];snprintf(receipt,sizeof(receipt),"{\"pid\":%d,\"uid\":%d,\"wireBytes\":%zu,\"earlyApply\":%d,\"probeReturn\":%ld,\"probeBeforeAgentStart\":true}",getpid(),getuid(),bytes.size(),result,value);
    start();env->ReleaseStringUTFChars(dir,d);env->ReleaseStringUTFChars(wire,w);env->ReleaseStringUTFChars(sha,hash);return env->NewStringUTF(receipt);
}
