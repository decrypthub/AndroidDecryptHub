#include "early_wire.h"
#include "../hook/native_hooks.h"
#include "../capture/capture.h"
#include <sys/syscall.h>
#include <ctime>
#include <cstdio>
#include <cstdlib>
extern "C" void adh_agent_set_policy(const char*);
extern "C" int adh_agent_copy_owner(void);
extern "C" void json_escape(const char*,char*,size_t);
static char status[2048]="null";
static char last_error[256]="";
static bool attempted=false;
static int apply(const AdhEarlyStep& step,int* hookId,void*){
    if(step.type==2){char error[512]{};int ok=adh_native_hook_install("got",step.a,step.b,"",0,0,0,-1,0,0,"",0,0,0,step.c,-1,0,"",0,"","",0,"","",0,1,0,"",hookId,error,sizeof(error));if(!ok)snprintf(last_error,sizeof(last_error),"%.240s",error);return ok&&*hookId>0?1:0;}
    int fd=int(syscall(SYS_memfd_create,"adh-early-result",1));if(fd<0)return -1;
    adh_cmd_capture_start(fd,"early-cache",step.a,step.b,step.c);
    auto size=lseek(fd,0,SEEK_END);if(size<5||size>8192||lseek(fd,0,SEEK_SET)<0){close(fd);return -1;}char data[8193]{};auto n=read(fd,data,size_t(size));close(fd);if(n!=size)return -1;
    const auto* h=reinterpret_cast<const unsigned char*>(data);size_t len=(size_t(h[0])<<24)|(size_t(h[1])<<16)|(size_t(h[2])<<8)|h[3];if(len+5!=size_t(size)||h[4]!=1)return -1;
    // This response contains install counters only, except sysModules. Count positive counters,
    // never the agent's unconditional ok:true or the number of requested system modules.
    int installed=0;const char* p=data+5;while((p=strstr(p,"\":"))){const char* end=p;const char* begin=end;while(begin>data+5&&begin[-1]!='"')begin--;bool modules=size_t(end-begin)==10&&!memcmp(begin,"sysModules",10);p+=2;while(*p==' ')p++;if(*p>='0'&&*p<='9'){char* next=nullptr;long v=strtol(p,&next,10);if(!modules&&v>0&&v<100000)installed+=int(v);p=next;}}
    return installed;
}
extern "C" const char* adh_early_status_json(){return status;}
extern "C" __attribute__((visibility("default"))) int adh_agent_apply_early_v1(const void* wire,size_t size,const char* package,const char* actualAgentSha){
    if(!adh_agent_copy_owner()||attempted)return 0;attempted=true;AdhEarlyPlan plan;
    if(!adh_early_parse(wire,size,package,uint32_t(getuid()),actualAgentSha,uint64_t(time(nullptr)),plan)){snprintf(status,sizeof(status),"{\"state\":\"rejected\",\"phase\":\"post-specialize-before-agent-start\"}");return 0;}
    char flags[64];snprintf(flags,sizeof(flags),"d=%d,h=%d,s=%d,a=%d,t=%d,e=%d,y=%d",!!(plan.families&1),!!(plan.families&2),!!(plan.families&4),!!(plan.families&8),!!(plan.families&16),!!(plan.families&32),!!(plan.families&64));adh_agent_set_policy(flags);
    auto result=adh_early_run(plan,apply,nullptr);std::string steps;for(unsigned n=0;n<plan.count;n++){char row[128];snprintf(row,sizeof(row),"%s{\"step\":%u,\"installed\":%d,\"hookId\":%d}",n?",":"",n,result.counts[n],result.hookIds[n]);steps+=row;}
    char error_json[512];json_escape(last_error,error_json,sizeof(error_json));snprintf(status,sizeof(status),"{\"state\":\"%s\",\"deploymentId\":\"%s\",\"digest\":\"%s\",\"phase\":\"post-specialize-before-agent-start\",\"attempted\":%d,\"confirmed\":%d,\"steps\":[%s],\"error\":\"%s\",\"evidence\":\"agent-reported\"}",result.applied?"applied":"partial-or-failed",plan.deployment,plan.digest,result.attempted,result.confirmed,steps.c_str(),error_json);
    return result.applied?1:0;
}
