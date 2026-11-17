#include "../../../agent/src/bootstrap/early_wire.h"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <fcntl.h>
int apply(const AdhEarlyStep&,int* id,void* pointer){int* remaining=static_cast<int*>(pointer);*id=7;return (*remaining)-- >0?1:0;}
int main(int argc,char** argv){
    if(argc==3&&std::string(argv[1])=="sha"){int fd=open(argv[2],O_RDONLY|O_BINARY);if(fd<0)return 2;auto hash=adh_sha_fd(fd);close(fd);std::puts(hash.c_str());return 0;}
    if(argc!=8)return 2;int fd=open(argv[1],O_RDONLY|O_BINARY);if(fd<0)return 2;std::vector<uint8_t> data;uint8_t chunk[4096];int n;while((n=read(fd,chunk,sizeof(chunk)))>0)data.insert(data.end(),chunk,chunk+n);close(fd);
    AdhEarlyPlan plan{};bool valid=adh_early_parse(data.data(),data.size(),argv[2],std::strtoul(argv[3],nullptr,10),argv[4],std::strtoull(argv[5],nullptr,10),plan);
    if(!valid){std::puts("rejected");return 0;}int remaining=std::atoi(argv[6]);auto receipt=adh_early_run(plan,apply,&remaining);std::printf("%s %d %d %s\n",receipt.applied?"applied":"partial-or-failed",receipt.attempted,receipt.confirmed,plan.digest);return 0;
}
