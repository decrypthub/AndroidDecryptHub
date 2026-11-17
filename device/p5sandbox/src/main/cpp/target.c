#include <unistd.h>
__attribute__((visibility("default"),noinline)) int p5_system_probe(const char *path){return access(path,F_OK);}
__attribute__((visibility("default"),noinline)) long p5_target_probe(void){return (long)getpid();}
