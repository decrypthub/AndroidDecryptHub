#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// An explicit, bounded native verification host. It loads the agent into ITSELF;
// it does not attach to, patch, stop or replace any installed Android application.
int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "usage: native-host AGENT_SO STOP_FILE SECONDS\n"); return 2; }
    char *end = NULL; long seconds = strtol(argv[3], &end, 10);
    if (!end || *end || seconds < 1 || seconds > 600) return 2;
    const char *stop = argv[2];
    if (strncmp(stop, "/data/local/tmp/adh-native-", 27) || strstr(stop, "..")) return 2;
    int source = open(argv[1], O_RDONLY), image = (int)syscall(__NR_memfd_create, "adh-native-fixture", 0);
    if (source < 0 || image < 0) { perror("open/memfd"); return 1; }
    char buffer[16384]; ssize_t got;
    while ((got = read(source, buffer, sizeof(buffer))) > 0) {
        for (ssize_t sent=0; sent<got;) { ssize_t n=write(image,buffer+sent,(size_t)(got-sent)); if(n<=0) {perror("write");return 1;} sent+=n; }
    }
    close(source); if (got < 0) { perror("read"); return 1; }
    char path[64]; snprintf(path,sizeof(path),"/proc/self/fd/%d",image);
    void *agent=dlopen(path,RTLD_NOW|RTLD_GLOBAL);
    if (!agent) { fprintf(stderr,"dlopen: %s\n",dlerror()); return 1; }
    void (*start)(void)=(void(*)(void))dlsym(agent,"adh_agent_start");
    void (*package)(const char*)=(void(*)(const char*))dlsym(agent,"adh_agent_set_package");
    if(!start||!package) {fprintf(stderr,"missing agent entry\n");return 1;}
    const char name[]="com.adh.nativefixture";
    size_t space=strlen(argv[0]); if(space<sizeof(name))return 2;
    memset(argv[0],0,space);memcpy(argv[0],name,sizeof(name));
    (void)prctl(PR_SET_NAME,"adh-native-test",0,0,0);
    package(name); start();
    printf("ADH_NATIVE_HOST pid=%d uid=%d lifetime=%ld memfd=true\n",getpid(),getuid(),seconds);fflush(stdout);
    for(long i=0;i<seconds;i++) {if(access(stop,F_OK)==0)break;sleep(1);}
    // No dlclose: worker threads own the agent until this bounded host exits.
    return 0;
}
