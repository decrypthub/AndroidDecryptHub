// The test generator places this around the shipping capture policy/start/stop functions.
// GOT slots, symbol resolution and sender I/O are deterministic mocks; no Android is claimed.
#ifdef ADH_FIXTURE_PRELUDE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define LOGI(...) ((void)0)
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SO_TYPE 1
typedef int socklen_t;
static int getsockopt(int a,int b,int c,int*d,socklen_t*e) { return -1; }
static void adh_capture_sender_start(int fd) {}
static void adh_capture_sender_stop(int fd) {}
static int g_key_lock, g_key_next;
static char g_keys[4];
static int pthread_mutex_trylock(int *lock) { return 1; }
static int pthread_mutex_unlock(int *lock) { return 0; }
static void cap_reset(void) {}
static char reply[32768];
static int send_line(int fd,const char *s) { snprintf(reply,sizeof(reply),"%s",s); return 0; }
static void json_escape(const char *s,char*out,size_t cap) { snprintf(out,cap,"%s",s); }
static void *adh_resolve_sym(const char*,const char*);
static int adh_got_replace(const char*,void*,void*);
static int adh_got_replace_by_name(const char*,const char*,void*);
static int adh_got_replace_by_name_ex(const char*,const char*,void*,void**,void**,char*,size_t);
#else
static const char *symbols[] = {
 "EVP_CipherUpdate","EVP_DigestUpdate","HMAC_Update","EVP_DigestSignUpdate","SSL_write","SSL_read",
 "EVP_CipherInit_ex","EVP_CIPHER_CTX_free","ECDSA_sign","ECDSA_verify","EVP_PKEY_encrypt","EVP_PKEY_decrypt",
 "EVP_AEAD_CTX_seal","EVP_AEAD_CTX_open","EVP_DigestSignInit","EVP_DigestVerifyInit","EVP_DigestSignFinal",
 "EVP_DigestVerifyUpdate","EVP_DigestVerifyFinal","open","openat","read","write","syscall","__read_chk",
 "__write_chk","ptrace","access","faccessat","__system_property_get","__system_property_read_callback"
};
static void *wrappers[] = {
 my_EVP_CipherUpdate,my_EVP_DigestUpdate,my_HMAC_Update,my_EVP_DigestSignUpdate,my_SSL_write,my_SSL_read,
 my_EVP_CipherInit_ex,my_EVP_CIPHER_CTX_free,my_ECDSA_sign,my_ECDSA_verify,my_EVP_PKEY_encrypt,my_EVP_PKEY_decrypt,
 my_EVP_AEAD_CTX_seal,my_EVP_AEAD_CTX_open,my_EVP_DigestSignInit,my_EVP_DigestVerifyInit,my_EVP_DigestSignFinal,
 my_EVP_DigestVerifyUpdate,my_EVP_DigestVerifyFinal,my_open,my_openat,my_read,my_write,my_syscall,my_read_chk,
 my_write_chk,my_ptrace,my_access,my_faccessat,my_prop,my_prop_read
};
static char originals[31];
static void *slots[2][31];
static int index_of(const char *s) { for(int i=0;i<31;i++)if(!strcmp(s,symbols[i]))return i;return -1; }
static void *adh_resolve_sym(const char *m,const char*s) { int i=index_of(s);return i<0?NULL:&originals[i]; }
static int belongs(const char *m,int bank,int i) {
 if(!m||!m[0])return i<19;
 const char *expected = i<19?(bank?"cryptoB":"cryptoA"):i<26?(bank?"fileB":"fileA"):(bank?"sysB":"sysA");
 return !strcmp(m,expected);
}
static int adh_got_replace(const char*m,void*orig,void*wrapper) {
 int n=0;for(int b=0;b<2;b++)for(int i=0;i<31;i++)if(belongs(m,b,i)&&slots[b][i]==orig){slots[b][i]=wrapper;n++;}return n;
}
static int adh_got_replace_by_name_ex(const char*m,const char*s,void*w,void**slot,void**old,char*p,size_t cap) {
 int i=index_of(s),n=0;if(i<0)return 0;
 for(int b=0;b<2;b++)if(belongs(m,b,i)) {if(!n){if(old)*old=slots[b][i];if(slot)*slot=&slots[b][i];}slots[b][i]=w;n++;}return n;
}
static int adh_got_replace_by_name(const char*m,const char*s,void*w) {return adh_got_replace_by_name_ex(m,s,w,NULL,NULL,NULL,0);}
static int owned(int bank) {int n=0;for(int i=0;i<31;i++)if(slots[bank][i]==wrappers[i])n++;return n;}
static void fail(const char*msg){fprintf(stderr,"FAIL %s\n",msg);exit(1);}
#define CHECK(x) do{if(!(x))fail(#x);}while(0)
static void select_bits(uint32_t bits,const char *expected) {
#if ADH_HAS_METHODS
 char selection[32],req[256];for(int i=0;i<31;i++)selection[i]=(bits&(UINT32_C(1)<<i))?'1':'0';selection[31]=0;
 snprintf(req,sizeof(req),"{\"t\":\"cmd\",\"op\":\"capture_methods\",\"id\":\"fixture\",\"action\":\"set\",\"catalog\":\"native-capture/1\",\"revision\":\"%u\",\"selection\":\"%s\"}",g_method_revision,selection);
 adh_cmd_capture_methods(-1,"fixture",req);
 if(expected)CHECK(strstr(reply,expected));else CHECK(strstr(reply,"\"ok\":true"));
#else
 (void)bits;(void)expected;
#endif
}
int main(int argc,char**argv) {
 CHECK(argc==2);const char*name=argv[1];
 for(int b=0;b<2;b++)for(int i=0;i<31;i++)slots[b][i]=&originals[i];
 if(!strncmp(name,"method-",7)) {
   int i=atoi(name+7);CHECK(i>=0&&i<31);uint32_t expected=UINT32_C(1)<<i;
   if(i==0)expected|=(UINT32_C(1)<<6)|(UINT32_C(1)<<7);
   if(i==6)expected|=UINT32_C(1)<<7;
   if(i==3||i==16)expected|=UINT32_C(1)<<14;
   if(i==17||i==18)expected|=UINT32_C(1)<<15;
   adh_capture_set_families(1,1,1,1,1,1,1);select_bits(UINT32_C(1)<<i,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");
   for(int j=0;j<31;j++)CHECK((slots[0][j]==wrappers[j])==!!(expected&(UINT32_C(1)<<j)));
   CHECK(owned(1)==0);
 } else if(!strcmp(name,"defaults")) {
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==26);CHECK(owned(1)==0);
 } else if(!strcmp(name,"none")) {
   adh_capture_set_families(1,1,1,1,1,1,1);select_bits(0,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==0);
 } else if(!strcmp(name,"single-tls")) {
   adh_capture_set_families(1,1,1,1,1,1,1);select_bits(UINT32_C(1)<<5,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==1);CHECK(slots[0][5]==wrappers[5]);CHECK(slots[0][4]==&originals[4]);
 } else if(!strcmp(name,"cipher-dependencies")) {
   select_bits(1,NULL);adh_cmd_capture_start(-1,"f","cryptoA","fileA","");CHECK(owned(0)==3);
   CHECK(slots[0][0]==wrappers[0]);CHECK(slots[0][6]==wrappers[6]);CHECK(slots[0][7]==wrappers[7]);
 } else if(!strcmp(name,"shared-hmac")) {
   adh_capture_set_families(0,1,0,0,0,0,0);select_bits(UINT32_C(1)<<16,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","","");CHECK(owned(0)==2);CHECK(slots[0][14]==wrappers[14]);CHECK(slots[0][16]==wrappers[16]);
 } else if(!strcmp(name,"family-off")) {
   adh_capture_set_families(0,0,0,0,0,0,0);select_bits(1,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==0);
 } else if(!strcmp(name,"repeat-retarget")) {
   adh_capture_set_families(1,1,1,1,1,1,1);adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==31);
   adh_cmd_capture_start(-1,"f","cryptoB","fileB","sysB");CHECK(owned(0)==0);CHECK(owned(1)==31);
 } else if(!strcmp(name,"stop-ownership")) {
   adh_capture_set_families(1,1,1,1,1,1,1);adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");
   static char third;slots[0][8]=&third;slots[0][27]=&third;
   adh_cmd_capture_stop(-1,"f");CHECK(slots[0][8]==&third);CHECK(slots[0][27]==&third);CHECK(owned(0)==0);
 } else {
#if ADH_HAS_METHODS
   if(!strcmp(name,"revision")) {
     uint32_t rev=g_method_revision;select_bits(0,NULL);CHECK(g_method_revision==rev+1);select_bits(0,NULL);CHECK(g_method_revision==rev+1);
     uint32_t bits=123;CHECK(!strcmp(adh_capture_method_validate(ADH_CAPTURE_CATALOG,"1","0000000000000000000000000000000",g_method_revision,0,&bits),"REVISION_CONFLICT"));
     adh_capture_set_families(0,1,1,1,1,1,0);CHECK(g_method_revision==rev+2);
   } else if(!strcmp(name,"active-reject")) {
     adh_cmd_capture_start(-1,"f","cryptoA","fileA","");uint32_t before=g_method_revision;
     select_bits(0,"CAPTURE_ACTIVE");CHECK(g_method_revision==before);CHECK(g_method_selected==ADH_CM_ALL);CHECK(owned(0)==26);
   } else if(!strcmp(name,"catalog-status")) {
     select_bits(1,NULL);adh_cmd_capture_methods(-1,"f","{\"action\":\"status\"}");
     puts(reply);CHECK(strstr(reply,"native.EVP_CipherUpdate"));CHECK(strstr(reply,"\"dependency\":true"));CHECK(strstr(reply,"\"installationEvidence\":\"last-attempt\""));
   } else if(!strcmp(name,"malformed")) {
     char out[40];uint32_t bits=0,rev=0;
     CHECK(!adh_capture_revision("4294967296",&rev));CHECK(!adh_capture_revision("01",&rev));CHECK(!adh_capture_revision("1x",&rev));
     CHECK(!adh_capture_method_bits("11111111111111111111111111111111",&bits));
     const char*bad[]={"{\"action\":\"status\",\"action\":\"set\"}","{\"action\":\"status\"", "{\"nest\":{\"action\":\"status\"}}", "{\"action\":\"status\",}","{\"action\":\"status\\n\"}","{\"action\":\"status\"} trailing"};
     for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)CHECK(!adh_capture_string_field(bad[i],"action",out,sizeof(out)));
     CHECK(adh_capture_string_field(" { \"action\" : \"status\" } \n","action",out,sizeof(out)));CHECK(!strcmp(out,"status"));
     CHECK(!strcmp(adh_capture_method_validate("wrong","1","0000000000000000000000000000000",1,0,&bits),"CATALOG_MISMATCH"));
   } else fail("unknown case");
#else
   fail("capture_methods unsupported by baseline source");
#endif
 }
 printf("PASS %s\n",name);return 0;
}
#endif
