// The test generator places this around the shipping capture policy/start/stop functions.
// GOT slots, symbol resolution and sender I/O are deterministic mocks; no Android is claimed.
#ifdef ADH_FIXTURE_PRELUDE
#define ADH_HAVE_LSPLANT 1
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
static int java_pending_fixture, java_stop_calls;
static unsigned java_family_fixture;
static int adh_java_crypto_stop(void) { java_stop_calls++; return java_pending_fixture; }
static void adh_java_crypto_set_families(unsigned mask) { java_family_fixture = mask; }
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
#if ADH_HAS_SLOTS
static int adh_capture_got_replace(const char*,void*,void*);
static int adh_capture_got_replace_by_name(const char*,const char*,void*);
static int adh_capture_got_replace_by_name_ex(const char*,const char*,void*,void**,void**,char*,size_t);
static int adh_capture_got_restore(void*);
static void adh_capture_got_state(void*,struct AdhCaptureSlotState*);
static unsigned adh_capture_got_pending(void);
#endif
#else
static const char *symbols[] = {
 "EVP_CipherUpdate","EVP_DigestUpdate","HMAC_Update","EVP_DigestSignUpdate","SSL_write","SSL_read",
 "EVP_CipherInit_ex","EVP_CIPHER_CTX_free","ECDSA_sign","ECDSA_verify","EVP_PKEY_encrypt","EVP_PKEY_decrypt",
 "EVP_DigestSignInit","EVP_DigestVerifyInit","EVP_DigestSignFinal",
 "EVP_DigestVerifyUpdate","EVP_DigestVerifyFinal","open","openat","read","write","syscall","__read_chk",
 "__write_chk","ptrace","access","faccessat","__system_property_get","__system_property_read_callback"
};
static void *wrappers[] = {
 my_EVP_CipherUpdate,my_EVP_DigestUpdate,my_HMAC_Update,my_EVP_DigestSignUpdate,my_SSL_write,my_SSL_read,
 my_EVP_CipherInit_ex,my_EVP_CIPHER_CTX_free,my_ECDSA_sign,my_ECDSA_verify,my_EVP_PKEY_encrypt,my_EVP_PKEY_decrypt,
 my_EVP_DigestSignInit,my_EVP_DigestVerifyInit,my_EVP_DigestSignFinal,
 my_EVP_DigestVerifyUpdate,my_EVP_DigestVerifyFinal,my_open,my_openat,my_read,my_write,my_syscall,my_read_chk,
 my_write_chk,my_ptrace,my_access,my_faccessat,my_prop,my_prop_read
};
static char originals[ADH_CM_COUNT];
static void *slots[2][ADH_CM_COUNT];
static int index_of(const char *s) { for(int i=0;i<ADH_CM_COUNT;i++)if(!strcmp(s,symbols[i]))return i;return -1; }
static void *adh_resolve_sym(const char *m,const char*s) { int i=index_of(s);return i<0?NULL:&originals[i]; }
static int belongs(const char *m,int bank,int i) {
 if(!m||!m[0])return i<17;
 const char *expected = i<17?(bank?"cryptoB":"cryptoA"):i<24?(bank?"fileB":"fileA"):(bank?"sysB":"sysA");
 return !strcmp(m,expected);
}
static int adh_got_replace(const char*m,void*orig,void*wrapper) {
 int n=0;for(int b=0;b<2;b++)for(int i=0;i<ADH_CM_COUNT;i++)if(belongs(m,b,i)&&slots[b][i]==orig){slots[b][i]=wrapper;n++;}return n;
}
static int adh_got_replace_by_name_ex(const char*m,const char*s,void*w,void**slot,void**old,char*p,size_t cap) {
 int i=index_of(s),n=0;if(i<0)return 0;
 for(int b=0;b<2;b++)if(belongs(m,b,i)) {if(!n){if(old)*old=slots[b][i];if(slot)*slot=&slots[b][i];}slots[b][i]=w;n++;}return n;
}
static int adh_got_replace_by_name(const char*m,const char*s,void*w) {return adh_got_replace_by_name_ex(m,s,w,NULL,NULL,NULL,0);}
#if ADH_HAS_SLOTS
static struct AdhCaptureSlots ledger;
static void **unreadable_slot;
static int publish_failure;
static int slot_read(void **slot,void **value) {if(slot==unreadable_slot)return 0;*value=*slot;return 1;}
static int slot_swap(void **slot,void *expected,void *value) {
 if(*slot==value)return publish_failure?0:1;
 if(*slot!=expected)return -1;*slot=value;return publish_failure?0:1;
}
static int adh_capture_got_replace(const char*m,void*orig,void*w) {
 int n=0;for(int b=0;b<2;b++)for(int i=0;i<ADH_CM_COUNT;i++)if(belongs(m,b,i)&&slots[b][i]==orig)
 if(adh_capture_slot_publish(&ledger,&slots[b][i],orig,w,0,slot_read,slot_swap)==1)n++;return n;
}
static int adh_capture_got_replace_by_name_ex(const char*m,const char*s,void*w,void**slot,void**old,char*p,size_t cap) {
 int i=index_of(s),n=0;if(i<0)return 0;
 for(int b=0;b<2;b++)if(belongs(m,b,i)) {
   void*previous=slots[b][i];if(adh_capture_slot_publish(&ledger,&slots[b][i],previous,w,0,slot_read,slot_swap)!=1)continue;
   if(!n){if(old)*old=previous;if(slot)*slot=&slots[b][i];}n++;
 }return n;
}
static int adh_capture_got_replace_by_name(const char*m,const char*s,void*w) {return adh_capture_got_replace_by_name_ex(m,s,w,NULL,NULL,NULL,0);}
static int adh_capture_got_restore(void*w) {return adh_capture_slot_restore(&ledger,w,slot_read,slot_swap);}
static void adh_capture_got_state(void*w,struct AdhCaptureSlotState*out) {adh_capture_slot_state(&ledger,w,slot_read,out);}
static unsigned adh_capture_got_pending(void) {return adh_capture_slots_pending(&ledger);}
#endif
static int owned(int bank) {int n=0;for(int i=0;i<ADH_CM_COUNT;i++)if(slots[bank][i]==wrappers[i])n++;return n;}
static void fail(const char*msg){fprintf(stderr,"FAIL %s\n",msg);exit(1);}
#define CHECK(x) do{if(!(x))fail(#x);}while(0)
static void select_bits(uint32_t bits,const char *expected) {
#if ADH_HAS_METHODS
 char selection[ADH_CM_COUNT+1],req[256];for(int i=0;i<ADH_CM_COUNT;i++)selection[i]=(bits&(UINT32_C(1)<<i))?'1':'0';selection[ADH_CM_COUNT]=0;
 snprintf(req,sizeof(req),"{\"t\":\"cmd\",\"op\":\"capture_methods\",\"id\":\"fixture\",\"action\":\"set\",\"catalog\":\"native-capture/2\",\"revision\":\"%u\",\"selection\":\"%s\"}",g_method_revision,selection);
 adh_cmd_capture_methods(-1,"fixture",req);
 if(expected)CHECK(strstr(reply,expected));else CHECK(strstr(reply,"\"ok\":true"));
#else
 (void)bits;(void)expected;
#endif
}
int main(int argc,char**argv) {
 CHECK(argc==2);const char*name=argv[1];
 for(int b=0;b<2;b++)for(int i=0;i<ADH_CM_COUNT;i++)slots[b][i]=&originals[i];
 if(!strcmp(name,"java-stop")) {
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","");java_pending_fixture=2;
   adh_cmd_capture_stop(1,"f");CHECK(java_stop_calls==1);CHECK(strstr(reply,"\"ok\":false"));CHECK(strstr(reply,"\"javaPending\":2"));CHECK(g_capture_on);
   java_pending_fixture=0;adh_cmd_capture_stop(1,"f");CHECK(java_stop_calls==2);CHECK(strstr(reply,"\"ok\":true"));CHECK(!g_capture_on);
 } else if(!strcmp(name,"java-family-policy")) {
   adh_capture_set_families(0,1,0,0,0,0,0);CHECK(java_family_fixture==2);
 } else if(!strcmp(name,"exact-prior")||!strcmp(name,"multi-prior")) {
   static char priorA,priorB;slots[0][8]=&priorA;slots[1][8]=&priorB;
   select_bits(UINT32_C(1)<<8,NULL);
   adh_cmd_capture_start(-1,"f",!strcmp(name,"multi-prior")?"":"cryptoA","","");
   CHECK(slots[0][8]==wrappers[8]);adh_cmd_capture_stop(-1,"f");CHECK(slots[0][8]==&priorA);CHECK(slots[1][8]==&priorB);
 } else if(!strcmp(name,"unreadable-stop")||!strcmp(name,"capacity")||!strcmp(name,"publish-failure")||!strcmp(name,"live-ownership")) {
#if ADH_HAS_SLOTS
   if(!strcmp(name,"unreadable-stop")) {
     adh_capture_set_families(1,1,1,1,1,1,1);select_bits((UINT32_C(1)<<ADH_CM_OPENAT)|(UINT32_C(1)<<ADH_CM_ACCESS),NULL);
     adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==2);
     unreadable_slot=&slots[0][ADH_CM_OPENAT];adh_cmd_capture_stop(1,"f");CHECK(strstr(reply,"\"ok\":false"));CHECK(adh_capture_got_pending()==1);CHECK(g_capture_on);
     unreadable_slot=NULL;adh_cmd_capture_stop(1,"f");CHECK(strstr(reply,"\"ok\":true"));CHECK(adh_capture_got_pending()==0);CHECK(!g_capture_on);CHECK(slots[0][ADH_CM_OPENAT]==&originals[ADH_CM_OPENAT]);
   } else if(!strcmp(name,"capacity")) {
     struct AdhCaptureSlots local={0};void *values[ADH_CAPTURE_SLOT_MAX+1];static char p,w;
     for(int i=0;i<=ADH_CAPTURE_SLOT_MAX;i++)values[i]=&p;
     for(int i=0;i<ADH_CAPTURE_SLOT_MAX;i++)CHECK(adh_capture_slot_publish(&local,&values[i],&p,&w,0,slot_read,slot_swap)==1);
     CHECK(adh_capture_slot_publish(&local,&values[ADH_CAPTURE_SLOT_MAX],&p,&w,0,slot_read,slot_swap)==-2);CHECK(values[ADH_CAPTURE_SLOT_MAX]==&p);
     CHECK(adh_capture_slot_restore(&local,&w,slot_read,slot_swap)==ADH_CAPTURE_SLOT_MAX);CHECK(!adh_capture_slots_pending(&local));
   } else if(!strcmp(name,"publish-failure")) {
     static char p,w;void *value=&p;publish_failure=1;
     CHECK(adh_capture_slot_publish(&ledger,&value,&p,&w,0,slot_read,slot_swap)==0);CHECK(value==&w);CHECK(adh_capture_got_pending()==1);
     CHECK(adh_capture_got_restore(&w)<0);CHECK(value==&p);CHECK(adh_capture_got_pending()==1);
     publish_failure=0;CHECK(adh_capture_got_restore(&w)==1);CHECK(value==&p);CHECK(!adh_capture_got_pending());
   } else {
     select_bits(UINT32_C(1)<<8,NULL);adh_cmd_capture_start(-1,"f","cryptoA","","");struct AdhCaptureSlotState st;
     adh_capture_got_state(wrappers[8],&st);CHECK(st.owned==1);static char third;slots[0][8]=&third;
     adh_capture_got_state(wrappers[8],&st);CHECK(st.owned==0&&st.changed==1);
     adh_cmd_capture_stop(-1,"f");CHECK(slots[0][8]==&third);adh_capture_got_state(wrappers[8],&st);CHECK(st.restoreConflicts==1);
   }
#else
   fail("exact-prior capture ledger unsupported by baseline source");
#endif
 } else if(!strncmp(name,"method-",7)) {
   int i=atoi(name+7);CHECK(i>=0&&i<ADH_CM_COUNT);uint32_t expected=UINT32_C(1)<<i;
   if(i==0)expected|=(UINT32_C(1)<<6)|(UINT32_C(1)<<7);
   if(i==6)expected|=UINT32_C(1)<<7;
   if(i==3||i==ADH_CM_SIGN_FINAL)expected|=UINT32_C(1)<<ADH_CM_SIGN_INIT;
   if(i==ADH_CM_VERIFY_UPDATE||i==ADH_CM_VERIFY_FINAL)expected|=UINT32_C(1)<<ADH_CM_VERIFY_INIT;
   adh_capture_set_families(1,1,1,1,1,1,1);select_bits(UINT32_C(1)<<i,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");
   for(int j=0;j<ADH_CM_COUNT;j++)CHECK((slots[0][j]==wrappers[j])==!!(expected&(UINT32_C(1)<<j)));
   CHECK(owned(1)==0);
 } else if(!strcmp(name,"defaults")) {
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==ADH_CM_COUNT-5);CHECK(owned(1)==0);
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
   adh_capture_set_families(0,1,0,0,0,0,0);select_bits(UINT32_C(1)<<ADH_CM_SIGN_FINAL,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","","");CHECK(owned(0)==2);CHECK(slots[0][ADH_CM_SIGN_INIT]==wrappers[ADH_CM_SIGN_INIT]);CHECK(slots[0][ADH_CM_SIGN_FINAL]==wrappers[ADH_CM_SIGN_FINAL]);
 } else if(!strcmp(name,"family-off")) {
   adh_capture_set_families(0,0,0,0,0,0,0);select_bits(1,NULL);
   adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==0);
 } else if(!strcmp(name,"repeat-retarget")) {
   adh_capture_set_families(1,1,1,1,1,1,1);adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");CHECK(owned(0)==ADH_CM_COUNT);
   adh_cmd_capture_start(-1,"f","cryptoB","fileB","sysB");CHECK(owned(0)==0);CHECK(owned(1)==ADH_CM_COUNT);
 } else if(!strcmp(name,"stop-ownership")) {
   adh_capture_set_families(1,1,1,1,1,1,1);adh_cmd_capture_start(-1,"f","cryptoA","fileA","sysA");
   static char third;slots[0][8]=&third;slots[0][ADH_CM_ACCESS]=&third;
   adh_cmd_capture_stop(-1,"f");CHECK(slots[0][8]==&third);CHECK(slots[0][ADH_CM_ACCESS]==&third);CHECK(owned(0)==0);
 } else {
#if ADH_HAS_METHODS
   if(!strcmp(name,"revision")) {
     uint32_t rev=g_method_revision;select_bits(0,NULL);CHECK(g_method_revision==rev+1);select_bits(0,NULL);CHECK(g_method_revision==rev+1);
     uint32_t bits=123;CHECK(!strcmp(adh_capture_method_validate(ADH_CAPTURE_CATALOG,"1","0000000000000000000000000000000",g_method_revision,0,&bits),"REVISION_CONFLICT"));
     adh_capture_set_families(0,1,1,1,1,1,0);CHECK(g_method_revision==rev+2);
   } else if(!strcmp(name,"active-reject")) {
     adh_cmd_capture_start(-1,"f","cryptoA","fileA","");uint32_t before=g_method_revision;
     select_bits(0,"CAPTURE_ACTIVE");CHECK(g_method_revision==before);CHECK(g_method_selected==ADH_CM_ALL);CHECK(owned(0)==ADH_CM_COUNT-5);
   } else if(!strcmp(name,"catalog-status")) {
     select_bits(1,NULL);adh_cmd_capture_methods(-1,"f","{\"action\":\"status\"}");
     puts(reply);CHECK(strstr(reply,"native.EVP_CipherUpdate"));CHECK(strstr(reply,"\"dependency\":true"));
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
