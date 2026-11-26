#include "native_inline.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <thread>
#include <vector>
static std::atomic<bool> near_mode{true};
static std::atomic<int> calls{0};
static thread_local bool expected_near=true;
static thread_local bool throw_hook=false;
static thread_local int window=0;
void dobby_enable_near_branch_trampoline(){near_mode=true;}
void dobby_disable_near_branch_trampoline(){near_mode=false;}
extern "C" void adh_stealth_pool_window(int active){window=active;}
int DobbyHook(void*,void*,void** original){
 assert(window==1);assert(near_mode.load()==expected_near);
 if(throw_hook)throw std::runtime_error("fixture allocation failure");
 std::this_thread::sleep_for(std::chrono::microseconds(20));
 assert(near_mode.load()==expected_near);*original=reinterpret_cast<void*>(0x1234);calls++;return 0;
}
int DobbyDestroy(void*){assert(window==1);return 0;}
int main(){
 void *original=nullptr;
 assert(!adh_inline_hook_art(nullptr,reinterpret_cast<void*>(2),&original));
 expected_near=false;throw_hook=true;try{adh_inline_hook_art(reinterpret_cast<void*>(1),reinterpret_cast<void*>(2),&original);assert(false);}catch(const std::runtime_error&){}
 assert(window==0&&near_mode);throw_hook=false;
 std::vector<std::thread> workers;
 for(int t=0;t<20;t++)workers.emplace_back([t]{expected_near=t%2;for(int n=0;n<40;n++){void* p=nullptr;int ok=expected_near?adh_inline_hook(reinterpret_cast<void*>(1),reinterpret_cast<void*>(2),&p):adh_inline_hook_art(reinterpret_cast<void*>(1),reinterpret_cast<void*>(2),&p);assert(ok==1&&p==reinterpret_cast<void*>(0x1234));assert(window==0);}});
 for(auto &w:workers)w.join();assert(calls==800&&near_mode);assert(adh_inline_unhook(reinterpret_cast<void*>(1)));assert(window==0);
 std::puts("PASS full/near option isolation, throw cleanup and 800 concurrent calls");
}
