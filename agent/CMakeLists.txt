cmake_minimum_required(VERSION 3.22)
project(adh_agent C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)          # C++ hook shims (Dobby)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(AGENT_SOURCES
    src/capture/capture.c
    src/bootstrap/agent_main.c
    src/bootstrap/util.c
    src/bootstrap/io.c
    src/bootstrap/mem.c
    src/bootstrap/fs.c
    src/hook/got.c
    src/runtime/actions.c
    src/runtime/art.c
    src/runtime/inspection.c
    src/runtime/jni.c
    src/trace/commands.c
    src/trace/qbdi_trace.c
)

# QBDI headers (loaded at runtime via dlopen — NOT linked, keeps agent independent).
# Present only if tools/fetch_qbdi.sh has run; guard so the build works without it.
set(QBDI_INC "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/qbdi/include")
    set(QBDI_INC third_party/qbdi/include)
else()
    message(WARNING "QBDI headers absent — run tools/fetch_qbdi.sh for instruction trace")
endif()

# Native inline-hook backend (Dobby, arm64). Present only after tools/fetch_dobby.sh has run;
# without it the agent still builds and adh_inline_crypto_test reports "inline backend not built".
set(DOB "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dobby")
set(HOOK_LIBS "")
set(HOOK_INC "")
if(EXISTS "${DOB}/lib/arm64-v8a/libdobby.a" AND EXISTS "${DOB}/include/dobby.h")
    message(STATUS "Dobby present — enabling native inline-hook backend")
    list(APPEND AGENT_SOURCES src/hook/native_inline_dobby.cpp)
    list(APPEND HOOK_INC ${DOB}/include)
    list(APPEND HOOK_LIBS "${DOB}/lib/arm64-v8a/libdobby.a")
    add_compile_definitions(ADH_HAVE_INLINE_HOOK=1)
else()
    message(WARNING "Dobby absent — run tools/fetch_dobby.sh for native inline hooking")
endif()

add_library(adh_agent SHARED ${AGENT_SOURCES})

# Release footprint: keep only the three bootstrap entry points in .dynsym.
# Dobby/libc++ internals stay local to this DSO; Zygisk resolves only
# adh_agent_start and System.loadLibrary resolves JNI_OnLoad.
set(AGENT_EXPORT_MAP "${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
if(NOT EXISTS "${AGENT_EXPORT_MAP}")
  message(FATAL_ERROR "missing agent export map: ${AGENT_EXPORT_MAP}")
endif()
target_link_options(adh_agent PRIVATE "-Wl,--version-script=${AGENT_EXPORT_MAP}")

target_include_directories(adh_agent PRIVATE ${QBDI_INC} ${HOOK_INC})

# Android system libs: log (android/log.h), plus libc/pthread (implicit).
find_library(log-lib log)
target_link_libraries(adh_agent ${log-lib} dl ${HOOK_LIBS})

# Keep our own code small + hidden; -Wall/-Wextra apply to C agent sources only
# (Third-party hook sources get -Wno-everything above.)
target_compile_options(adh_agent PRIVATE -O2 -fvisibility=hidden)
target_compile_options(adh_agent PRIVATE $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>)
