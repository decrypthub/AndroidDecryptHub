cmake_minimum_required(VERSION 3.22)
project(adh_agent C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(AGENT_SOURCES
    src/capture/capture.c
    src/bootstrap/agent_main.c
    src/bootstrap/util.c
    src/bootstrap/io.c
    src/bootstrap/mem.c
    src/bootstrap/mem_read.c
    src/bootstrap/fs.c
    src/hook/got.c
    src/hook/site_hooks.c
    src/hook/slot_hooks.c
    src/hook/stealth_pool.c
    src/hook/native_hooks.cpp
    src/runtime/actions.c
    src/runtime/fp_call.S
    src/runtime/art.c
    src/runtime/inspection.c
    src/runtime/jni.c
    src/runtime/jni_hooks.c
    src/runtime/jni_env_hooks.c
    src/runtime/jni_method_names.c
    src/runtime/jni_onload.c
    src/runtime/dlopen_watch.c
    src/runtime/java_enum.cpp
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
# without it the agent still builds (native_hook mode=inline then reports that the backend is not built in).
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

# LSPlant (ART Java-method hook) is optional and statically linked when its pinned sources
# are present. It reuses the same Dobby static backend as native inline hooks. No HTTP/DB/
# analysis code enters the agent; the shim only exposes init/hook/unhook/probe primitives.
set(LSPLANT_VERSION "v6.4")
set(LSP "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lsplant/lsplant/src/main/jni")
set(DXB "${LSP}/external/dex_builder")
set(LSPLANT_INC "")
set(LSPLANT_LIBS "")
if(EXISTS "${LSP}/lsplant.cc"
   AND EXISTS "${DXB}/dex_builder.cc"
   AND EXISTS "${DXB}/external/parallel_hashmap/CMakeLists.txt"
   AND EXISTS "${DOB}/lib/arm64-v8a/libdobby.a"
   AND EXISTS "${DOB}/include/dobby.h")
    message(STATUS "LSPlant present — enabling ART Java-method hook backend")
    add_subdirectory("${DXB}/external/parallel_hashmap" phmap_build EXCLUDE_FROM_ALL)
    list(APPEND AGENT_SOURCES
        src/hook/java_lsplant.cpp
        "${LSP}/lsplant.cc"
        "${DXB}/dex_builder.cc"
        "${DXB}/dex_helper.cc"
        "${DXB}/slicer/reader.cc"
        "${DXB}/slicer/writer.cc"
        "${DXB}/slicer/dex_ir.cc"
        "${DXB}/slicer/common.cc"
        "${DXB}/slicer/dex_format.cc"
        "${DXB}/slicer/dex_utf8.cc"
        "${DXB}/slicer/dex_bytecode.cc"
        "${DXB}/slicer/sha1.cpp"
    )
    set(LSPLANT_INC "${LSP}" "${LSP}/include" "${DXB}/include" "${DXB}")
    set(LSPLANT_LIBS z phmap)
    add_compile_definitions(ADH_HAVE_LSPLANT=1 ADH_LSPLANT_VERSION="${LSPLANT_VERSION}")
    set_source_files_properties(
        "${LSP}/lsplant.cc"
        "${DXB}/dex_builder.cc"
        "${DXB}/dex_helper.cc"
        "${DXB}/slicer/reader.cc"
        "${DXB}/slicer/writer.cc"
        "${DXB}/slicer/dex_ir.cc"
        "${DXB}/slicer/common.cc"
        "${DXB}/slicer/dex_format.cc"
        "${DXB}/slicer/dex_utf8.cc"
        "${DXB}/slicer/dex_bytecode.cc"
        "${DXB}/slicer/sha1.cpp"
        PROPERTIES COMPILE_FLAGS "-Wno-everything"
    )
else()
    message(WARNING "LSPlant absent — run tools/fetch_lsplant.sh for Java-method hooking")
endif()

add_library(adh_agent SHARED ${AGENT_SOURCES})

# Release footprint: keep only the three bootstrap entry points in .dynsym.
# Dobby/libc++/LSPlant internals stay local to this DSO; Zygisk resolves only
# adh_agent_start and System.loadLibrary resolves JNI_OnLoad.
set(AGENT_EXPORT_MAP "${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
if(NOT EXISTS "${AGENT_EXPORT_MAP}")
  message(FATAL_ERROR "missing agent export map: ${AGENT_EXPORT_MAP}")
endif()
target_link_options(adh_agent PRIVATE "-Wl,--version-script=${AGENT_EXPORT_MAP}")

# No SONAME at all: the shipped .dynstr is readable by the target (it can walk its own mappings), so
# the library name must not sit in there. Nothing needs it - the Zygisk/Xposed loaders dlopen a PATH
# (memfd or absolute path), and System.loadLibrary resolves the FILE name (libadh_agent.so, which
# stays for build/tooling compatibility). A plain -soname link option loses to CMake's own, hence
# the property.
set_target_properties(adh_agent PROPERTIES NO_SONAME TRUE)

target_include_directories(adh_agent PRIVATE ${QBDI_INC} ${HOOK_INC} ${LSPLANT_INC})

# Android system libs: log (android/log.h), plus libc/pthread (implicit).
find_library(log-lib log)
target_link_libraries(adh_agent ${log-lib} dl ${HOOK_LIBS} ${LSPLANT_LIBS})

# Keep our own code small + hidden; -Wall/-Wextra apply to C agent sources only
# (third-party hook sources get -Wno-everything above).
target_compile_options(adh_agent PRIVATE -O2 -fvisibility=hidden)
target_compile_options(adh_agent PRIVATE $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>)