cmake_minimum_required(VERSION 3.22)
project(idh_agent C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)          # LSPlant v6.4 needs C++20
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

# LSPlant (ART Java-method hook, WS-A) — present only if tools/fetch_lsplant.sh has run.
# Guarded so the agent still builds without it (like QBDI). When present we compile the
# C++ shim + LSPlant + DexBuilder and define ADH_HAVE_LSPLANT for agent_main.c.
set(LSP "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lsplant/lsplant/src/main/jni")
set(DXB "${LSP}/external/dex_builder")
set(DOB "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dobby")
set(LSPLANT_LIBS "")
set(LSPLANT_INC "")
set(DOBBY_AVAILABLE FALSE)
if(EXISTS "${DOB}/lib/arm64-v8a/libdobby.a" AND EXISTS "${DOB}/include/dobby.h")
    message(STATUS "Dobby present — enabling native inline-hook backend")
    list(APPEND AGENT_SOURCES src/hook/native_inline_dobby.cpp)
    list(APPEND LSPLANT_INC ${DOB}/include)
    list(APPEND LSPLANT_LIBS "${DOB}/lib/arm64-v8a/libdobby.a")
    set(DOBBY_AVAILABLE TRUE)
    add_compile_definitions(ADH_HAVE_INLINE_HOOK=1)
endif()

if(EXISTS "${LSP}/lsplant.cc" AND DOBBY_AVAILABLE)
    message(STATUS "LSPlant present — enabling Java-method hook backend (Dobby prebuilt static)")
    add_subdirectory("${DXB}/external/parallel_hashmap" phmap_build EXCLUDE_FROM_ALL)
    list(APPEND AGENT_SOURCES
        src/hook/java_lsplant.cpp
        ${LSP}/lsplant.cc
        ${DXB}/dex_builder.cc
        ${DXB}/dex_helper.cc
        ${DXB}/slicer/reader.cc  ${DXB}/slicer/writer.cc
        ${DXB}/slicer/dex_ir.cc  ${DXB}/slicer/common.cc
        ${DXB}/slicer/dex_format.cc ${DXB}/slicer/dex_utf8.cc
        ${DXB}/slicer/dex_bytecode.cc ${DXB}/slicer/sha1.cpp
    )
    list(APPEND LSPLANT_INC ${LSP} ${LSP}/include ${DXB}/include ${DXB})
    list(APPEND LSPLANT_LIBS z phmap)
    add_compile_definitions(ADH_HAVE_LSPLANT=1)
    # LSPlant/DexBuilder upstream warnings are not ours — don't fail on them.
    set_source_files_properties(
        ${LSP}/lsplant.cc ${DXB}/dex_builder.cc ${DXB}/dex_helper.cc
        ${DXB}/slicer/reader.cc ${DXB}/slicer/writer.cc ${DXB}/slicer/dex_ir.cc
        ${DXB}/slicer/common.cc ${DXB}/slicer/dex_format.cc ${DXB}/slicer/dex_utf8.cc
        ${DXB}/slicer/dex_bytecode.cc ${DXB}/slicer/sha1.cpp
        PROPERTIES COMPILE_FLAGS "-Wno-everything")
else()
    if(NOT DOBBY_AVAILABLE)
        message(WARNING "Dobby absent — run tools/fetch_lsplant.sh for native inline hooking")
    else()
        message(WARNING "LSPlant absent — run tools/fetch_lsplant.sh for Java-method hooking")
    endif()
endif()

add_library(idh_agent SHARED ${AGENT_SOURCES})

# Release footprint: keep only the three bootstrap entry points in .dynsym.
# Dobby/LSPlant/libc++ internals stay local to this DSO; Zygisk resolves only
# adh_agent_start/idh_agent_start and System.loadLibrary resolves JNI_OnLoad.
set(AGENT_EXPORT_MAP "${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
if(NOT EXISTS "${AGENT_EXPORT_MAP}")
  message(FATAL_ERROR "missing agent export map: ${AGENT_EXPORT_MAP}")
endif()
target_link_options(idh_agent PRIVATE "-Wl,--version-script=${AGENT_EXPORT_MAP}")

target_include_directories(idh_agent PRIVATE ${QBDI_INC} ${LSPLANT_INC})

# Android system libs: log (android/log.h), plus libc/pthread (implicit).
find_library(log-lib log)
target_link_libraries(idh_agent ${log-lib} dl ${LSPLANT_LIBS})

# Keep our own code small + hidden; -Wall/-Wextra apply to C agent sources only
# (LSPlant/DexBuilder sources get -Wno-everything above).
target_compile_options(idh_agent PRIVATE -O2 -fvisibility=hidden)
target_compile_options(idh_agent PRIVATE $<$<COMPILE_LANGUAGE:C>:-Wall -Wextra>)
