cmake_minimum_required(VERSION 3.22)
project(idh_agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)

add_library(idh_agent SHARED
    src/bootstrap/agent_main.c
    src/trace/qbdi_trace.c
)

# QBDI headers (loaded at runtime via dlopen — NOT linked, keeps agent independent).
# Present only if tools/fetch_qbdi.sh has run; guard so the build works without it.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/qbdi/include")
    target_include_directories(idh_agent PRIVATE third_party/qbdi/include)
else()
    message(WARNING "QBDI headers absent — run tools/fetch_qbdi.sh for instruction trace")
endif()

# Android system libs: log (android/log.h), plus libc/pthread (implicit).
find_library(log-lib log)
target_link_libraries(idh_agent ${log-lib} dl)

# Keep the .so small and stripped in release.
target_compile_options(idh_agent PRIVATE -Wall -Wextra -O2 -fvisibility=hidden)
