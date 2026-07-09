cmake_minimum_required(VERSION 3.22)
project(idh_agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_VISIBILITY_PRESET hidden)

add_library(idh_agent SHARED
    src/bootstrap/agent_main.c
)

# Android system libs: log (android/log.h), plus libc/pthread (implicit).
find_library(log-lib log)
target_link_libraries(idh_agent ${log-lib})

# Keep the .so small and stripped in release.
target_compile_options(idh_agent PRIVATE -Wall -Wextra -O2 -fvisibility=hidden)
