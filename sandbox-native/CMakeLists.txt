cmake_minimum_required(VERSION 3.22)
project(adhdetect C)
set(CMAKE_C_STANDARD 11)
# -fno-omit-frame-pointer: the hook-hit backtrace walks the real x29 chain, and clang omits the frame
# pointer at -O2 for arm64 by default. AOSP builds its own native code the same way for the same
# reason (debuggability); the fixture must not be the one thing in the process without frames.
add_compile_options(-fno-omit-frame-pointer)
add_library(adhdetect SHARED detect.c)
# Runtime-loaded plugin fixtures for the load-time JNI_OnLoad watch (v4.30). Same source, two
# libraries, distinct counter symbols so a verifier can tell whether the real JNI_OnLoad ran.
add_library(adhplugin_a SHARED plugin.c)
target_compile_definitions(adhplugin_a PRIVATE ADH_PLUGIN_SYMBOL=adh_plugin_a_count)
add_library(adhplugin_b SHARED plugin.c)
target_compile_definitions(adhplugin_b PRIVATE ADH_PLUGIN_SYMBOL=adh_plugin_b_count)
find_library(log-lib log)
target_link_libraries(adhdetect ${log-lib})
target_link_libraries(adhplugin_a ${log-lib} adhdetect)
target_link_libraries(adhplugin_b ${log-lib} adhdetect)
target_compile_options(adhdetect PRIVATE -Wall -O2)
target_compile_options(adhplugin_a PRIVATE -Wall -O2)
target_compile_options(adhplugin_b PRIVATE -Wall -O2)