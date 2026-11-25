#ifndef ADH_JAVA_ENUM_INTERNAL_H
#define ADH_JAVA_ENUM_INTERNAL_H

// Shared helpers for java_enum.cpp / java_call.cpp (split from java_enum.cpp).

#include "java_enum.h"
#include "jni.h"
#include "jni_env_hooks.h"

#include <android/log.h>
#include <pthread.h>
#include <time.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <vector>

#define TAG "rt.enum"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

inline void set_error(char *error, size_t error_size, const char *format, ...) {
    if (!error || !error_size) return;
    va_list ap;
    va_start(ap, format);
    vsnprintf(error, error_size, format, ap);
    va_end(ap);
    error[error_size - 1] = 0;
}

struct LocalFrameGuard {
    JNIEnv *env;
    bool active;
    LocalFrameGuard(JNIEnv *e, jint capacity) : env(e), active(false) {
        if (env && env->PushLocalFrame(capacity) == 0) active = true;
    }
    ~LocalFrameGuard() {
        if (active) {
            if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
            env->PopLocalFrame(nullptr);
        }
    }
};

std::string jstring_to_utf(JNIEnv *env, jstring value); static std::string throwable_text(JNIEnv *env, jthrowable throwable);
std::string pending_exception_text(JNIEnv *env);
std::string json_escape(const std::string &value);
std::string class_name_of(JNIEnv *env, jclass cls, jmethodID get_name);

#endif
