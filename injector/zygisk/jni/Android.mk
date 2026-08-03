LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := adh
LOCAL_SRC_FILES := main.cpp
LOCAL_LDLIBS := -llog -ldl
LOCAL_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti -Wall -Wextra
include $(BUILD_SHARED_LIBRARY)
