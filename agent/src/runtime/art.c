#include "art.h"

#include <fcntl.h>
#include <jni.h>
#include <stdint.h>

#include "../bootstrap/agent_internal.h"
#include "jni.h"
#include "jni_env_hooks.h"

#define UNTAG(x) ((unsigned long long)(x) & 0x00FFFFFFFFFFFFFFULL)

struct DexView {
    unsigned long long begin;
    unsigned int size;
    unsigned long long logical;
    unsigned long long data_begin;
    unsigned int data_size;
    char format[8];
    unsigned int version;
    int confidence;
};

// Reads go through the shared backend (mem_read.c): /proc/self/mem when the target is dumpable,
// a bounds-checked direct copy otherwise. art_dexfiles used to require the fd outright, so a
// non-dumpable target reported "no dex files" for the same reason every other read failed.
static ssize_t safe_read_at(unsigned long long address, void *buffer, size_t size) {
    address = UNTAG(address);
    if (address < 0x1000) return 0;
    ssize_t read_size = adh_mem_pread(buffer, size, address);
    return read_size > 0 ? read_size : 0;
}

static unsigned int read_u32(const unsigned char *bytes, int offset) {
    return (unsigned int)bytes[offset] |
           ((unsigned int)bytes[offset + 1] << 8) |
           ((unsigned int)bytes[offset + 2] << 16) |
           ((unsigned int)bytes[offset + 3] << 24);
}

// Scavenge candidate art::DexFile words for begin_ instead of hardcoding ART field
// offsets. DEX 041 snapshots the full container; compact DEX keeps its data range
// explicit for later host-side reconstruction.
static int resolve_dexfile(unsigned long long dexfile_ptr, struct DexView *view) {
    unsigned long long words[24];
    ssize_t read_size = safe_read_at(dexfile_ptr, words, sizeof(words));
    int word_count = (int)(read_size / 8);
    for (int i = 0; i < word_count; i++) {
        unsigned long long begin = UNTAG(words[i]);
        unsigned char header[120];
        if (safe_read_at(begin, header, sizeof(header)) < 120) continue;
        int compact = 0;
        if (header[0] == 'd' && header[1] == 'e' && header[2] == 'x' && header[3] == '\n') compact = 0;
        else if (header[0] == 'c' && header[1] == 'd' && header[2] == 'e' && header[3] == 'x') compact = 1;
        else continue;
        if (header[4] < '0' || header[4] > '9' || header[5] < '0' || header[5] > '9' || header[6] < '0' || header[6] > '9') continue;
        unsigned int version = (header[4] - '0') * 100 + (header[5] - '0') * 10 + (header[6] - '0');
        unsigned int file_size = read_u32(header, 32);
        unsigned int header_size = read_u32(header, 36);
        unsigned int endian = read_u32(header, 40);
        if (file_size < 0x70 || file_size > (256u << 20)) continue;
        if (!compact && endian != 0x12345678u) continue;
        memset(view, 0, sizeof(*view));
        view->logical = begin;
        view->version = version;
        view->confidence = compact ? 60 : 95;
        if (compact) {
            snprintf(view->format, sizeof(view->format), "cdex");
            view->begin = begin;
            view->size = file_size;
        } else if (version >= 41 && header_size >= 0x78) {
            unsigned int container_size = read_u32(header, 112);
            unsigned int header_offset = read_u32(header, 116);
            snprintf(view->format, sizeof(view->format), "dex041");
            if (container_size >= file_size && container_size <= (256u << 20) &&
                header_offset <= container_size) {
                view->begin = begin - header_offset;
                view->size = container_size;
                view->confidence = 100;
            } else {
                view->begin = begin;
                view->size = file_size;
                view->confidence = 70;
            }
            view->data_begin = begin + read_u32(header, 108);
            view->data_size = read_u32(header, 104);
        } else {
            snprintf(view->format, sizeof(view->format), "dex");
            view->begin = begin;
            view->size = file_size;
            view->confidence = 100;
            view->data_begin = begin + read_u32(header, 108);
            view->data_size = read_u32(header, 104);
        }
        return 1;
    }
    return 0;
}

// Walk live thread context ClassLoaders and their parent chains, then resolve each
// DexFile cookie structurally. This is the SDK 35/36 path; it does not magic-scan RAM.
void adh_cmd_art_dexfiles(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    int did = 0;
    JNIEnv *env = adh_jni_attach(&did);
    if (!env) { char e[160]; snprintf(e, sizeof(e), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"art_dexfiles\",\"ok\":false,\"error\":\"no JavaVM\"}\n", idj); send_line(fd, e); return; }
    (*env)->PushLocalFrame(env, 512);

    jclass thread_class = (*env)->FindClass(env, "java/lang/Thread");
    jclass map_class = (*env)->FindClass(env, "java/util/Map");
    jclass set_class = (*env)->FindClass(env, "java/util/Set");
    jclass iterator_class = (*env)->FindClass(env, "java/util/Iterator");
    jclass classloader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
    jclass base_dex_classloader_class = (*env)->FindClass(env, "dalvik/system/BaseDexClassLoader");
    jclass dex_path_list_class = (*env)->FindClass(env, "dalvik/system/DexPathList");
    jclass element_class = (*env)->FindClass(env, "dalvik/system/DexPathList$Element");
    jclass dexfile_class = (*env)->FindClass(env, "dalvik/system/DexFile");
    jclass class_class = (*env)->FindClass(env, "java/lang/Class");
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);

    jmethodID get_all = thread_class ? (*env)->GetStaticMethodID(env, thread_class, "getAllStackTraces", "()Ljava/util/Map;") : NULL;
    jmethodID key_set = map_class ? (*env)->GetMethodID(env, map_class, "keySet", "()Ljava/util/Set;") : NULL;
    jmethodID iterator = set_class ? (*env)->GetMethodID(env, set_class, "iterator", "()Ljava/util/Iterator;") : NULL;
    jmethodID has_next = iterator_class ? (*env)->GetMethodID(env, iterator_class, "hasNext", "()Z") : NULL;
    jmethodID next = iterator_class ? (*env)->GetMethodID(env, iterator_class, "next", "()Ljava/lang/Object;") : NULL;
    jmethodID get_context_loader = thread_class ? (*env)->GetMethodID(env, thread_class, "getContextClassLoader", "()Ljava/lang/ClassLoader;") : NULL;
    jmethodID get_parent = classloader_class ? (*env)->GetMethodID(env, classloader_class, "getParent", "()Ljava/lang/ClassLoader;") : NULL;
    jmethodID get_name = class_class ? (*env)->GetMethodID(env, class_class, "getName", "()Ljava/lang/String;") : NULL;
    jfieldID path_list_field = base_dex_classloader_class ? (*env)->GetFieldID(env, base_dex_classloader_class, "pathList", "Ldalvik/system/DexPathList;") : NULL;
    jfieldID dex_elements_field = dex_path_list_class ? (*env)->GetFieldID(env, dex_path_list_class, "dexElements", "[Ldalvik/system/DexPathList$Element;") : NULL;
    jfieldID dexfile_field = element_class ? (*env)->GetFieldID(env, element_class, "dexFile", "Ldalvik/system/DexFile;") : NULL;
    jfieldID cookie_field = dexfile_class ? (*env)->GetFieldID(env, dexfile_class, "mCookie", "Ljava/lang/Object;") : NULL;
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);

    size_t capacity = 1 << 14, length = 0; char *records = (char *)malloc(capacity); if (records) records[0] = 0;
    int record_count = 0, loader_count = 0;
    unsigned long long seen[512]; int seen_count = 0;

    if (get_all && key_set && iterator && path_list_field && dex_elements_field &&
        dexfile_field && cookie_field && records) {
        jobject map = (*env)->CallStaticObjectMethod(env, thread_class, get_all);
        jobject set = map ? (*env)->CallObjectMethod(env, map, key_set) : NULL;
        jobject iterator_obj = set ? (*env)->CallObjectMethod(env, set, iterator) : NULL;
        while (iterator_obj && (*env)->CallBooleanMethod(env, iterator_obj, has_next)) {
            jobject thread = (*env)->CallObjectMethod(env, iterator_obj, next);
            jobject loader = thread ? (*env)->CallObjectMethod(env, thread, get_context_loader) : NULL;
            int depth = 0;
            while (loader && depth++ < 16) {
                if ((*env)->IsInstanceOf(env, loader, base_dex_classloader_class)) {
                    loader_count++;
                    char loader_name[128] = "";
                    jobject loader_class = (*env)->GetObjectClass(env, loader);
                    if (loader_class && get_name) { jstring name = (jstring)(*env)->CallObjectMethod(env, loader_class, get_name);
                        if (name) { const char *s = (*env)->GetStringUTFChars(env, name, NULL); if (s) { strncpy(loader_name, s, sizeof(loader_name) - 1); (*env)->ReleaseStringUTFChars(env, name, s); } } }
                    jobject path_list = (*env)->GetObjectField(env, loader, path_list_field);
                    jobjectArray elements = path_list ? (jobjectArray)(*env)->GetObjectField(env, path_list, dex_elements_field) : NULL;
                    jsize element_count = elements ? (*env)->GetArrayLength(env, elements) : 0;
                    jclass long_array_class = (*env)->FindClass(env, "[J");
                    for (jsize element_index = 0; element_index < element_count; element_index++) {
                        jobject element = (*env)->GetObjectArrayElement(env, elements, element_index);
                        jobject dexfile = element ? (*env)->GetObjectField(env, element, dexfile_field) : NULL;
                        jobject cookie = dexfile ? (*env)->GetObjectField(env, dexfile, cookie_field) : NULL;
                        if (cookie && (*env)->IsInstanceOf(env, cookie, long_array_class)) {
                            jlongArray array = (jlongArray)cookie;
                            jsize cookie_count = (*env)->GetArrayLength(env, array);
                            jlong *values = (*env)->GetLongArrayElements(env, array, NULL);
                            for (jsize cookie_index = 0; cookie_index < cookie_count && record_count < 256; cookie_index++) {
                                unsigned long long pointer = (unsigned long long)values[cookie_index];
                                if (pointer < 0x10000) continue;
                                struct DexView view;
                                if (resolve_dexfile(pointer, &view)) {
                                    int duplicate = 0; for (int i = 0; i < seen_count; i++) if (seen[i] == view.begin) { duplicate = 1; break; }
                                    if (duplicate) continue;
                                    if (seen_count < 512) seen[seen_count++] = view.begin;
                                    char loaderj[160]; json_escape(loader_name, loaderj, sizeof(loaderj));
                                    char record[520];
                                    int written = snprintf(record, sizeof(record),
                                        "%s{\"dexFilePtr\":\"%llx\",\"begin\":\"%llx\",\"size\":%u,\"magic\":\"%s\",\"format\":\"%s\",\"version\":%u,\"logical\":\"%llx\",\"dataBegin\":\"%llx\",\"dataSize\":%u,\"confidence\":%d,\"loader\":\"%s\"}",
                                        record_count ? "," : "", pointer, view.begin, view.size, view.format, view.format, view.version, view.logical, view.data_begin, view.data_size, view.confidence, loaderj);
                                    if (written > 0) {
                                        if (length + (size_t)written + 1 >= capacity) {
                                            size_t new_capacity = capacity; while (length + (size_t)written + 1 >= new_capacity) new_capacity *= 2;
                                            char *new_records = realloc(records, new_capacity);
                                            if (!new_records) continue;
                                            records = new_records; capacity = new_capacity;
                                        }
                                        memcpy(records + length, record, (size_t)written); length += (size_t)written; records[length] = 0; record_count++;
                                    }
                                }
                            }
                            (*env)->ReleaseLongArrayElements(env, array, values, JNI_ABORT);
                        }
                        if (element) (*env)->DeleteLocalRef(env, element);
                        if (dexfile) (*env)->DeleteLocalRef(env, dexfile);
                        if (cookie) (*env)->DeleteLocalRef(env, cookie);
                    }
                }
                jobject parent = (*env)->CallObjectMethod(env, loader, get_parent);
                (*env)->DeleteLocalRef(env, loader);
                loader = parent;
            }
            if (thread) (*env)->DeleteLocalRef(env, thread);
        }
    }
    if (adh_jni_exception_check(env)) adh_jni_exception_clear(env);
    adh_mem_fd_release();          // no standing /proc/self/mem fd after the command returns
    (*env)->PopLocalFrame(env, NULL);
    adh_jni_detach(did);

    size_t output_size = (records ? strlen(records) : 0) + 200;
    char *out = (char *)malloc(output_size);
    if (out) { snprintf(out, output_size, "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"art_dexfiles\",\"ok\":true,\"loaders\":%d,\"count\":%d,\"dexfiles\":[%s]}\n", idj, loader_count, record_count, records ? records : ""); send_line(fd, out); free(out); }
    free(records);
    LOGI("art_dexfiles: loaders=%d dexfiles=%d", loader_count, record_count);
}
