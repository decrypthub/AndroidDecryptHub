// fs.c — filesystem browsing commands: list a directory, read a file. Powers the web
// 「文件」panel (browse the target app's private dir + app-readable dirs). Collect-only,
// bounded, fail-loud. Uses util/io helpers. No target knowledge lives here.
#include "agent_internal.h"
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>

// List directory `path`: one JSON object per entry with name/type/size/mode/mtime.
// Bounded to MAXENT entries — `truncated:true` beyond (no silent under-report). opendir
// failure replies ok:false with strerror(errno). type: "d" dir / "f" file / "l" symlink / "o" other.
void cmd_list_dir(int fd, const char *id, const char *path) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    if (!path || !path[0]) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"list_dir\",\"ok\":false,\"error\":\"empty path\"}\n", idj);
        send_line(fd, err); return;
    }
    DIR *dir = opendir(path);
    if (!dir) {
        int e = errno;
        char pj[1200]; json_escape(path, pj, sizeof(pj));
        char err[1500];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"list_dir\",\"ok\":false,\"path\":\"%s\",\"error\":\"opendir errno %d (%s)\"}\n",
                 idj, pj, e, strerror(e));
        send_line(fd, err); return;
    }
    const int MAXENT = 4000;
    size_t cap = 1 << 16, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { closedir(dir); send_oom(fd, idj, "list_dir"); return; }
    buf[0] = 0;
    int emitted = 0, truncated = 0;
    size_t plen = strlen(path);
    struct dirent *de;
    while ((de = readdir(dir))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (emitted >= MAXENT) { truncated = 1; break; }
        // Build full path for lstat (path + "/" + name), skip entry on overflow rather than truncate silently.
        char full[2048];
        int need = snprintf(full, sizeof(full), "%s%s%s", path,
                            (plen && path[plen - 1] == '/') ? "" : "/", de->d_name);
        struct stat st;
        long long size = -1, mtime = 0; unsigned mode = 0; char type = 'o';
        if (need > 0 && (size_t)need < sizeof(full) && lstat(full, &st) == 0) {
            mode = st.st_mode & 07777;
            mtime = (long long)st.st_mtime;
            if (S_ISDIR(st.st_mode)) type = 'd';
            else if (S_ISLNK(st.st_mode)) type = 'l';
            else if (S_ISREG(st.st_mode)) { type = 'f'; size = (long long)st.st_size; }
            else { type = 'o'; size = (long long)st.st_size; }
        } else {
            // Directory entry exists but can't stat it (perms/dangling) — report it honestly.
            type = 'o';
        }
        char nj[1100]; json_escape(de->d_name, nj, sizeof(nj));
        char rec[1400];
        int w = snprintf(rec, sizeof(rec),
            "%s{\"name\":\"%s\",\"type\":\"%c\",\"size\":%lld,\"mode\":%u,\"mtime\":%lld}",
            emitted ? "," : "", nj, type, size, mode, mtime);
        if (w < 0) continue;
        if (len + (size_t)w + 1 >= cap) {
            while (len + (size_t)w + 1 >= cap) cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { truncated = 1; break; }   // OOM: stop but report — never silently under-list
            buf = nb;
        }
        memcpy(buf + len, rec, (size_t)w);
        len += (size_t)w; buf[len] = 0;
        emitted++;
    }
    closedir(dir);
    char pj[1200]; json_escape(path, pj, sizeof(pj));
    size_t olen = len + 400;
    char *out = (char *)malloc(olen);
    if (!out) { free(buf); send_oom(fd, idj, "list_dir"); return; }
    snprintf(out, olen,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"list_dir\",\"ok\":true,\"path\":\"%s\",\"count\":%d,\"truncated\":%s,\"entries\":[%s]}\n",
        idj, pj, emitted, truncated ? "true" : "false", buf ? buf : "");
    send_line(fd, out);
    free(out); free(buf);
}

// Read up to READCAP bytes of file `path`, reply as base64. `size` is bytes returned;
// `truncated:true` iff the file is larger than what we read. open/read failure -> ok:false + errno.
void cmd_read_file(int fd, const char *id, const char *path) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    if (!path || !path[0]) {
        char err[160];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read_file\",\"ok\":false,\"error\":\"empty path\"}\n", idj);
        send_line(fd, err); return;
    }
    const size_t READCAP = 1u << 20;   // 1MB cap per read
    char pj[1200]; json_escape(path, pj, sizeof(pj));
    int f = open(path, O_RDONLY);
    if (f < 0) {
        int e = errno;
        char err[1500];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read_file\",\"ok\":false,\"path\":\"%s\",\"error\":\"open errno %d (%s)\"}\n",
                 idj, pj, e, strerror(e));
        send_line(fd, err); return;
    }
    struct stat st; long long fsize = -1;
    if (fstat(f, &st) == 0) fsize = (long long)st.st_size;
    unsigned char *raw = (unsigned char *)malloc(READCAP);
    if (!raw) { close(f); send_oom(fd, idj, "read_file"); return; }
    size_t total = 0; ssize_t got;
    while (total < READCAP && (got = read(f, raw + total, READCAP - total)) > 0) total += (size_t)got;
    int rerr = (got < 0) ? errno : 0;
    // Probe one more byte to know if the file exceeds our cap (honest truncated flag).
    int truncated = 0;
    if (total == READCAP) { unsigned char extra; if (read(f, &extra, 1) == 1) truncated = 1; }
    close(f);
    if (got < 0 && total == 0) {
        free(raw);
        char err[1500];
        snprintf(err, sizeof(err), "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read_file\",\"ok\":false,\"path\":\"%s\",\"error\":\"read errno %d (%s)\"}\n",
                 idj, pj, rerr, strerror(rerr));
        send_line(fd, err); return;
    }
    char *b64 = (char *)malloc(total * 4 / 3 + 8);
    if (!b64) { free(raw); send_oom(fd, idj, "read_file"); return; }
    b64_encode(raw, total, b64);
    free(raw);
    size_t olen = strlen(b64) + 400;
    char *out = (char *)malloc(olen);
    if (!out) { free(b64); send_oom(fd, idj, "read_file"); return; }
    snprintf(out, olen,
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"read_file\",\"ok\":true,\"path\":\"%s\",\"size\":%zu,\"fsize\":%lld,\"truncated\":%s,\"b64\":\"%s\"}\n",
        idj, pj, total, fsize, truncated ? "true" : "false", b64);
    send_line(fd, out);
    free(out); free(b64);
}
