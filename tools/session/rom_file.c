/* SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200809L
#include "rom_file.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fail(const char **reason, const char *why)
{
    if (reason) *reason = why;
    return 1;
}

int gw_read_rom_file(const char *path, uint8_t *buffer, size_t capacity, size_t *size, const char **reason)
{
    struct stat info;
    size_t length, done = 0;
    int fd;
    if (!path || !buffer || !size) return fail(reason, "read-error");
    /* O_NONBLOCK keeps a FIFO from stalling open; fstat then rejects it. */
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return fail(reason, errno == ENOENT || errno == ENOTDIR ? "missing" : "read-error");
    if (fstat(fd, &info) != 0) { (void)close(fd); return fail(reason, "read-error"); }
    if (!S_ISREG(info.st_mode)) { (void)close(fd); return fail(reason, "not-regular-file"); }
    if (info.st_size < 0 || (uintmax_t)info.st_size > (uintmax_t)capacity) {
        (void)close(fd);
        return fail(reason, "too-large");
    }
    length = (size_t)info.st_size;
    if (length & 1u) { (void)close(fd); return fail(reason, "odd-size"); }
    while (done < length) {
        ssize_t got = read(fd, buffer + done, length - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { (void)close(fd); return fail(reason, "read-error"); }
        done += (size_t)got;
    }
    (void)close(fd);
    *size = length;
    return 0;
}

void gw_sanitize_display(const char *in, char *out, size_t capacity)
{
    const char *base = in;
    size_t i = 0;
    if (!out || capacity == 0) return;
    if (!in) { out[0] = '\0'; return; }
    for (const char *p = in; *p; ++p)
        if (*p == '/') base = p + 1;
    for (; base[i] && i + 1 < capacity; ++i) {
        unsigned char c = (unsigned char)base[i];
        out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    out[i] = '\0';
}
