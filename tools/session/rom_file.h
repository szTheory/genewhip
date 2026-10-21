/* SPDX-License-Identifier: MIT
 * Bounded cartridge file reader and display-name sanitizer for host tools.
 * POSIX file descriptors are used so the regular-file check applies to the
 * descriptor actually read (no stat-then-open race).
 */
#ifndef GENEWHIP_ROM_FILE_H
#define GENEWHIP_ROM_FILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reads a whole cartridge file into buffer (capacity bytes at most).
 * Returns 0 and sets *size, or nonzero and sets *reason to one of: "missing",
 * "not-regular-file", "too-large", "odd-size", "read-error". Never reads
 * past capacity. Files that pass but are too small or have invalid vectors
 * are left to gw_load_rom. */
int gw_read_rom_file(const char *path, uint8_t *buffer, size_t capacity, size_t *size, const char **reason);

/* Copies the final path component of in to out (always terminated), replacing
 * every byte outside printable ASCII with '?' and truncating to capacity - 1. */
void gw_sanitize_display(const char *in, char *out, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
