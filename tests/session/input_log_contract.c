/* SPDX-License-Identifier: MIT
 * Input log reader/writer: round trip and every rejection reason.
 */
#define _POSIX_C_SOURCE 200809L
#include "contract.h"
#include "input_log.h"
#include <unistd.h>

static char path[256];

static void write_text(const char *text)
{
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "open temp");
    CHECK(fputs(text, f) >= 0, "write temp");
    CHECK(fclose(f) == 0, "close temp");
}

static void write_bytes(const char *bytes, size_t size)
{
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL, "open temp");
    CHECK(fwrite(bytes, 1, size, f) == size, "write temp");
    CHECK(fclose(f) == 0, "close temp");
}

static void expect_reject(gw_input_log *log, const char *text, const char *reason, const char *name)
{
    const char *got = NULL;
    write_text(text);
    log->count = 7; /* must be cleared on failure */
    CHECK(gw_input_log_read(path, log, &got) != 0, name);
    CHECK(got && strcmp(got, reason) == 0, name);
    CHECK(log->count == 0, name);
}

int main(void)
{
    gw_input_log log, other;
    const char *reason = NULL;
    static const char head[] = "genewhip-input-log 1\n";
    char *big;
    size_t used = 0;
    CHECK(gw_input_log_init(&log) == 0 && gw_input_log_init(&other) == 0, "init");
    (void)snprintf(path, sizeof(path), "input_log_contract_%ld.tmp", (long)getpid());

    /* Round trip. */
    CHECK(gw_input_log_add(&log, 896040, GW_LOG_PAD, 0, 0x41) == 0, "add pad");
    CHECK(gw_input_log_add(&log, 896040, GW_LOG_PAD, 1, 0x80) == 0, "add pad 2");
    CHECK(gw_input_log_add(&log, 900000, GW_LOG_RESET, 0, 0) == 0, "add reset");
    CHECK(gw_input_log_add(&log, 1, GW_LOG_PAD, 0, 0) != 0, "decreasing add refused");
    CHECK(gw_input_log_add(&log, 900000, GW_LOG_PAD, 2, 0) != 0, "port 2 add refused");
    CHECK(gw_input_log_add(&log, 900000, GW_LOG_PAD, 0, 0x100) != 0, "wide mask add refused");
    CHECK(gw_input_log_write(path, &log) == 0, "write");
    CHECK(gw_input_log_read(path, &other, &reason) == 0 && reason == NULL, "read back");
    CHECK(other.count == 3 && other.entries[0].mask == 0x41 && other.entries[1].port == 1 &&
          other.entries[2].kind == GW_LOG_RESET && other.entries[2].tick == 900000, "round trip content");

    expect_reject(&other, "", "header", "empty file");
    expect_reject(&other, "genewhip-input-log 2\n", "header", "bad version");
    expect_reject(&other, "not a log\n", "header", "bad header");
    expect_reject(&other, "genewhip-input-log 1", "header", "unterminated header");
    expect_reject(&other, "genewhip-input-log 1\nabc pad 0 01\n", "syntax", "non-numeric tick");
    expect_reject(&other, "genewhip-input-log 1\n5 pad 0 zz\n", "syntax", "non-hex mask");
    expect_reject(&other, "genewhip-input-log 1\n5 jump\n", "syntax", "unknown kind");
    expect_reject(&other, "genewhip-input-log 1\n5 reset 1\n", "syntax", "reset with operands");
    expect_reject(&other, "genewhip-input-log 1\n5 pad 0 01", "syntax", "truncated final line");
    expect_reject(&other, "genewhip-input-log 1\n10 pad 0 01\n9 pad 0 02\n", "order", "decreasing tick");
    expect_reject(&other, "genewhip-input-log 1\n10 pad 0 01\n9 reset\n", "order", "decreasing reset tick");
    expect_reject(&other, "genewhip-input-log 1\n10 pad 2 01\n", "port", "port 2");
    expect_reject(&other, "genewhip-input-log 1\n10 pad 0 100\n", "mask", "mask 0x100");
    expect_reject(&other, "genewhip-input-log 1\n10 pad 0 123456789\n", "mask", "huge mask");

    /* A line that begins with NUL must be a named syntax rejection, not an underflow. */
    {
        static const char nul_line[] = "genewhip-input-log 1\n\0abc\n";
        const char *got = NULL;
        write_bytes(nul_line, sizeof(nul_line) - 1);
        other.count = 7;
        CHECK(gw_input_log_read(path, &other, &got) != 0, "NUL-leading line rejected");
        CHECK(got && strcmp(got, "syntax") == 0, "NUL-leading line reason");
        CHECK(other.count == 0, "NUL-leading line clears log");
    }

    /* Capacity: exactly the limit reads; one more is rejected. */
    big = (char *)malloc(sizeof(head) + (size_t)(GW_INPUT_LOG_MAX + 1) * 8u);
    CHECK(big != NULL, "alloc");
    memcpy(big, head, sizeof(head) - 1);
    used = sizeof(head) - 1;
    for (unsigned i = 0; i < GW_INPUT_LOG_MAX; ++i) { memcpy(big + used, "1 reset\n", 8); used += 8; }
    big[used] = '\0';
    write_text(big);
    CHECK(gw_input_log_read(path, &other, &reason) == 0 && other.count == GW_INPUT_LOG_MAX, "at capacity reads");
    memcpy(big + used, "1 reset\n", 9);
    expect_reject(&other, big, "capacity", "over capacity");
    free(big);

    reason = NULL;
    CHECK(gw_input_log_read("input_log_contract_missing.tmp", &other, &reason) != 0 && !strcmp(reason, "io"), "missing file");
    (void)unlink(path);
    gw_input_log_free(&log);
    gw_input_log_free(&other);
    puts("PASS: input_log_contract");
    return 0;
}
