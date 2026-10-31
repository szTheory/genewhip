/* SPDX-License-Identifier: MIT */
#include "session.h"
#include "route_controller.h"
#include <genewhip/genewhip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct read_call { uint32_t address; size_t length; int status; uint8_t byte; } read_call;
static read_call calls[128];
static size_t call_count;

gw_status gw_test_forward_peek(gw_machine *machine, uint32_t address, void *out, size_t length)
{
    gw_status status = gw_peek_memory(machine, address, out, length);
    if (call_count < sizeof(calls) / sizeof(calls[0])) {
        calls[call_count++] = (read_call){address, length, (int)status,
            status == GW_OK && length == 1 && out ? *(const uint8_t *)out : 0};
    }
    return status;
}

static void put_le32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value; out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16); out[3] = (uint8_t)(value >> 24);
}

static void descriptor_bytes(uint8_t out[144])
{
    uint32_t words[36] = {0};
    words[0] = UINT32_C(0x43525747); words[1] = 1; words[2] = 1;
    words[3] = 1; words[4] = 1; words[6] = 1; words[30] = 14;
    words[32] = UINT32_C(0x00e00000); words[33] = UINT32_C(0x00e00000);
    words[34] = 1; words[35] = 0;
    for (size_t i = 0; i < 36; ++i) put_le32(out + i * 4, words[i]);
}

static int run_case(const char *name, const uint8_t *code, size_t code_size,
                    uint32_t probe_pc, int enabled, int probe_only)
{
    uint8_t rom[1024] = {0}, descriptor[144], *report = NULL;
    gw_config config = {sizeof(gw_config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 1, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, 0};
    gw_session session = {0}; gw_route_controller *plan = NULL;
    FILE *stream = NULL; long report_size; int route_status;
    rom[0] = 0xa5; rom[1] = 0xff; rom[2] = 0; rom[3] = 0x10;
    rom[4] = 0; rom[5] = 0; rom[6] = 2; rom[7] = 0;
    memcpy(rom + 0x200, code, code_size); descriptor_bytes(descriptor);
    call_count = 0;
    int open_status = gw_session_open(&session, &config, rom, sizeof(rom));
    if (open_status != GW_OK) {
        fprintf(stderr, "phase6 stack forward: session open failed (%d)\n", open_status); goto fail;
    }
    int parse_status = gw_route_controller_parse(descriptor, sizeof(descriptor), &plan);
    if (parse_status != 0) {
        fprintf(stderr, "phase6 stack forward: descriptor parse failed (%d)\n", parse_status); goto fail;
    }
    stream = tmpfile();
    if (!stream) { fputs("phase6 stack forward: tmpfile failed\n", stderr); goto fail; }
    session.route_instruction_probe = 1; session.route_probe_only = probe_only;
    session.route_probe_stack_before_a7 = enabled; session.route_probe_pc = probe_pc;
    route_status = gw_route_controller_run(&session, plan, stream, NULL, NULL, NULL, NULL, 0);
    if (fflush(stream) != 0 || fseek(stream, 0, SEEK_END) != 0 || (report_size = ftell(stream)) < 0 ||
        report_size > 8388608 || fseek(stream, 0, SEEK_SET) != 0) goto fail;
    report = malloc((size_t)report_size + 1);
    if (!report || fread(report, 1, (size_t)report_size, stream) != (size_t)report_size) goto fail;
    report[report_size] = 0;
    printf("{\"case\":\"%s\",\"route_status\":%d,\"guest_hex\":\"", name, route_status);
    for (size_t i = 0; i < sizeof(rom); ++i) printf("%02x", rom[i]);
    fputs("\",\"descriptor_hex\":\"", stdout);
    for (size_t i = 0; i < sizeof(descriptor); ++i) printf("%02x", descriptor[i]);
    printf("\",\"report\":%s,\"calls\":[", report);
    for (size_t i = 0; i < call_count; ++i) {
        printf("%s{\"address\":%u,\"length\":%zu,\"status\":%d,\"byte\":%u}",
            i ? "," : "", calls[i].address, calls[i].length, calls[i].status, calls[i].byte);
    }
    puts("]}");
    free(report); fclose(stream); gw_route_controller_free(plan); gw_session_close(&session);
    return 0;
fail:
    free(report); if (stream) fclose(stream); gw_route_controller_free(plan); gw_session_close(&session);
    return 1;
}

int main(void)
{
    static const uint8_t pea[] = {0x48,0x79,0x00,0x06,0x92,0x3c};
    static const uint8_t followed[] = {0x48,0x79,0x00,0x06,0x92,0x3c,0x4e,0x71};
    static const uint8_t same_pc[] = {0x60,0xfe};
    static const uint8_t wrap[] = {0x2e,0x7c,0,0,0,2,0x4e,0x71};
    static const uint8_t bad[] = {0x2e,0x7c,0,0x80,0,8,0x4e,0x71};
    if (run_case("enabled-pea", pea, sizeof(pea), 0x200, 1, 1) ||
        run_case("disabled-pea", pea, sizeof(pea), 0x200, 0, 1) ||
        run_case("absent-target", pea, sizeof(pea), 0x204, 1, 1) ||
        run_case("target-followed", followed, sizeof(followed), 0x200, 1, 0) ||
        run_case("same-pc", same_pc, sizeof(same_pc), 0x200, 1, 1) ||
        run_case("wrap", wrap, sizeof(wrap), 0x206, 1, 1) ||
        run_case("exact-error", bad, sizeof(bad), 0x206, 1, 1)) return 1;
    return 0;
}
