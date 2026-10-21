/* SPDX-License-Identifier: MIT
 * Bounded data-directive emitter, not a CPU assembler or an emulator oracle.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    unsigned char bytes[4096] = {0};
    char line[512], directive[16], operand[64];
    size_t position = 0, length = 0;
    FILE *input, *output;
    int line_number = 0;
    if (argc != 3) { fputs("usage: build-rom source.S output.bin\n", stderr); return 1; }
    input = fopen(argv[1], "r");
    if (!input) return 1;
    while (fgets(line, sizeof(line), input)) {
        char *start = line, *end;
        unsigned long value;
        unsigned width, i;
        ++line_number;
        while (*start == ' ' || *start == '\t') ++start;
        if (*start != '.') continue;
        if (sscanf(start, "%15s %63s", directive, operand) != 2) goto invalid;
        errno = 0;
        value = strtoul(operand, &end, 0);
        if (errno || *end || value > UINT32_MAX) goto invalid;
        if (!strcmp(directive, ".org")) {
            if (value < position || value >= sizeof(bytes)) goto invalid;
            position = value;
            continue;
        }
        if (!strcmp(directive, ".word")) width = 2;
        else if (!strcmp(directive, ".long")) width = 4;
        else goto invalid;
        if ((width == 2 && value > UINT16_MAX) || position > sizeof(bytes) - width) goto invalid;
        for (i = 0; i < width; ++i) bytes[position++] = (unsigned char)(value >> (8u * (width - i - 1u)));
        length = position;
    }
    if (ferror(input) || fclose(input)) return 1;
    output = fopen(argv[2], "wb");
    if (!output) return 1;
    if (fwrite(bytes, 1, length, output) != length) { fclose(output); return 1; }
    return fclose(output) != 0;
invalid:
    fprintf(stderr, "Invalid diagnostic directive at line %d\n", line_number);
    fclose(input);
    return 1;
}
