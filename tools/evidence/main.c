/* SPDX-License-Identifier: MIT */
#include "diagnostic_identity.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    char data[GW_EVIDENCE_MAX_BYTES+1]; size_t length, counts[6]={0};
    FILE *f; const char *reason; int qualify=1, io_error;
    if(argc!=2 && !(argc==3 && !strcmp(argv[2],"--inspect"))) {
        fputs("usage: gw_validate_evidence report.json [--inspect]\n",stderr); return 2;
    }
    if(argc==3) qualify=0;
    f=fopen(argv[1],"rb");
    if(!f) { fputs("REJECT: missing\n",stderr); return 1; }
    length=fread(data,1,sizeof(data),f); io_error=ferror(f);
    if(fclose(f)) io_error=1;
    if(io_error) { fputs("REJECT: infrastructure-error\n",stderr); return 1; }
    reason=gw_evidence_validate(data,length,&gw_diagnostic_identity,qualify,counts);
    if(!strcmp(reason,"ok") && qualify && strcmp(GW_SOURCE_STATE,"clean")) reason="dirty-build";
    printf("%s: %s pass=%zu fail=%zu unknown=%zu unsupported=%zu skipped=%zu infrastructure-error=%zu expected=6\n",
        !strcmp(reason,"ok") ? "ACCEPT" : "REJECT",reason,
        counts[0],counts[1],counts[2],counts[3],counts[4],counts[5]);
    return strcmp(reason,"ok") ? 1 : 0;
}
