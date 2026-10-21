/* SPDX-License-Identifier: MIT */
#include "evidence.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const ids[] = {"reset", "ram", "exception", "return", "stop", "bounded"};
static const gw_evidence_identity identity = {
    "1111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "va3-ntsc-u-v1", "original-authored-constants-v1", ids, 6};
static const char *const outcomes[] = {"pass", "fail", "unknown", "unsupported", "skipped", "infrastructure-error"};
static char data[GW_EVIDENCE_MAX_BYTES + 1], valid[GW_EVIDENCE_MAX_BYTES + 1];
static size_t counts[6];
#define CHECK(x, name) do { if (!(x)) { fprintf(stderr,"FAIL: %s at %d\n",name,__LINE__); exit(1); } } while (0)
static void make(int mixed)
{
    size_t used = (size_t)snprintf(data, sizeof(data),
        "{\"schema_version\":1,\"source_revision\":\"%s\",\"source_state\":\"clean\","
        "\"configuration\":\"%s\",\"fixture\":\"%s\",\"input\":\"%s\","
        "\"profile\":\"%s\",\"oracle\":\"%s\",\"expected\":6,\"results\":[",
        identity.revision, identity.configuration, identity.fixture, identity.input, identity.profile, identity.oracle);
    for (size_t i=0; i<6; ++i)
        used += (size_t)snprintf(data+used,sizeof(data)-used,
            "%s{\"id\":\"%s\",\"outcome\":\"%s\",\"observed\":\"assertion-v1\"}",
            i ? "," : "", ids[i], mixed ? outcomes[i] : "pass");
    (void)snprintf(data+used,sizeof(data)-used,"]}");
}
static void expect(const char *reason, int qualify, const char *name)
{
    const char *actual = gw_evidence_validate(data,strlen(data),&identity,qualify,counts);
    if (strcmp(actual,reason)) { fprintf(stderr,"FAIL: %s expected %s actual %s\n",name,reason,actual); exit(1); }
}
int main(void)
{
    char *p;
    make(0); strcpy(valid,data);
    expect("ok",1,"valid complete evidence qualifies");
    CHECK(counts[0]==6,"full passing denominator");
    make(1); expect("ok",0,"all six outcomes retained for inspection");
    for(size_t i=0;i<6;++i) CHECK(counts[i]==1,"each outcome retained");
    expect("non-pass",1,"mixed corpus cannot qualify");
    CHECK(!strcmp(gw_evidence_validate(NULL,0,&identity,1,counts),"missing"),"missing evidence designated rejection");
    strcpy(data,valid); data[0]='['; expect("malformed",1,"malformed object");
    strcpy(data,valid); p=strstr(data,identity.revision); *p='a'; expect("revision",1,"stale revision");
    strcpy(data,valid); p=strstr(data,identity.configuration); *p='a'; expect("configuration",1,"configuration mismatch");
    strcpy(data,valid); p=strstr(data,identity.fixture); *p='a'; expect("fixture",1,"fixture mismatch");
    strcpy(data,valid); p=strstr(data,identity.input); *p='a'; expect("input",1,"input mismatch");
    strcpy(data,valid); p=strstr(data,identity.profile); *p='x'; expect("profile",1,"profile mismatch");
    strcpy(data,valid); p=strstr(data,identity.oracle); *p='x'; expect("oracle",1,"oracle mismatch");
    strcpy(data,valid); p=strstr(data,"clean"); memcpy(p,"dirty",5); expect("dirty",1,"dirty source not qualified");
    strcpy(data,valid); p=strstr(data,"expected\":6"); p[10]='5'; expect("denominator",1,"denominator drift");
    strcpy(data,valid); p=strstr(data,",{\"id\":\"bounded"); strcpy(p,"]}"); expect("denominator",1,"lost outcome");
    strcpy(data,valid); p=strstr(data,"bounded"); memcpy(p,"unknown",7); expect("case-id",1,"substituted case");
    strcpy(data,valid); p=strstr(data,"pass"); memcpy(p,"nope",4); expect("outcome",1,"unknown outcome");
    strcpy(data,valid); strcat(data,"garbage"); expect("malformed",1,"trailing bytes");
    strcpy(data,valid); p=strstr(data,identity.fixture); *p='z'; expect("malformed",1,"nonhex identity");
    CHECK(!strcmp(gw_evidence_validate(valid,strlen(valid)-1,&identity,1,counts),"malformed"),"truncated evidence");
    CHECK(!strcmp(gw_evidence_validate(valid,GW_EVIDENCE_MAX_BYTES+1,&identity,1,counts),"oversize"),"bound before reading");
    for(size_t length=1;length<strlen(valid);++length)
        CHECK(strcmp(gw_evidence_validate(valid,length,&identity,1,counts),"ok"),"every truncation rejected");
    strcpy(data,valid); p=strstr(data,"\"expected\":6");
    memmove(p+13,p+12,strlen(p+12)+1); p[12]='0';
    expect("denominator",1,"larger numeric denominator");
    strcpy(data,valid); p=strstr(data,"assertion-v1"); *p='\\'; expect("malformed",1,"escaped strings not canonical");
    strcpy(data,valid); p=strstr(data,"schema_version\":1"); p[16]='2'; expect("malformed",1,"unknown schema version");
    strcpy(data,valid); data[30]=0;
    CHECK(!strcmp(gw_evidence_validate(data,strlen(valid),&identity,1,counts),"malformed"),"embedded NUL");
    puts("PASS: evidence_contract identities, six outcomes, full denominator, designated rejections");
    return 0;
}
