/* SPDX-License-Identifier: MIT */
#include "evidence.h"
#include <string.h>

typedef struct parser { const char *p, *end; } parser;
static void space(parser *s)
{
    while (s->p < s->end && (*s->p==' ' || *s->p=='\t' || *s->p=='\r' || *s->p=='\n')) ++s->p;
}
static int token(parser *s, const char *text)
{
    size_t n = strlen(text);
    space(s);
    if ((size_t)(s->end-s->p)<n || memcmp(s->p,text,n)) return 0;
    s->p += n; return 1;
}
static int string(parser *s, char out[129])
{
    size_t n=0;
    if (!token(s,"\"")) return 0;
    while (s->p<s->end && *s->p!='"') {
        unsigned char c=(unsigned char)*s->p++;
        if (n==128 || !((c>='a' && c<='z') || (c>='A' && c<='Z') ||
            (c>='0' && c<='9') || c=='-' || c=='_' || c=='.')) return 0;
        out[n++]=(char)c;
    }
    out[n]=0;
    return n!=0 && token(s,"\"");
}
static int hex(const char *s, size_t length)
{
    if(strlen(s)!=length) return 0;
    for(size_t i=0;i<length;++i)
        if(!((s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f'))) return 0;
    return 1;
}
static const char *field(parser *s, const char *key, const char *expected,
    size_t hex_length, const char *reason)
{
    char value[129];
    if (!token(s,key) || !string(s,value) || (hex_length && !hex(value,hex_length))) return "malformed";
    return strcmp(value,expected) ? reason : NULL;
}

const char *gw_evidence_validate(const char *data, size_t length,
    const gw_evidence_identity *expected, int qualify, size_t counts[6])
{
    static const char *const outcomes[] = {"pass","fail","unknown","unsupported","skipped","infrastructure-error"};
    size_t local[6]={0}, denominator=0, rows=0;
    char value[129]; const char *error; int dirty;
    parser s;
    if (!data || !length) return "missing";
    if (length>GW_EVIDENCE_MAX_BYTES) return "oversize";
    if (!expected || !counts || !expected->ids || !expected->count || expected->count>GW_EVIDENCE_MAX_ROWS)
        return "argument";
    if (memchr(data,0,length)) return "malformed";
    s.p=data; s.end=data+length;
    if (!token(&s,"{") || !token(&s,"\"schema_version\":") || !token(&s,"1")) return "malformed";
    error=field(&s,",\"source_revision\":",expected->revision,40,"revision"); if(error) return error;
    if(!token(&s,",\"source_state\":") || !string(&s,value)) return "malformed";
    dirty=!strcmp(value,"dirty");
    if(!dirty && strcmp(value,"clean")) return "malformed";
    error=field(&s,",\"configuration\":",expected->configuration,64,"configuration"); if(error) return error;
    error=field(&s,",\"fixture\":",expected->fixture,64,"fixture"); if(error) return error;
    error=field(&s,",\"input\":",expected->input,64,"input"); if(error) return error;
    error=field(&s,",\"profile\":",expected->profile,0,"profile"); if(error) return error;
    error=field(&s,",\"oracle\":",expected->oracle,0,"oracle"); if(error) return error;
    if(!token(&s,",\"expected\":")) return "malformed";
    space(&s);
    if(s.p==s.end || *s.p<'1' || *s.p>'9') return "denominator";
    while(s.p<s.end && *s.p>='0' && *s.p<='9') {
        denominator=denominator*10+(size_t)(*s.p++-'0');
        if(denominator>GW_EVIDENCE_MAX_ROWS) return "denominator";
    }
    if(denominator!=expected->count) return "denominator";
    if(!token(&s,",\"results\":[")) return "malformed";
    for(;;) {
        size_t outcome;
        space(&s);
        if(s.p<s.end && *s.p==']') { ++s.p; break; }
        if(rows>=denominator) return "denominator";
        if(!token(&s,"{\"id\":") || !string(&s,value)) return "malformed";
        if(strcmp(value,expected->ids[rows])) return "case-id";
        if(!token(&s,",\"outcome\":") || !string(&s,value)) return "malformed";
        for(outcome=0;outcome<6;++outcome) if(!strcmp(value,outcomes[outcome])) break;
        if(outcome==6) return "outcome";
        ++local[outcome]; ++rows;
        if(!token(&s,",\"observed\":") || !string(&s,value) || !token(&s,"}")) return "malformed";
        space(&s);
        if(s.p<s.end && *s.p==']') { ++s.p; break; }
        if(!token(&s,",")) return "malformed";
        space(&s);
        if(s.p==s.end || *s.p==']') return "malformed";
    }
    if(!token(&s,"}")) return "malformed";
    space(&s);
    if(s.p!=s.end) return "malformed";
    if(rows!=denominator) return "denominator";
    memcpy(counts,local,sizeof(local));
    if(qualify && dirty) return "dirty";
    if(qualify && local[0]!=denominator) return "non-pass";
    return "ok";
}
