/* SPDX-License-Identifier: MIT */
#ifndef GW_DIAGNOSTIC_IDENTITY_H
#define GW_DIAGNOSTIC_IDENTITY_H
#include "evidence.h"
#include "identity.h"
static const char *const gw_diagnostic_cases[] = {"reset","ram","exception","return","stop","bounded"};
static const gw_evidence_identity gw_diagnostic_identity = {
    GW_SOURCE_REVISION, GW_CONFIGURATION, GW_FIXTURE, GW_INPUT,
    "va3-ntsc-u-v1", "original-authored-constants-v1", gw_diagnostic_cases, 6};
#endif
