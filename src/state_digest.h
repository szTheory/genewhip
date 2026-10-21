/* SPDX-License-Identifier: MIT */
#ifndef GW_STATE_DIGEST_H
#define GW_STATE_DIGEST_H

#include "genewhip/genewhip.h"

#ifdef GW_TEST_HOOKS
/* Private test-only hash of explicit execution state; never installed. */
uint64_t gw_test_state_digest(const gw_machine *machine);
#endif

#endif
