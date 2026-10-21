/* SPDX-License-Identifier: MIT */
#ifndef GENEWHIP_RATE_CTL_H
#define GENEWHIP_RATE_CTL_H

#include <stdint.h>

#define GW_RATE_K_PPM INT32_C(100000)
#define GW_RATE_LIMIT_PPM INT32_C(5000)

/* Returns the signed ppm offset in ratio = 1 + result/1,000,000. */
int32_t gw_rate_ppm(int64_t depth_frames, int64_t target_frames, int32_t k_ppm);

#endif
