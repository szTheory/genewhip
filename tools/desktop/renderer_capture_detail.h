/* SPDX-License-Identifier: MIT */
#ifndef GW_RENDERER_CAPTURE_DETAIL_H
#define GW_RENDERER_CAPTURE_DETAIL_H
/* Stable additive host diagnostic enum; never store SDL errors or file paths. */
typedef enum {
    CAPTURE_NONE = 0,
    CAPTURE_LOGICAL_QUERY = 1,
    CAPTURE_CROP = 2,
    CAPTURE_READBACK = 3,
    CAPTURE_SURFACE_SHAPE = 4,
    CAPTURE_SIZE = 5,
    CAPTURE_ALLOCATION = 6,
    CAPTURE_CONVERSION = 7,
    CAPTURE_EXCLUSIVE_OPEN = 8,
    CAPTURE_WRITE = 9,
    CAPTURE_CLOSE = 10
} route_capture_substage;
#endif
