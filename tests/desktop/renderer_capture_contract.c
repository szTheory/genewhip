/* SPDX-License-Identifier: MIT
 * Runs the production capture implementation, replacing only SDL/file leaves.
 * No SDL, ROM, device, window server or filesystem output is needed.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "renderer_capture_detail.h"
typedef struct { float x, y, w, h; } SDL_FRect;
typedef struct { int x, y, w, h; } SDL_Rect;
typedef struct { void *pixels; int w, h, pitch, format; } SDL_Surface;
enum { SDL_PIXELFORMAT_RGBA32 = 1, ROUTE_FAILURE_NONE = 0,
    ROUTE_FAILURE_RENDERER_CAPTURE = 13, ROUTE_FAILURE_ROUTE_EXECUTION = 15 };
typedef struct {
    void *renderer;
    const char *route_renderer_capture_path;
    int route_renderer_capture_done, route_first_failure;
    uint64_t route_renderer_capture_field, route_renderer_capture_hash;
    route_capture_substage route_capture_first_failure;
} runner;
static int fault, width = 320, height = 224, shape, destroys, frees, opens, closes, writes;
static int allocated;
static SDL_Surface surface;
static uint8_t output[320u * 224u * 4u];
static size_t output_size;
static float origin_x, origin_y;
static void route_mark_failure(runner *r, int stage)
{ if (r->route_first_failure == ROUTE_FAILURE_NONE) r->route_first_failure = stage; }
static uint64_t route_hash_bytes(uint64_t hash, const void *data, size_t length)
{
    const uint8_t *bytes = data;
    if (!hash) hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) { hash ^= bytes[i]; hash *= UINT64_C(1099511628211); }
    return hash;
}
static int SDL_GetRenderLogicalPresentationRect(void *renderer, SDL_FRect *rect)
{
    (void)renderer;
    *rect = (SDL_FRect){origin_x, origin_y, (float)width, (float)height};
    if (fault == CAPTURE_CROP) rect->w = 319;
    return fault != CAPTURE_LOGICAL_QUERY;
}
static SDL_Surface *SDL_RenderReadPixels(void *renderer, const SDL_Rect *crop)
{
    (void)renderer;
    surface = (SDL_Surface){&surface, crop->w, crop->h, 4, 0};
    if (fault == CAPTURE_SURFACE_SHAPE) {
        if (shape == 0) surface.pixels = NULL;
        if (shape == 1) surface.w--;
        if (shape == 2) surface.h--;
    }
    return fault == CAPTURE_READBACK ? NULL : &surface;
}
static void SDL_DestroySurface(SDL_Surface *value) { assert(value == &surface); destroys++; }
static void *fake_malloc(size_t size)
{
    if (fault == CAPTURE_ALLOCATION) return NULL;
    allocated++;
    return malloc(size);
}
static void fake_free(void *value) { assert(allocated == 1); allocated--; frees++; free(value); }
static int SDL_ConvertPixels(int w, int h, int format, const void *pixels, int pitch,
    int target_format, void *target, int target_pitch)
{
    (void)format; (void)pixels; (void)pitch; (void)target_format;
    assert(target_pitch == w * 4);
    if (fault == CAPTURE_CONVERSION) return 0;
    for (int y = 0; y < h; ++y) for (int x = 0; x < w; ++x) {
        uint8_t *p = (uint8_t *)target + ((size_t)y * (size_t)w + (size_t)x) * 4u;
        p[0] = (uint8_t)x; p[1] = (uint8_t)y; p[2] = (uint8_t)(x + y); p[3] = 255;
    }
    return 1;
}
static FILE *route_capture_open_exclusive(const char *path)
{ (void)path; opens++; return fault == CAPTURE_EXCLUSIVE_OPEN ? NULL : (FILE *)&surface; }
static size_t fake_write(const void *data, size_t size, size_t count, FILE *file)
{
    assert(file == (FILE *)&surface && size == 1 && count == 4); writes++;
    if (fault == CAPTURE_WRITE) return 3;
    assert(output_size + 4 <= sizeof(output));
    memcpy(output + output_size, data, 4); output_size += 4;
    return 4;
}
static int fake_close(FILE *file)
{
    assert(file == (FILE *)&surface); closes++;
    /* A write error deliberately coincides with a cleanup close error. */
    return fault == CAPTURE_CLOSE || fault == CAPTURE_WRITE ? -1 : 0;
}
#define SDL_malloc fake_malloc
#define SDL_free fake_free
#define fwrite fake_write
#define fclose fake_close
#include "renderer_capture_impl.h"
#undef fwrite
#undef fclose
static runner fresh(int failure)
{
    runner r = {0};
    fault = failure; destroys = frees = opens = closes = writes = allocated = 0;
    output_size = 0;
    origin_x = origin_y = 0.0f;
    r.route_renderer_capture_path = "offline-only"; r.route_renderer_capture_field = 7;
    return r;
}
static void success(void)
{
    runner r = fresh(0);
    assert(route_capture_renderer_target(&r, 7) == 1);
    assert(r.route_renderer_capture_done && r.route_first_failure == 0);
    assert(r.route_capture_first_failure == CAPTURE_NONE);
    assert(output_size == sizeof(output) && destroys == 1 && frees == 1 && allocated == 0);
    assert(closes == 1 && opens == 1 && writes == 320 * 224);
    for (unsigned y = 0; y < 224; ++y) for (unsigned x = 0; x < 320; ++x) {
        unsigned sx = (2*x+1) * (unsigned)width / 640;
        unsigned sy = (2*y+1) * (unsigned)height / 448;
        const uint8_t *p = output + (y*320+x)*4;
        assert(p[0] == (uint8_t)(sx+sy) && p[1] == (uint8_t)sy && p[2] == (uint8_t)sx && p[3] == 0);
    }
    printf("success %dx%d %016llx\n", width, height, (unsigned long long)r.route_renderer_capture_hash);
}
int main(int argc, char **argv)
{
    success(); width = 640; height = 448; success(); width = 320; height = 224;
    if (argc == 2 && strcmp(argv[1], "--success-only") == 0) return 0;
    for (int failure = 1; failure <= 10; ++failure) {
        runner r = fresh(failure);
        if (failure == CAPTURE_SIZE) { width = 8192; height = 4096; }
        assert(route_capture_renderer_target(&r, 7) == 0);
        assert(r.route_first_failure == 13 && (int)r.route_capture_first_failure == failure);
        assert(!r.route_renderer_capture_done && !r.route_renderer_capture_hash && allocated == 0);
        assert(destroys == (failure >= CAPTURE_SURFACE_SHAPE));
        assert(frees == (failure >= CAPTURE_CONVERSION));
        assert(closes == (failure >= CAPTURE_WRITE));
        route_mark_capture_failure(&r, CAPTURE_CLOSE);
        route_mark_failure(&r, ROUTE_FAILURE_ROUTE_EXECUTION);
        assert((int)r.route_capture_first_failure == failure && r.route_first_failure == 13);
        width = 320; height = 224;
    }
    for (shape = 1; shape <= 2; ++shape) {
        runner r = fresh(CAPTURE_SURFACE_SHAPE);
        assert(!route_capture_renderer_target(&r, 7));
        assert(r.route_capture_first_failure == CAPTURE_SURFACE_SHAPE && destroys == 1);
    }
    /* Neighbor dimensions and the unchanged 80 MiB bound. Allocation is
     * denied at its leaf so these controls do not consume the large buffer. */
    for (int w = 5119; w <= 5121; ++w) {
        runner r = fresh(CAPTURE_ALLOCATION);
        width = w; height = 4096;
        assert(!route_capture_renderer_target(&r, 7));
        assert(r.route_capture_first_failure == (w <= 5120 ? CAPTURE_ALLOCATION : CAPTURE_SIZE));
        assert(destroys == 1 && allocated == 0);
    }
    for (int dimension = 0; dimension < 2; ++dimension) {
        runner r = fresh(0);
        width = dimension ? 320 : 319; height = dimension ? 223 : 224;
        assert(!route_capture_renderer_target(&r, 7));
        assert(r.route_capture_first_failure == CAPTURE_CROP && destroys == 0);
    }
    width = 321; height = 225; success(); width = 320; height = 224;
    {
        const float invalid[] = {-0.5f, NAN, INFINITY, (float)INT_MAX};
        for (unsigned coordinate = 0; coordinate < 2; ++coordinate) {
            for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
                runner r = fresh(0);
                if (coordinate == 0) origin_x = invalid[i];
                else origin_y = invalid[i];
                assert(!route_capture_renderer_target(&r, 7));
                assert(r.route_capture_first_failure == CAPTURE_CROP);
                assert(destroys == 0 && allocated == 0 && opens == 0);
            }
        }
    }
    {
        runner r = fresh(CAPTURE_WRITE);
        r.route_first_failure = ROUTE_FAILURE_ROUTE_EXECUTION;
        assert(!route_capture_renderer_target(&r, 7));
        assert(r.route_first_failure == 15 && r.route_capture_first_failure == CAPTURE_NONE);
    }
    {
        runner r = fresh(CAPTURE_LOGICAL_QUERY);
        assert(route_capture_renderer_target(&r, 6) && !r.route_first_failure);
        r.route_renderer_capture_path = NULL;
        assert(route_capture_renderer_target(&r, 7) && !r.route_first_failure);
        r.route_renderer_capture_path = "offline-only"; r.route_renderer_capture_done = 1;
        assert(route_capture_renderer_target(&r, 7) && !r.route_first_failure);
    }
    puts("capture branches, cleanup precedence and skip controls pass");
    return 0;
}
