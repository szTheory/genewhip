/* SPDX-License-Identifier: MIT
 * Real pinned SDL software renderer; no window, device, ROM or guest work.
 * Only the output file sink is replaced. Production readback remains real.
 */
#include <SDL3/SDL.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "renderer_capture_detail.h"

enum { ROUTE_FAILURE_NONE = 0, ROUTE_FAILURE_RENDERER_CAPTURE = 13 };
typedef struct {
    SDL_Renderer *renderer;
    const char *route_renderer_capture_path;
    int route_renderer_capture_done, route_first_failure;
    uint64_t route_renderer_capture_field, route_renderer_capture_hash;
    route_capture_substage route_capture_first_failure;
} runner;
static uint8_t captured[320u * 224u * 4u];
static size_t captured_size;
static int sink, returned_w, returned_h, readbacks;
static SDL_Rect requested;
static void route_mark_failure(runner *r, int stage)
{ if (!r->route_first_failure) r->route_first_failure = stage; }
static uint64_t route_hash_bytes(uint64_t hash, const void *data, size_t length)
{
    const uint8_t *bytes = data;
    if (!hash) hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) { hash ^= bytes[i]; hash *= UINT64_C(1099511628211); }
    return hash;
}
static FILE *route_capture_open_exclusive(const char *path)
{ (void)path; return (FILE *)&sink; }
static size_t sink_write(const void *data, size_t size, size_t count, FILE *file)
{
    if (file != (FILE *)&sink || size != 1 || count != 4 ||
        captured_size + count > sizeof(captured)) return 0;
    memcpy(captured + captured_size, data, count);
    captured_size += count;
    return count;
}
static int sink_close(FILE *file) { return file == (FILE *)&sink ? 0 : -1; }
static SDL_Surface *observed_readback(SDL_Renderer *renderer, const SDL_Rect *crop)
{
    SDL_Surface *result = SDL_RenderReadPixels(renderer, crop);
    requested = *crop; ++readbacks;
    returned_w = result ? result->w : -1;
    returned_h = result ? result->h : -1;
    return result;
}
#define SDL_RenderReadPixels observed_readback
#define fwrite sink_write
#define fclose sink_close
#include "renderer_capture_impl.h"
#undef SDL_RenderReadPixels
#undef fwrite
#undef fclose

static int check_case(int width, int height, const uint8_t *canonical, uint64_t expected_hash)
{
    SDL_Surface *output = SDL_CreateSurface(width, height, SDL_PIXELFORMAT_RGBA32);
    SDL_Surface *image = NULL;
    SDL_Renderer *renderer = NULL;
    SDL_Texture *texture = NULL;
    SDL_FRect logical = {0};
    runner r = {0};
    int passed = 0, result = 0;
    if (!output) goto cleanup;
    renderer = SDL_CreateSoftwareRenderer(output);
    if (!renderer) goto cleanup;
    if (!SDL_SetRenderLogicalPresentation(renderer, 320, 224,
            SDL_LOGICAL_PRESENTATION_INTEGER_SCALE)) goto cleanup;
    image = SDL_CreateSurface(320, 224, SDL_PIXELFORMAT_RGBA32);
    if (!image) goto cleanup;
    for (unsigned y = 0; y < 224; ++y) for (unsigned x = 0; x < 320; ++x) {
        uint8_t *p = (uint8_t *)image->pixels + y * (size_t)image->pitch + x * 4u;
        p[0] = (uint8_t)x; p[1] = (uint8_t)y; p[2] = (uint8_t)(x ^ y); p[3] = 255;
    }
    texture = SDL_CreateTextureFromSurface(renderer, image);
    if (!texture || !SDL_SetTextureScaleMode(texture, SDL_SCALEMODE_NEAREST) ||
        !SDL_SetTextureBlendMode(texture, SDL_BLENDMODE_NONE) ||
        !SDL_SetRenderDrawColor(renderer, 239, 17, 193, 255) ||
        !SDL_RenderClear(renderer) || !SDL_RenderTexture(renderer, texture, NULL, NULL) ||
        !SDL_GetRenderLogicalPresentationRect(renderer, &logical)) goto cleanup;
    captured_size = 0; returned_w = returned_h = -1; readbacks = 0;
    r.renderer = renderer; r.route_renderer_capture_path = "memory-only";
    r.route_renderer_capture_field = 7;
    result = route_capture_renderer_target(&r, 7);
    passed = result == 1 && r.route_renderer_capture_done && !r.route_first_failure &&
        r.route_capture_first_failure == CAPTURE_NONE && readbacks == 1 &&
        requested.x == (int)logical.x && requested.y == (int)logical.y &&
        requested.w == (int)logical.w && requested.h == (int)logical.h &&
        returned_w == requested.w && returned_h == requested.h &&
        captured_size == sizeof(captured) &&
        memcmp(captured, canonical, sizeof(captured)) == 0 &&
        r.route_renderer_capture_hash == expected_hash;
    printf("%s output=%dx%d logical=%.1f,%.1f,%.1f,%.1f crop=%d,%d,%d,%d "
           "returned=%dx%d stage=%d bytes=%zu hash=%016llx\n",
        passed ? "PASS" : "FAIL", width, height,
        logical.x, logical.y, logical.w, logical.h,
        requested.x, requested.y, requested.w, requested.h,
        returned_w, returned_h, (int)r.route_capture_first_failure, captured_size,
        (unsigned long long)r.route_renderer_capture_hash);
cleanup:
    if (!renderer || !texture) fprintf(stderr, "SDL setup failed: %s\n", SDL_GetError());
    SDL_DestroyTexture(texture);
    SDL_DestroyRenderer(renderer);
    SDL_DestroySurface(image);
    SDL_DestroySurface(output);
    return passed;
}
int main(void)
{
    static uint8_t canonical[sizeof(captured)];
    const int dimensions[][2] = {
        {640, 448}, {641, 449}, {641, 448}, {640, 449},
        {960, 672}, {961, 673}, {961, 672}, {960, 673},
        {1280, 896}, {1281, 897}, {1281, 896}, {1280, 897}
    };
    int failed = 0;
    for (unsigned y = 0; y < 224; ++y) for (unsigned x = 0; x < 320; ++x) {
        uint8_t *p = canonical + (y * 320u + x) * 4u;
        p[0] = (uint8_t)(x ^ y); p[1] = (uint8_t)y; p[2] = (uint8_t)x; p[3] = 0;
    }
    uint64_t expected_hash = route_hash_bytes(0, canonical, sizeof(canonical));
    printf("SDL=%d canonical_hash=%016llx\n", SDL_GetVersion(), (unsigned long long)expected_hash);
    for (size_t i = 0; i < sizeof(dimensions) / sizeof(dimensions[0]); ++i)
        if (!check_case(dimensions[i][0], dimensions[i][1], canonical, expected_hash)) ++failed;
    printf("real SDL software capture: %d failed\n", failed);
    return failed ? 1 : 0;
}
