/* SPDX-License-Identifier: MIT
 * Private implementation shared with the offline branch harness. Requires the
 * runner, SDL operations, exclusive opener and hash helper from its includer.
 * No runtime injection hooks or changes to route timing/acceptance are added.
 */
#include <limits.h>
static void route_mark_capture_failure(runner *r, route_capture_substage substage)
{
    if (r->route_first_failure == ROUTE_FAILURE_NONE) {
        r->route_capture_first_failure = substage;
        route_mark_failure(r, ROUTE_FAILURE_RENDERER_CAPTURE);
    }
}

/* Capture one field from the renderer's actual target. SDL3 logical presentation
 * returns the destination rectangle in output pixels; nearest sampling maps
 * the integer-scaled renderer image back to the 320x224 core coordinate grid. */
static int route_capture_renderer_target(runner *r, uint64_t field_sequence)
{
    SDL_FRect logical;
    SDL_Rect crop;
    SDL_Surface *surface;
    uint8_t *rgba;
    size_t rgba_bytes;
    FILE *out;
    uint64_t hash = 0;
    if (!r->route_renderer_capture_path || r->route_renderer_capture_done ||
        field_sequence != r->route_renderer_capture_field) return 1;
    if (!SDL_GetRenderLogicalPresentationRect(r->renderer, &logical)) {
        route_mark_capture_failure(r, CAPTURE_LOGICAL_QUERY); return 0;
    }
    /* SDL floors the viewport origin and clips readback to that viewport.
     * Rounding a half-pixel origin upward shifts the crop and loses an edge.
     * Validate before converting; truncation equals floor for these origins. */
    if (!(logical.x >= 0.0f && logical.y >= 0.0f &&
          logical.w >= 320.0f && logical.h >= 224.0f &&
          logical.x < (float)INT_MAX && logical.y < (float)INT_MAX &&
          logical.w < (float)INT_MAX && logical.h < (float)INT_MAX)) {
        route_mark_capture_failure(r, CAPTURE_CROP); return 0;
    }
    crop.x = (int)logical.x;
    crop.y = (int)logical.y;
    crop.w = (int)(logical.w + 0.5f);
    crop.h = (int)(logical.h + 0.5f);
    if (crop.x < 0 || crop.y < 0 || crop.w < 320 || crop.h < 224) {
        route_mark_capture_failure(r, CAPTURE_CROP); return 0;
    }
    surface = SDL_RenderReadPixels(r->renderer, &crop);
    if (!surface) {
        route_mark_capture_failure(r, CAPTURE_READBACK); return 0;
    }
    if (!surface->pixels || surface->w != crop.w || surface->h != crop.h) {
        if (surface) SDL_DestroySurface(surface);
        route_mark_capture_failure(r, CAPTURE_SURFACE_SHAPE);
        return 0;
    }
    if ((size_t)crop.w > SIZE_MAX / 4u / (size_t)crop.h) {
        SDL_DestroySurface(surface);
        route_mark_capture_failure(r, CAPTURE_SIZE);
        return 0;
    }
    rgba_bytes = (size_t)crop.w * (size_t)crop.h * 4u;
    if (rgba_bytes > 80u * 1024u * 1024u) {
        SDL_DestroySurface(surface); route_mark_capture_failure(r, CAPTURE_SIZE); return 0;
    }
    rgba = (uint8_t *)SDL_malloc(rgba_bytes);
    if (!rgba) { SDL_DestroySurface(surface); route_mark_capture_failure(r, CAPTURE_ALLOCATION); return 0; }
    if (!SDL_ConvertPixels(surface->w, surface->h, surface->format, surface->pixels,
            surface->pitch, SDL_PIXELFORMAT_RGBA32, rgba, crop.w * 4)) {
        SDL_free(rgba);
        SDL_DestroySurface(surface);
        route_mark_capture_failure(r, CAPTURE_CONVERSION);
        return 0;
    }
    out = route_capture_open_exclusive(r->route_renderer_capture_path);
    if (!out) {
        SDL_free(rgba); SDL_DestroySurface(surface);
        route_mark_capture_failure(r, CAPTURE_EXCLUSIVE_OPEN); return 0;
    }
    for (unsigned y = 0; y < 224; ++y) {
        unsigned sy = (unsigned)(((uint64_t)(2u * y + 1u) * (unsigned)crop.h) / (2u * 224u));
        for (unsigned x = 0; x < 320; ++x) {
            unsigned sx = (unsigned)(((uint64_t)(2u * x + 1u) * (unsigned)crop.w) / (2u * 320u));
            const uint8_t *pixel = rgba + ((size_t)sy * (unsigned)crop.w + sx) * 4u;
            uint8_t serialized[4] = {pixel[2], pixel[1], pixel[0], 0};
            hash = route_hash_bytes(hash, serialized, sizeof(serialized));
            if (fwrite(serialized, 1, sizeof(serialized), out) != sizeof(serialized)) {
                (void)fclose(out); SDL_free(rgba); SDL_DestroySurface(surface);
                route_mark_capture_failure(r, CAPTURE_WRITE); return 0;
            }
        }
    }
    if (fclose(out) != 0) {
        SDL_free(rgba); SDL_DestroySurface(surface);
        route_mark_capture_failure(r, CAPTURE_CLOSE); return 0;
    }
    SDL_free(rgba);
    SDL_DestroySurface(surface);
    r->route_renderer_capture_done = 1;
    r->route_renderer_capture_hash = hash;
    return 1;
}

