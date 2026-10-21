# SPDX-License-Identifier: MIT
# Opt-in desktop runner: pinned static SDL3 (zlib license), desktop only.
# Included from the root CMakeLists.txt only when GENEWHIP_BUILD_DESKTOP is ON,
# so a default configure never loads FetchContent or touches the network.
include(FetchContent)

set(GENEWHIP_SDL3_ARCHIVE "" CACHE FILEPATH
  "Optional local copy of SDL3-3.4.18.tar.gz; the pinned SHA-256 is still enforced")

set(GW_SDL3_URL "https://github.com/libsdl-org/SDL/releases/download/release-3.4.18/SDL3-3.4.18.tar.gz")
if(GENEWHIP_SDL3_ARCHIVE)
  set(GW_SDL3_URL "${GENEWHIP_SDL3_ARCHIVE}")
endif()

set(SDL_SHARED OFF CACHE BOOL "" FORCE)
set(SDL_STATIC ON CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY OFF CACHE BOOL "" FORCE)
set(SDL_TESTS OFF CACHE BOOL "" FORCE)
set(SDL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
# SDL audio stays enabled: Phase 3 needs it.

FetchContent_Declare(SDL3
  URL "${GW_SDL3_URL}"
  URL_HASH SHA256=9c75cf16330322c217dedd2e0609f1124f1b54b8633e763467b4684d0f4334a3
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(SDL3)

add_subdirectory(tools/desktop)
