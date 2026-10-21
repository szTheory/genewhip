# SPDX-License-Identifier: MIT
# Thin SDL3 shell. Every core interaction goes through gw_session.
add_executable(genewhip_desktop main_sdl.c audio.c)
set_target_properties(genewhip_desktop PROPERTIES OUTPUT_NAME genewhip-desktop
  C_STANDARD 17 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
target_link_libraries(genewhip_desktop PRIVATE gw_session SDL3::SDL3-static)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(genewhip_desktop PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
endif()
