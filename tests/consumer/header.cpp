// SPDX-License-Identifier: MIT
#include <genewhip/genewhip.h>
int main()
{
    gw_config config = {};
    config.struct_size = sizeof(config);
    config.version = GW_API_VERSION;
    config.profile = GW_PROFILE_VA3_NTSC_U;
    config.reset_policy = GW_RESET_DETERMINISTIC_ZERO;
    gw_machine *machine = nullptr;
    gw_video_field field = {};
    const uint32_t *pixels = nullptr;
    gw_status (*query)(const gw_machine *, gw_video_field *, const uint32_t **) = &gw_get_video_field;
    gw_run_result run = {};
    gw_event event = {};
    gw_audio_read_result audio_result = {};
    gw_audio_write audio_write = {};
    gw_status (*audio_read)(gw_machine *, int16_t *, uint32_t, gw_audio_read_result *) = &gw_audio_read;
    gw_status (*configure_trace)(gw_machine *, size_t) = &gw_configure_audio_trace;
    gw_status (*get_writes)(const gw_machine *, gw_audio_write *, size_t, size_t *, uint64_t *) =
        &gw_get_audio_writes;
    run.flags = GW_RUN_CONTINUE_PAST_FIELD;
    event.type = GW_EVENT_PAD_STATE;
    (void)field; (void)pixels; (void)query; (void)run; (void)event;
    (void)audio_result; (void)audio_write; (void)audio_read; (void)configure_trace; (void)get_writes;
    if (gw_api_version() != GW_API_VERSION || gw_create(&config, &machine) != GW_OK) return 1;
    gw_destroy(machine);
    return 0;
}
