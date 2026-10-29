/* SPDX-License-Identifier: MIT */
#include <genewhip/genewhip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FIELDS UINT64_C(4)
#define TEST_RATE UINT32_C(48000)

typedef struct observation {
    gw_diagnostic_record diagnostics;
    uint8_t ram[GW_RAM_SIZE];
    uint64_t pcm_hash;
    uint32_t pcm_frames;
    uint64_t video_hash;
    uint32_t video_fields;
    uint64_t final_tick;
} observation;

static uint64_t hash_byte(uint64_t h, uint8_t b)
{
    return (h ^ b) * UINT64_C(1099511628211);
}

static uint64_t hash_bytes(uint64_t h, const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < size; ++i) h = hash_byte(h, bytes[i]);
    return h;
}

static int schedule(gw_machine *m, uint64_t tick, uint32_t type,
    uint32_t port, uint32_t mask)
{
    gw_event event;
    memset(&event, 0, sizeof(event));
    event.struct_size = sizeof(event);
    event.version = GW_API_VERSION;
    event.tick = tick;
    event.type = type;
    event.port = port;
    event.mask = mask;
    return gw_schedule_event(m, &event) == GW_OK ? 0 : 1;
}

static int schedule_inputs_and_reset(gw_machine *m)
{
    /* Same-tick insertion order and same-value observations are deliberate. */
    return schedule(m, 10000, GW_EVENT_PAD_STATE, 0, GW_BUTTON_A) ||
        schedule(m, 10000, GW_EVENT_PAD_STATE, 0, GW_BUTTON_A) ||
        schedule(m, 10000, GW_EVENT_PAD_STATE, 1, GW_BUTTON_START) ||
        schedule(m, 900000, GW_EVENT_PAD_STATE, 0, GW_BUTTON_RIGHT) ||
        schedule(m, 1800000, GW_EVENT_CONSOLE_RESET, 0, 0) ||
        schedule(m, 2200000, GW_EVENT_PAD_STATE, 1, 0) ||
        schedule(m, 2700000, GW_EVENT_PAD_STATE, 0, GW_BUTTON_A | GW_BUTTON_C);
}

static int read_snapshot(gw_machine *m, observation *out)
{
    gw_audio_read_result audio;
    int16_t pcm[GW_AUDIO_QUEUE_FRAMES][2];
    out->diagnostics.struct_size = sizeof(out->diagnostics);
    out->diagnostics.version = GW_API_VERSION;
    if (gw_get_diagnostics(m, &out->diagnostics) != GW_OK ||
        gw_peek_memory(m, UINT32_C(0x00ff0000), out->ram, sizeof(out->ram)) != GW_OK)
        return 1;

    memset(&audio, 0, sizeof(audio));
    audio.struct_size = sizeof(audio);
    audio.version = GW_API_VERSION;
    if (gw_audio_read(m, &pcm[0][0], GW_AUDIO_QUEUE_FRAMES, &audio) != GW_OK ||
        audio.lost != 0 || audio.produced > GW_AUDIO_QUEUE_FRAMES ||
        audio.first_index != 0)
        return 1;
    out->pcm_hash = hash_bytes(out->pcm_hash, pcm,
        (size_t)audio.produced * sizeof(pcm[0]));
    out->pcm_frames = audio.produced;
    out->final_tick = out->diagnostics.tick;
    return 0;
}

static int capture_new_field(gw_machine *m, observation *out, uint64_t *previous_sequence)
{
    gw_video_field field;
    const uint32_t *pixels = NULL;
    memset(&field, 0, sizeof(field));
    field.struct_size = sizeof(field);
    field.version = GW_API_VERSION;
    if (gw_get_video_field(m, &field, &pixels) == GW_ERROR_EMPTY) return 0;
    if (!pixels || field.width == 0 || field.height == 0 ||
        field.pitch_bytes < (size_t)field.width * sizeof(*pixels)) return 1;
    if (field.sequence == *previous_sequence) return 0;
    if (field.sequence != out->video_fields) return 1;
    out->video_hash = hash_bytes(out->video_hash, &field.sequence, sizeof(field.sequence));
    for (uint32_t y = 0; y < field.height; ++y)
        out->video_hash = hash_bytes(out->video_hash,
            (const uint8_t *)pixels + (size_t)y * field.pitch_bytes,
            (size_t)field.width * sizeof(*pixels));
    ++out->video_fields;
    *previous_sequence = field.sequence;
    return 0;
}

static int run_variant(int variable, observation *out)
{
    static const uint8_t program[] = {
        0x13,0xfc,0x00,0x5a,0xe0,0xff,0x00,0x59,
        0x13,0xfc,0x00,0x40,0x00,0xa1,0x00,0x09,
        0x13,0xfc,0x00,0x40,0x00,0xa1,0x00,0x03,
        0x33,0xfc,0x00,0x01,0x00,0xff,0x00,0x00,
        0x10,0x39,0x00,0xa1,0x00,0x03,
        0x08,0x00,0x00,0x03,0x67,0x0a,
        0x33,0xfc,0x00,0x03,0x00,0xff,0x00,0x00,0x60,0xea,
        0x33,0xfc,0x00,0x02,0x00,0xff,0x00,0x00,0x60,0xe0
    };
    uint8_t rom[512 + sizeof(program)];
    gw_config config = {sizeof(gw_config), GW_API_VERSION, GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO, 1, {GW_DEVICE_PAD3, GW_DEVICE_PAD3}, TEST_RATE};
    gw_machine *machine = NULL;
    uint64_t current = 0, requested = TEST_FIELDS * GW_FIELD_TICKS;
    uint64_t iteration = 0, previous_sequence = UINT64_MAX;
    int failed = 0;
    memset(out, 0, sizeof(*out));
    out->pcm_hash = UINT64_C(14695981039346656037);
    out->video_hash = UINT64_C(14695981039346656037);
    memset(rom, 0, sizeof(rom));
    rom[0] = 0x00; rom[1] = 0xff; rom[2] = 0x00; rom[3] = 0x00;
    rom[4] = 0x00; rom[5] = 0x00; rom[6] = 0x02; rom[7] = 0x00;
    memcpy(rom + 512, program, sizeof(program));
    if (gw_create(&config, &machine) != GW_OK ||
        gw_load_rom(machine, rom, sizeof(rom)) != GW_OK ||
        schedule_inputs_and_reset(machine) != 0) {
        fputs("phase6 chunk contract: setup/input scheduling failed\n", stderr);
        failed = 1;
        goto done;
    }
    {
        gw_diagnostic_record diagnostic;
        memset(&diagnostic, 0, sizeof(diagnostic));
        diagnostic.struct_size = sizeof(diagnostic);
        diagnostic.version = GW_API_VERSION;
        if (gw_get_diagnostics(machine, &diagnostic) != GW_OK) {
            failed = 1;
            goto done;
        }
        current = diagnostic.tick;
    }
    while (current < requested - UINT64_C(1000)) {
        gw_run_result result;
        uint64_t increment = variable ? UINT64_C(1) + ((iteration++ * 17u) % 47u) : 1u;
        uint64_t target = current + increment;
        if (target > requested - UINT64_C(1000)) target = requested - UINT64_C(1000);
        memset(&result, 0, sizeof(result));
        result.struct_size = sizeof(result);
        result.version = GW_API_VERSION;
        result.flags = GW_RUN_CONTINUE_PAST_FIELD;
        if (gw_run_until(machine, target, &result) != GW_OK ||
            result.requested_tick != target || result.actual_tick < target ||
            result.overshoot_ticks != result.actual_tick - target ||
            result.stop_reason != GW_STOP_TARGET || result.actual_tick <= current) {
            fputs("phase6 chunk contract: run result/overshoot contract failed\n", stderr);
            failed = 1;
            goto done;
        }
        current = result.actual_tick;
        if (current > requested) {
            fputs("phase6 chunk contract: bounded chunk crossed final synchronization window\n", stderr);
            failed = 1;
            goto done;
        }

        /* Hash every newly completed field immediately; the pixel pointer is borrowed. */
        if (capture_new_field(machine, out, &previous_sequence) != 0) {
            failed = 1;
            goto done;
        }
    }
    /* Both variants end on the same instruction boundary selected by the exact
     * final target; varied calls remain varied up to this synchronization point. */
    {
        gw_run_result result;
        memset(&result, 0, sizeof(result));
        result.struct_size = sizeof(result);
        result.version = GW_API_VERSION;
        result.flags = GW_RUN_CONTINUE_PAST_FIELD;
        if (gw_run_until(machine, requested, &result) != GW_OK ||
            result.actual_tick < requested ||
            result.overshoot_ticks != result.actual_tick - requested ||
            result.stop_reason != GW_STOP_TARGET) {
            fputs("phase6 chunk contract: final synchronization run failed\n", stderr);
            failed = 1;
            goto done;
        }
        if (capture_new_field(machine, out, &previous_sequence) != 0) {
            fputs("phase6 chunk contract: final field capture failed\n", stderr);
            failed = 1;
            goto done;
        }
    }
    if (read_snapshot(machine, out) != 0 || out->diagnostics.stop_reason != GW_STOP_TARGET ||
        out->diagnostics.instructions == 0 || out->video_fields != TEST_FIELDS) {
        fputs("phase6 chunk contract: final full-state/media capture failed\n", stderr);
        failed = 1;
    }
done:
    gw_destroy(machine);
    return failed;
}

typedef struct title_input { uint64_t tick; uint32_t port, mask; } title_input;

static int read_title_inputs(const char *path, title_input rows[GW_EVENT_CAPACITY], size_t *count)
{
    FILE *file=fopen(path,"r"); unsigned long long tick; unsigned port,mask; char tail;
    if(!file)return 1;
    *count=0;
    while(fscanf(file,"%llu,%u,%u%c",&tick,&port,&mask,&tail)==4) {
        if(tail!='\n' || *count>=GW_EVENT_CAPACITY || port>1 || mask>GW_BUTTON_MASK_PAD3) {
            fclose(file);return 1;
        }
        rows[*count]=(title_input){(uint64_t)tick,(uint32_t)port,(uint32_t)mask};++*count;
    }
    if(ferror(file) || fclose(file)!=0 || *count==0)return 1;
    return 0;
}

static int load_title_rom(const char *path,uint8_t **bytes,size_t *size)
{
    FILE *file=fopen(path,"rb"); long length;
    if(!file)return 1;
    if(fseek(file,0,SEEK_END)!=0 || (length=ftell(file))<514 || length>GW_MAX_ROM_SIZE ||
       fseek(file,0,SEEK_SET)!=0) {fclose(file);return 1;}
    *size=(size_t)length;*bytes=(uint8_t*)malloc(*size);
    if(!*bytes || fread(*bytes,1,*size,file)!=*size || fclose(file)!=0) {free(*bytes);*bytes=NULL;return 1;}
    return 0;
}

typedef struct title_runner {
    gw_machine *machine;
    uint64_t current,iterations,calls;
    int cpu_stopped,variable,instruction_step;
    size_t next_input;
} title_runner;

static int diagnostics_equal(const gw_diagnostic_record *a,const gw_diagnostic_record *b)
{
    return a->tick==b->tick && a->profile==b->profile && a->pc==b->pc && a->sr==b->sr &&
        memcmp(a->d,b->d,sizeof(a->d))==0 && memcmp(a->a,b->a,sizeof(a->a))==0 &&
        a->initial_ssp==b->initial_ssp && a->initial_pc==b->initial_pc &&
        a->stop_reason==b->stop_reason && a->diagnostics_enabled==b->diagnostics_enabled &&
        a->instructions==b->instructions && a->exceptions==b->exceptions &&
        a->exception_returns==b->exception_returns && a->external_resets==b->external_resets;
}

static int advance_runner(title_runner *runner,uint64_t target,const title_input *inputs,
    size_t input_count,uint64_t call_limit)
{
    while(runner->current<target) {
        uint64_t requested;
        if(runner->cpu_stopped) {
            requested=runner->current+308;
            if(requested>target)requested=target;
            while(runner->next_input<input_count && inputs[runner->next_input].tick<=runner->current)
                ++runner->next_input;
            if(runner->next_input<input_count && inputs[runner->next_input].tick>runner->current &&
               requested>inputs[runner->next_input].tick)requested=inputs[runner->next_input].tick;
        } else if(runner->variable) {
            uint64_t stride=1+(runner->iterations++*37u)%4096u;
            requested=runner->current+stride;if(requested>target)requested=target;
        } else if(runner->instruction_step) {
            requested=runner->current+1;if(requested>target)requested=target;
        } else {
            requested=runner->current+4096;if(requested>target)requested=target;
        }
        gw_run_result run={0};run.struct_size=sizeof(run);run.version=GW_API_VERSION;
        run.flags=GW_RUN_CONTINUE_PAST_FIELD;
        if(runner->calls>=call_limit)return 1;
        if(gw_run_until(runner->machine,requested,&run)!=GW_OK || run.requested_tick!=requested ||
           run.actual_tick<requested || run.overshoot_ticks!=run.actual_tick-requested ||
           (run.stop_reason!=GW_STOP_TARGET && run.stop_reason!=GW_STOP_CPU_STOPPED) ||
           run.actual_tick<=runner->current)return 1;
        ++runner->calls;
        runner->current=run.actual_tick;runner->cpu_stopped=run.stop_reason==GW_STOP_CPU_STOPPED;
    }
    return 0;
}

static int compare_diagnostic_segment(title_runner *left,title_runner *right,
    uint64_t *compared_events,uint64_t *dropped_events)
{
    gw_diagnostic_event events[2][GW_DIAGNOSTIC_CAPACITY];size_t count[2]={0,0};
    uint64_t dropped[2]={0,0};
    if(gw_get_diagnostic_events(left->machine,events[0],GW_DIAGNOSTIC_CAPACITY,&count[0],&dropped[0])!=GW_OK ||
       gw_get_diagnostic_events(right->machine,events[1],GW_DIAGNOSTIC_CAPACITY,&count[1],&dropped[1])!=GW_OK ||
       dropped[0]!=0 || dropped[1]!=0 || count[0]!=count[1])return 1;
    for(size_t i=0;i<count[0];++i)
        if(events[0][i].tick!=events[1][i].tick ||
           events[0][i].instruction_address!=events[1][i].instruction_address ||
           events[0][i].opcode!=events[1][i].opcode ||
           events[0][i].stop_reason!=events[1][i].stop_reason ||
           events[0][i].fault_address!=events[1][i].fault_address)return 1;
    *compared_events+=count[0];*dropped_events+=dropped[0];return 0;
}

static int title_pair(const uint8_t *rom,size_t rom_size,const title_input *inputs,size_t input_count,
    uint64_t field_count,uint64_t call_limit,uint64_t media_sequence,uint64_t terminal_tick,uint64_t calls[2],
    uint64_t *pcm_frames,uint64_t *pcm_hash,uint64_t *media_hash,uint64_t *ram_hash,
    uint64_t *diagnostic_hash,uint64_t *final_instructions,uint32_t *final_pc,
    uint64_t *compared_events,uint64_t *dropped_events,uint64_t *trace_segments,
    uint64_t *terminal_actual)
{
    gw_config config={sizeof(gw_config),GW_API_VERSION,GW_PROFILE_VA3_NTSC_U,
        GW_RESET_DETERMINISTIC_ZERO,1,{GW_DEVICE_PAD3,GW_DEVICE_PAD3},48000};
    title_runner runner[2]={{0},{0}};uint8_t *ram[2]={NULL,NULL};
    int failed=0;const char *failure="unknown";
    int media_seen=0;
    uint64_t pcm_index=0,hpcm=UINT64_C(14695981039346656037),
        hram=UINT64_C(14695981039346656037),hdiag=UINT64_C(14695981039346656037),hmedia=0,
        instruction_total=0;
    calls[0]=calls[1]=0;*pcm_frames=*pcm_hash=*media_hash=*ram_hash=*diagnostic_hash=0;
    *final_instructions=*compared_events=*dropped_events=*trace_segments=*terminal_actual=0;*final_pc=0;
    if(field_count==0 || terminal_tick==UINT64_MAX ||
       terminal_tick<(field_count-1)*GW_FIELD_TICKS+(uint64_t)GW_ACTIVE_LINES*GW_LINE_TICKS) {
        failure="terminal-tick-range";failed=1;goto done;
    }
    for(unsigned instance=0;instance<2;++instance) {
        runner[instance].variable=(instance==1);
        runner[instance].instruction_step=(instance==0 && call_limit>=UINT64_C(100000000));
        if(gw_create(&config,&runner[instance].machine)!=GW_OK ||
           gw_load_rom(runner[instance].machine,rom,rom_size)!=GW_OK) {
            failure="create-or-load";failed=1;goto done;
        }
        ram[instance]=(uint8_t*)malloc(GW_RAM_SIZE);
        if(!ram[instance]){failure="ram-allocation";failed=1;goto done;}
        gw_diagnostic_record initial={0};initial.struct_size=sizeof(initial);initial.version=GW_API_VERSION;
        if(gw_get_diagnostics(runner[instance].machine,&initial)!=GW_OK) {
            failure="initial-diagnostics";failed=1;goto done;
        }
        runner[instance].current=initial.tick;
        for(size_t i=0;i<input_count;++i) {
            gw_event event={sizeof(event),GW_API_VERSION,inputs[i].tick,GW_EVENT_PAD_STATE,
                inputs[i].port,inputs[i].mask,0};
            if(gw_schedule_event(runner[instance].machine,&event)!=GW_OK) {
                failure="schedule-input";failed=1;goto done;
            }
        }
    }
    for(uint64_t field=0;field<field_count && !failed;++field) {
        uint64_t target=field*GW_FIELD_TICKS+(uint64_t)GW_ACTIVE_LINES*GW_LINE_TICKS;
        /* Short diagnostic windows retain every attempted instruction, including
         * repeated same-value source markers, without overflowing the public ring. */
        while(runner[0].current<target && !failed) {
            uint64_t segment_end=runner[0].current+4096;
            if(segment_end>target)segment_end=target;
            for(unsigned instance=0;instance<2;++instance) {
                uint64_t other_calls=runner[1-instance].calls;
                if(other_calls>=call_limit || advance_runner(&runner[instance],segment_end,
                    inputs,input_count,call_limit-other_calls)) {
                    failure="run-target-or-call-cap";failed=1;break;
                }
            }
            if(failed)break;
            gw_diagnostic_record diag[2]={{0},{0}};
            for(unsigned instance=0;instance<2;++instance) {
                diag[instance].struct_size=sizeof(diag[instance]);diag[instance].version=GW_API_VERSION;
                if(gw_get_diagnostics(runner[instance].machine,&diag[instance])!=GW_OK) {
                    failure="segment-diagnostics";failed=1;break;
                }
            }
            if(failed)break;
            if(!diagnostics_equal(&diag[0],&diag[1]) ||
               compare_diagnostic_segment(&runner[0],&runner[1],compared_events,dropped_events)) {
                failure="instruction-event-sequence";failed=1;break;
            }
            ++*trace_segments;
            instruction_total+=diag[1].instructions;
            for(unsigned instance=0;instance<2;++instance)
                if(gw_configure_diagnostics(runner[instance].machine,GW_DIAGNOSTIC_CAPACITY)!=GW_OK) {
                    failure="diagnostic-window-reset";failed=1;break;
                }
        }
        if(failed)break;
        gw_diagnostic_record diag[2]={{0},{0}};gw_video_field video[2]={{0},{0}};
        const uint32_t *pixels[2]={NULL,NULL};gw_audio_read_result audio[2]={{0},{0}};
        int16_t pcm[2][GW_AUDIO_QUEUE_FRAMES][2];
        for(unsigned instance=0;instance<2;++instance) {
            diag[instance].struct_size=sizeof(diag[instance]);diag[instance].version=GW_API_VERSION;
            video[instance].struct_size=sizeof(video[instance]);video[instance].version=GW_API_VERSION;
            audio[instance].struct_size=sizeof(audio[instance]);audio[instance].version=GW_API_VERSION;
            if(gw_get_diagnostics(runner[instance].machine,&diag[instance])!=GW_OK ||
               gw_peek_memory(runner[instance].machine,UINT32_C(0x00ff0000),ram[instance],GW_RAM_SIZE)!=GW_OK ||
               gw_get_video_field(runner[instance].machine,&video[instance],&pixels[instance])!=GW_OK || !pixels[instance] ||
               gw_audio_read(runner[instance].machine,&pcm[instance][0][0],GW_AUDIO_QUEUE_FRAMES,&audio[instance])!=GW_OK ||
               audio[instance].lost!=0 || audio[instance].first_index!=pcm_index ||
               audio[instance].produced>GW_AUDIO_QUEUE_FRAMES || video[instance].sequence!=field ||
               video[instance].end_tick>target+8192) {failure="boundary-capture";failed=1;break;}
        }
        if(failed)break;
        if(!diagnostics_equal(&diag[0],&diag[1]) || memcmp(ram[0],ram[1],GW_RAM_SIZE)!=0 ||
           video[0].pixel_format!=video[1].pixel_format || video[0].width!=video[1].width ||
           video[0].height!=video[1].height || video[0].pitch_bytes!=video[1].pitch_bytes ||
           video[0].start_tick!=video[1].start_tick || video[0].end_tick!=video[1].end_tick ||
           video[0].sequence!=video[1].sequence || video[0].flags!=video[1].flags ||
           memcmp(video[0].reserved,video[1].reserved,sizeof(video[0].reserved))!=0 ||
           audio[0].first_index!=audio[1].first_index || audio[0].lost!=audio[1].lost ||
           audio[0].clipped!=audio[1].clipped || audio[0].produced!=audio[1].produced ||
           audio[0].flags!=audio[1].flags || audio[0].mix_id!=audio[1].mix_id ||
           audio[0].filter_id!=audio[1].filter_id ||
           memcmp(audio[0].reserved,audio[1].reserved,sizeof(audio[0].reserved))!=0 ||
           memcmp(pcm[0],pcm[1],(size_t)audio[0].produced*sizeof(pcm[0][0]))!=0) {
            failure="common-boundary-state";failed=1;break;
        }
        for(uint32_t y=0;y<video[0].height;++y) {
            const uint8_t *left=(const uint8_t*)pixels[0]+(size_t)y*video[0].pitch_bytes;
            const uint8_t *right=(const uint8_t*)pixels[1]+(size_t)y*video[1].pitch_bytes;
            if(memcmp(left,right,(size_t)video[0].width*sizeof(uint32_t))!=0) {
                failure="common-boundary-video";failed=1;break;
            }
            if(video[1].sequence==media_sequence) {
                if(y==0){hmedia=UINT64_C(14695981039346656037);media_seen=1;}
                hmedia=hash_bytes(hmedia,right,(size_t)video[1].width*sizeof(uint32_t));
            }
        }
        if(failed)break;
        for(size_t i=0;i<GW_RAM_SIZE;++i)hram=hash_byte(hram,ram[1][i]);
        hdiag=hash_bytes(hdiag,&diag[1].tick,sizeof(diag[1].tick));
        hdiag=hash_bytes(hdiag,&diag[1].pc,sizeof(diag[1].pc));
        hdiag=hash_bytes(hdiag,&diag[1].sr,sizeof(diag[1].sr));
        hdiag=hash_bytes(hdiag,diag[1].d,sizeof(diag[1].d));
        hdiag=hash_bytes(hdiag,diag[1].a,sizeof(diag[1].a));
        hdiag=hash_bytes(hdiag,&diag[1].instructions,sizeof(diag[1].instructions));
        hpcm=hash_bytes(hpcm,pcm[1],(size_t)audio[1].produced*sizeof(pcm[1][0]));
        *pcm_frames+=audio[1].produced;pcm_index+=audio[1].produced;
        *final_instructions=instruction_total;*final_pc=diag[1].pc;
    }
    /* The terminal source marker can be after the last completed video field.
     * Continue both machines to that exact source tick, keeping diagnostic
     * windows bounded and comparing the full ordered instruction trace. */
    uint64_t terminal_request=terminal_tick+1;
    if(terminal_request<=runner[0].current || terminal_request<=runner[1].current) {
        uint64_t current=runner[0].current>runner[1].current?runner[0].current:runner[1].current;
        if(current==UINT64_MAX){failure="terminal-tick-overflow";failed=1;}
        else terminal_request=current+1;
    }
    while(!failed && runner[0].current<terminal_request) {
        uint64_t segment_end=runner[0].current+4096;
        if(segment_end>terminal_request)segment_end=terminal_request;
        for(unsigned instance=0;instance<2;++instance) {
            uint64_t other_calls=runner[1-instance].calls;
            if(other_calls>=call_limit || advance_runner(&runner[instance],segment_end,inputs,input_count,
                call_limit-other_calls)) {failure="terminal-run-or-call-cap";failed=1;break;}
        }
        if(failed)break;
        gw_diagnostic_record diag[2]={{0}};
        for(unsigned instance=0;instance<2;++instance) {
            diag[instance].struct_size=sizeof(diag[instance]);diag[instance].version=GW_API_VERSION;
            if(gw_get_diagnostics(runner[instance].machine,&diag[instance])!=GW_OK) {
                failure="terminal-diagnostics";failed=1;break;
            }
        }
        if(failed)break;
        if(!diagnostics_equal(&diag[0],&diag[1]) ||
           compare_diagnostic_segment(&runner[0],&runner[1],compared_events,dropped_events)) {
            failure="terminal-instruction-event-sequence";failed=1;break;
        }
        ++*trace_segments;instruction_total+=diag[1].instructions;
        for(unsigned instance=0;instance<2;++instance)
            if(gw_configure_diagnostics(runner[instance].machine,GW_DIAGNOSTIC_CAPACITY)!=GW_OK) {
                failure="terminal-diagnostic-window-reset";failed=1;break;
            }
    }
    if(!failed) {
        gw_diagnostic_record terminal[2]={{0}};uint8_t terminal_ram[2][GW_RAM_SIZE];
        for(unsigned instance=0;instance<2;++instance) {
            terminal[instance].struct_size=sizeof(terminal[instance]);terminal[instance].version=GW_API_VERSION;
            if(gw_get_diagnostics(runner[instance].machine,&terminal[instance])!=GW_OK ||
               gw_peek_memory(runner[instance].machine,UINT32_C(0x00ff0000),terminal_ram[instance],GW_RAM_SIZE)!=GW_OK) {
                failure="terminal-state-capture";failed=1;break;
            }
        }
        if(!failed && (!diagnostics_equal(&terminal[0],&terminal[1]) ||
            memcmp(terminal_ram[0],terminal_ram[1],GW_RAM_SIZE)!=0 ||
            terminal[0].tick<terminal_tick)) {failure="terminal-state-divergence";failed=1;}
        if(!failed)*terminal_actual=terminal[1].tick;
    }
    if(!failed && (runner[0].calls+runner[1].calls>call_limit)){failure="aggregate-call-cap";failed=1;}
    if(!failed && !media_seen){failure="selected-media-field";failed=1;}
    if(!failed) {
        gw_diagnostic_record final={0};final.struct_size=sizeof(final);final.version=GW_API_VERSION;
        if(gw_get_diagnostics(runner[1].machine,&final)!=GW_OK) {failure="final-diagnostics";failed=1;}
        else {*final_instructions=instruction_total;*final_pc=final.pc;}
    }
    *pcm_hash=hpcm;*ram_hash=hram;*diagnostic_hash=hdiag;*media_hash=hmedia;
    calls[0]=runner[0].calls;calls[1]=runner[1].calls;
done:
    free(ram[0]);free(ram[1]);gw_destroy(runner[0].machine);gw_destroy(runner[1].machine);
    if(failed)fprintf(stderr,"phase6 title chunk pair failure stage=%s fields=%llu baseline_calls=%llu variable_calls=%llu\n",
        failure,(unsigned long long)field_count,(unsigned long long)runner[0].calls,
        (unsigned long long)runner[1].calls);
    return failed;
}

static int run_title_chunk_equivalence(const char *rom_path,const char *input_path,
    uint64_t fields,uint64_t call_limit,uint64_t media_sequence,uint64_t terminal_tick,const char *output_path)
{
    uint8_t *rom=NULL;size_t rom_size=0,count=0;title_input inputs[GW_EVENT_CAPACITY];
    uint64_t calls[2]={0,0},pcm_frames=0,pcm_hash=0,media_hash=0,ram_hash=0,diag_hash=0,
        final_instructions=0,compared_events=0,dropped_events=0,trace_segments=0,terminal_actual=0;
    uint32_t final_pc=0;
    if(load_title_rom(rom_path,&rom,&rom_size)!=0 || read_title_inputs(input_path,inputs,&count)!=0) {
        fputs("phase6 title chunk: bounded ROM/input load failed\n",stderr);free(rom);return 1;
    }
    for(size_t i=0;i<count;++i)if(inputs[i].tick>terminal_tick) {
        fputs("phase6 title chunk: source input exceeds terminal tick\n",stderr);free(rom);return 1;
    }
    int result=title_pair(rom,rom_size,inputs,count,fields,call_limit,media_sequence,terminal_tick,calls,
        &pcm_frames,&pcm_hash,&media_hash,&ram_hash,&diag_hash,&final_instructions,&final_pc,
        &compared_events,&dropped_events,&trace_segments,&terminal_actual);
    free(rom);
    if(result){fputs("phase6 title chunk: variable public-API run stopped, diverged or exceeded call cap\n",stderr);return 1;}
    FILE *out=fopen(output_path,"w");if(!out)return 1;
    fprintf(out,"{\"schema\":\"genewhip-phase6-title-chunk-v1\",\"status\":\"pass\",\"fields\":%llu,\"events\":%zu,\"baseline_calls\":%llu,\"variable_calls\":%llu,\"baseline_mode\":\"%s\",\"pair_comparison\":\"pass\",\"common_boundary_comparisons\":{\"ram\":%llu,\"cpu_state\":%llu,\"video\":%llu,\"pcm\":%llu},\"input_order_events_compared\":%zu,\"trace_segments\":%llu,\"compared_instruction_events\":%llu,\"instruction_events_dropped\":%llu,\"terminal_tick_target\":%llu,\"terminal_tick_actual\":%llu,\"terminal_boundary_comparison\":\"pass\",\"pcm_frames\":%llu,\"pcm_fnv1a64\":\"%016llx\",\"media_sequence\":%llu,\"media_fnv1a64\":\"%016llx\",\"boundary_ram_fnv1a64\":\"%016llx\",\"boundary_diagnostic_fnv1a64\":\"%016llx\",\"final_instructions\":%llu,\"final_pc\":%u}\n",
        (unsigned long long)fields,count,(unsigned long long)calls[0],(unsigned long long)calls[1],
        call_limit>=UINT64_C(100000000)?"one-instruction-stop308":"coarse-4096-stop308",
        (unsigned long long)fields,(unsigned long long)fields,(unsigned long long)fields,(unsigned long long)fields,
        count,(unsigned long long)trace_segments,(unsigned long long)compared_events,(unsigned long long)dropped_events,
        (unsigned long long)terminal_tick,(unsigned long long)terminal_actual,
        (unsigned long long)pcm_frames,
        (unsigned long long)pcm_hash,(unsigned long long)media_sequence,(unsigned long long)media_hash,
        (unsigned long long)ram_hash,(unsigned long long)diag_hash,(unsigned long long)final_instructions,final_pc);
    if(fclose(out)!=0)return 1;
    printf("{\"schema\":\"genewhip-phase6-title-chunk-v1\",\"status\":\"pass\",\"fields\":%llu,\"events\":%zu,\"baseline_calls\":%llu,\"variable_calls\":%llu,\"baseline_mode\":\"%s\",\"pair_comparison\":\"pass\",\"common_boundary_comparisons\":{\"ram\":%llu,\"cpu_state\":%llu,\"video\":%llu,\"pcm\":%llu},\"input_order_events_compared\":%zu,\"trace_segments\":%llu,\"compared_instruction_events\":%llu,\"instruction_events_dropped\":%llu,\"terminal_tick_target\":%llu,\"terminal_tick_actual\":%llu,\"terminal_boundary_comparison\":\"pass\",\"pcm_frames\":%llu,\"pcm_fnv1a64\":\"%016llx\",\"media_sequence\":%llu,\"media_fnv1a64\":\"%016llx\",\"boundary_ram_fnv1a64\":\"%016llx\",\"boundary_diagnostic_fnv1a64\":\"%016llx\",\"final_instructions\":%llu,\"final_pc\":%u}\n",
        (unsigned long long)fields,count,(unsigned long long)calls[0],(unsigned long long)calls[1],
        call_limit>=UINT64_C(100000000)?"one-instruction-stop308":"coarse-4096-stop308",
        (unsigned long long)fields,(unsigned long long)fields,(unsigned long long)fields,(unsigned long long)fields,
        count,(unsigned long long)trace_segments,(unsigned long long)compared_events,(unsigned long long)dropped_events,
        (unsigned long long)terminal_tick,(unsigned long long)terminal_actual,
        (unsigned long long)pcm_frames,
        (unsigned long long)pcm_hash,(unsigned long long)media_sequence,(unsigned long long)media_hash,
        (unsigned long long)ram_hash,(unsigned long long)diag_hash,(unsigned long long)final_instructions,final_pc);
    return 0;
}

int main(int argc,char **argv)
{
    if (argc == 9 && strcmp(argv[1],"--title")==0) {
        char *end=NULL;unsigned long long fields=strtoull(argv[4],&end,10);
        if(!end||*end||fields==0)return 2;
        unsigned long long calls=strtoull(argv[5],&end,10);if(!end||*end||calls==0)return 2;
        char *seqend=NULL;unsigned long long media_sequence=strtoull(argv[6],&seqend,10);
        if(!seqend||*seqend)return 2;
        char *tickend=NULL;unsigned long long terminal_tick=strtoull(argv[7],&tickend,10);
        if(!tickend||*tickend||terminal_tick==0)return 2;
        return run_title_chunk_equivalence(argv[2],argv[3],(uint64_t)fields,(uint64_t)calls,
            (uint64_t)media_sequence,(uint64_t)terminal_tick,argv[8]);
    }
    observation instruction, variable;
    int failed = 0;
    if (run_variant(0, &instruction) != 0 || run_variant(1, &variable) != 0) return 1;
    if (instruction.final_tick != variable.final_tick ||
        instruction.diagnostics.instructions != variable.diagnostics.instructions ||
        instruction.diagnostics.pc != variable.diagnostics.pc ||
        instruction.diagnostics.sr != variable.diagnostics.sr ||
        memcmp(instruction.diagnostics.d, variable.diagnostics.d, sizeof(instruction.diagnostics.d)) != 0 ||
        memcmp(instruction.diagnostics.a, variable.diagnostics.a, sizeof(instruction.diagnostics.a)) != 0 ||
        memcmp(instruction.ram, variable.ram, sizeof(instruction.ram)) != 0 ||
        instruction.pcm_hash != variable.pcm_hash || instruction.pcm_frames != variable.pcm_frames ||
        instruction.video_hash != variable.video_hash || instruction.video_fields != variable.video_fields) {
        fputs("phase6 chunk contract: execution, input/reset, RAM, video or full PCM diverged\n", stderr);
        failed = 1;
    }
    if (!failed) puts("phase6 chunk contract: pass");
    return failed;
}
