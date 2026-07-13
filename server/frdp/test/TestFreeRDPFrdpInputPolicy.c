#include "frdp-session-agent/input_policy.h"

#include <freerdp/input.h>

#include <stdio.h>
#include <string.h>

static void init_event(frdpAgentInputEvent *event, uint32_t event_type)
{
    memset(event, 0, sizeof(*event));
    event->event_type = event_type;
}

static int test_accepts_valid_events(void)
{
    frdpAgentInputEvent event;

    init_event(&event, FRDP_AGENT_INPUT_SYNC);
    event.flags = KBD_SYNC_SCROLL_LOCK | KBD_SYNC_NUM_LOCK;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_KEYBOARD);
    event.flags = KBD_FLAGS_EXTENDED | KBD_FLAGS_RELEASE;
    event.param1 = 0x1C;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_UNICODE);
    event.param1 = 0x20AC;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    event.param1 = 0xD83C;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    event.param1 = 0xDF0D;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_MOUSE);
    event.flags = PTR_FLAGS_MOVE | PTR_FLAGS_BUTTON1 | PTR_FLAGS_DOWN;
    event.param1 = 640;
    event.param2 = 480;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_REL_MOUSE);
    event.flags = PTR_FLAGS_MOVE;
    event.param1 = -8;
    event.param2 = 7;
    if (!frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_EXT_MOUSE);
    event.flags = PTR_XFLAGS_BUTTON1 | PTR_XFLAGS_DOWN;
    event.param1 = 1;
    event.param2 = 2;
    return frdp_agent_input_event_payload_is_valid(&event) ? 0 : -1;
}

static int test_rejects_unknown_types_and_flags(void)
{
    frdpAgentInputEvent event;

    init_event(&event, 0xFFFFFFFFU);
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_SYNC);
    event.flags = KBD_SYNC_SCROLL_LOCK | 0x80000000U;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_KEYBOARD);
    event.flags = PTR_FLAGS_BUTTON1;
    event.param1 = 0x1C;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_MOUSE);
    event.flags = PTR_FLAGS_WHEEL | PTR_FLAGS_HWHEEL;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_EXT_MOUSE);
    event.flags = PTR_XFLAGS_BUTTON1 | PTR_XFLAGS_BUTTON2;
    return frdp_agent_input_event_payload_is_valid(&event) ? -1 : 0;
}

static int test_rejects_parameter_bounds(void)
{
    frdpAgentInputEvent event;

    init_event(&event, FRDP_AGENT_INPUT_KEYBOARD);
    event.param1 = 0x100;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_UNICODE);
    event.param1 = 0x10000;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_MOUSE);
    event.flags = PTR_FLAGS_MOVE;
    event.param1 = -1;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_REL_MOUSE);
    event.flags = PTR_FLAGS_MOVE;
    event.param1 = 32768;
    if (frdp_agent_input_event_payload_is_valid(&event))
        return -1;

    init_event(&event, FRDP_AGENT_INPUT_EXT_MOUSE);
    event.param2 = 65536;
    return frdp_agent_input_event_payload_is_valid(&event) ? -1 : 0;
}

static int test_decodes_unicode_surrogate_pairs(void)
{
    frdpAgentUnicodeInputState state = { 0 };
    frdpAgentInputEvent event;
    uint32_t codepoint = UINT32_MAX;

    init_event(&event, FRDP_AGENT_INPUT_UNICODE);
    event.param1 = 0xD83C;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0) ||
        (state.pending_high_surrogate != 0xD83C) || (codepoint != 0))
        return -1;
    event.flags = KBD_FLAGS_RELEASE;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0) ||
        (state.pending_high_surrogate != 0xD83C))
        return -1;
    event.flags = 0;
    event.param1 = 0xDF0D;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 1) ||
        (state.pending_high_surrogate != 0) || (codepoint != 0x1F30D))
        return -1;

    event.param1 = 0x20AC;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 1) ||
        (codepoint != 0x20AC))
        return -1;
    event.param1 = 0xD800;
    if (frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0)
        return -1;
    event.param1 = 0xDC00;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 1) ||
        (codepoint != 0x10000))
        return -1;
    event.param1 = 0xDBFF;
    if (frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0)
        return -1;
    event.param1 = 0xDFFF;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 1) ||
        (codepoint != 0x10FFFF))
        return -1;
    return 0;
}

static int test_maps_unicode_scalars_to_x11_keysyms(void)
{
    if (frdp_agent_unicode_scalar_to_keysym('A') != UINT32_C(0x41))
        return -1;
    if (frdp_agent_unicode_scalar_to_keysym(0x20AC) != UINT32_C(0x010020AC))
        return -1;
    if (frdp_agent_unicode_scalar_to_keysym(0x1F30D) != UINT32_C(0x0101F30D))
        return -1;
    if (frdp_agent_unicode_scalar_to_keysym(0x10FFFF) != UINT32_C(0x0110FFFF))
        return -1;
    if ((frdp_agent_unicode_scalar_to_keysym(0x1F) != 0) ||
        (frdp_agent_unicode_scalar_to_keysym(0xD800) != 0) ||
        (frdp_agent_unicode_scalar_to_keysym(0x110000) != 0))
        return -1;
    return 0;
}

static int test_rejects_malformed_unicode_sequences(void)
{
    frdpAgentUnicodeInputState state = { 0 };
    frdpAgentInputEvent event;
    uint32_t codepoint = UINT32_MAX;

    init_event(&event, FRDP_AGENT_INPUT_UNICODE);
    event.param1 = 0xDC00;
    if (frdp_agent_unicode_input_decode(&state, &event, &codepoint) != -1)
        return -1;
    event.param1 = 0xD800;
    if (frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0)
        return -1;
    event.param1 = 0xDBFF;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != -1) ||
        (state.pending_high_surrogate != 0))
        return -1;
    event.param1 = 0xD800;
    if (frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0)
        return -1;
    event.param1 = 'A';
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != -1) ||
        (state.pending_high_surrogate != 0))
        return -1;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 1) ||
        (codepoint != 'A'))
        return -1;
    event.param1 = 0xD800;
    if (frdp_agent_unicode_input_decode(&state, &event, &codepoint) != 0)
        return -1;
    event.param2 = 1;
    if ((frdp_agent_unicode_input_decode(&state, &event, &codepoint) != -1) ||
        (state.pending_high_surrogate != 0) || (codepoint != 0))
        return -1;
    frdp_agent_unicode_input_reset(&state);
    return 0;
}

int TestFreeRDPFrdpInputPolicy(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    if (!frdp_agent_input_event_payload_is_valid(NULL)) {
        /* Expected rejection path; keep this explicit for null-argument coverage. */
    } else {
        fprintf(stderr, "null input event accepted\n");
        return -1;
    }

    if (test_accepts_valid_events() != 0) {
        fprintf(stderr, "valid input event rejected\n");
        return -1;
    }
    if (test_rejects_unknown_types_and_flags() != 0) {
        fprintf(stderr, "unknown input type or flags accepted\n");
        return -1;
    }
    if (test_rejects_parameter_bounds() != 0) {
        fprintf(stderr, "out-of-bounds input parameters accepted\n");
        return -1;
    }
    if (test_decodes_unicode_surrogate_pairs() != 0) {
        fprintf(stderr, "valid Unicode surrogate pair rejected\n");
        return -1;
    }
    if (test_maps_unicode_scalars_to_x11_keysyms() != 0) {
        fprintf(stderr, "Unicode scalar mapped to an invalid X11 keysym\n");
        return -1;
    }
    if (test_rejects_malformed_unicode_sequences() != 0) {
        fprintf(stderr, "malformed Unicode surrogate sequence accepted\n");
        return -1;
    }
    return 0;
}
