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
    event.param1 = 0xD800;
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
    return 0;
}
