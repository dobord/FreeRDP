#include "input_policy.h"

#include <freerdp/input.h>

static int uint16_param_is_valid(int32_t value)
{
    return (value >= 0) && (value <= 0xFFFF);
}

static int int16_param_is_valid(int32_t value)
{
    return (value >= -32768) && (value <= 32767);
}

static int single_button_is_valid(uint32_t flags, uint32_t button_mask)
{
    uint32_t buttons = flags & button_mask;

    return (buttons == 0) || ((buttons & (buttons - 1U)) == 0);
}

static int unicode_codepoint_is_supported(uint32_t codepoint)
{
    switch (codepoint) {
        case 0x08:
        case 0x09:
        case 0x0D:
        case 0x1B:
        case 0x7F:
            return 1;
        default:
            break;
    }

    if ((codepoint < 0x20U) || (codepoint > 0xFFFFU))
        return 0;
    if ((codepoint >= 0xD800U) && (codepoint <= 0xDFFFU))
        return 0;
    return 1;
}

static int keyboard_event_is_valid(const frdpAgentInputEvent *event)
{
    const uint32_t allowed_flags =
        KBD_FLAGS_EXTENDED | KBD_FLAGS_EXTENDED1 | KBD_FLAGS_DOWN | KBD_FLAGS_RELEASE;

    return ((event->flags & ~allowed_flags) == 0) && uint16_param_is_valid(event->param1) &&
           (event->param1 <= 0xFF) && (event->param2 == 0);
}

static int unicode_event_is_valid(const frdpAgentInputEvent *event)
{
    const uint32_t allowed_flags = KBD_FLAGS_DOWN | KBD_FLAGS_RELEASE;

    return ((event->flags & ~allowed_flags) == 0) && uint16_param_is_valid(event->param1) &&
           unicode_codepoint_is_supported((uint32_t)event->param1) && (event->param2 == 0);
}

static int mouse_event_is_valid(const frdpAgentInputEvent *event)
{
    const uint32_t wheel_flags = PTR_FLAGS_WHEEL | PTR_FLAGS_HWHEEL;
    const uint32_t button_mask = PTR_FLAGS_BUTTON1 | PTR_FLAGS_BUTTON2 | PTR_FLAGS_BUTTON3;
    const uint32_t allowed_flags = wheel_flags | PTR_FLAGS_WHEEL_NEGATIVE | PTR_FLAGS_MOVE |
                                   PTR_FLAGS_DOWN | button_mask | WheelRotationMask;
    const uint32_t lower_rotation_bits = WheelRotationMask & ~PTR_FLAGS_WHEEL_NEGATIVE;

    if ((event->flags & ~allowed_flags) != 0)
        return 0;
    if (!uint16_param_is_valid(event->param1) || !uint16_param_is_valid(event->param2))
        return 0;
    if ((event->flags & PTR_FLAGS_WHEEL) && (event->flags & PTR_FLAGS_HWHEEL))
        return 0;

    if (event->flags & wheel_flags) {
        const uint32_t allowed_wheel_flags =
            wheel_flags | PTR_FLAGS_WHEEL_NEGATIVE | WheelRotationMask;

        return (event->flags & ~allowed_wheel_flags) == 0;
    }

    if ((event->flags & lower_rotation_bits) != 0)
        return 0;
    if ((event->flags & PTR_FLAGS_WHEEL_NEGATIVE) != 0)
        return 0;
    return single_button_is_valid(event->flags, button_mask);
}

static int rel_mouse_event_is_valid(const frdpAgentInputEvent *event)
{
    const uint32_t button_mask =
        PTR_FLAGS_BUTTON1 | PTR_FLAGS_BUTTON2 | PTR_FLAGS_BUTTON3 | PTR_XFLAGS_BUTTON1 |
        PTR_XFLAGS_BUTTON2;
    const uint32_t allowed_flags = PTR_FLAGS_MOVE | PTR_FLAGS_DOWN | button_mask;

    return ((event->flags & ~allowed_flags) == 0) && int16_param_is_valid(event->param1) &&
           int16_param_is_valid(event->param2) && single_button_is_valid(event->flags, button_mask);
}

static int extended_mouse_event_is_valid(const frdpAgentInputEvent *event)
{
    const uint32_t button_mask = PTR_XFLAGS_BUTTON1 | PTR_XFLAGS_BUTTON2;
    const uint32_t allowed_flags = PTR_XFLAGS_DOWN | button_mask;

    return ((event->flags & ~allowed_flags) == 0) && uint16_param_is_valid(event->param1) &&
           uint16_param_is_valid(event->param2) && single_button_is_valid(event->flags, button_mask);
}

int frdp_agent_input_event_payload_is_valid(const frdpAgentInputEvent *event)
{
    const uint32_t sync_flags =
        KBD_SYNC_SCROLL_LOCK | KBD_SYNC_NUM_LOCK | KBD_SYNC_CAPS_LOCK | KBD_SYNC_KANA_LOCK;

    if (!event)
        return 0;

    switch (event->event_type) {
        case FRDP_AGENT_INPUT_SYNC:
            return ((event->flags & ~sync_flags) == 0) && (event->param1 == 0) &&
                   (event->param2 == 0);
        case FRDP_AGENT_INPUT_KEYBOARD:
            return keyboard_event_is_valid(event);
        case FRDP_AGENT_INPUT_UNICODE:
            return unicode_event_is_valid(event);
        case FRDP_AGENT_INPUT_MOUSE:
            return mouse_event_is_valid(event);
        case FRDP_AGENT_INPUT_REL_MOUSE:
            return rel_mouse_event_is_valid(event);
        case FRDP_AGENT_INPUT_EXT_MOUSE:
            return extended_mouse_event_is_valid(event);
        default:
            return 0;
    }
}
