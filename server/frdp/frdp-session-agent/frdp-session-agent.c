#define _GNU_SOURCE

/*
 * frdp-session-agent - Per-user agent for FreeRDP-based RDP server
 *
 * This component runs in the security context of an authenticated user.  It
 * launches the headless desktop backend (for example Xvfb or Wayland), sets
 * up graphics capture and input dispatch and enforces channel policy.  In this
 * minimal prototype launches the display server, injects validated keyboard,
 * Unicode BMP text and mouse input, and serves raw framebuffer tiles over a
 * local control fd with XDamage-backed dirty-tile tracking.  The display
 * number, geometry and audit identifiers are provided via environment variables
 * from the session manager:
 * DISPLAY or FRDP_DISPLAY, FRDP_GEOMETRY, FRDP_SESSION_ID and
 * FRDP_CORRELATION_ID.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xdamage.h>
#include <X11/extensions/Xrandr.h>
#include <X11/extensions/XTest.h>

#include <freerdp/input.h>

#include <winpr/input.h>

#include "../ipc/frdp-ipc.h"

#define FRDP_AGENT_READY_MARKER 'R'
#define FRDP_AGENT_FRAME_TILE_MAX 120U
#define FRDP_AGENT_DAMAGE_EVENT_LIMIT 256U
#define FRDP_AGENT_DISPLAY_SIZE_MAX 8192U

typedef struct {
    Display *display;
    Window root;
    int screen;
    int damage_event;
    Damage damage;
    int damage_enabled;
    uint32_t screen_width;
    uint32_t screen_height;
    uint32_t dirty_cols;
    uint32_t dirty_rows;
    unsigned char *dirty_tiles;
} frdpAgentFrameState;

static volatile int g_x11_resize_error = 0;
static volatile int g_x11_keyboard_error = 0;
static volatile sig_atomic_t g_stop_requested = 0;

static void agent_signal_handler(int signum)
{
    (void)signum;
    g_stop_requested = 1;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = agent_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    if (sigaction(SIGINT, &action, NULL) != 0)
        return -1;
    if (sigaction(SIGTERM, &action, NULL) != 0)
        return -1;
    return 0;
}

static char hex_digit(unsigned int value)
{
    return (value < 10U) ? (char)('0' + value) : (char)('a' + (value - 10U));
}

static int log_char_is_safe(unsigned char c)
{
    return ((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
           ((c >= '0') && (c <= '9')) || (c == '.') || (c == '_') || (c == '-') ||
           (c == ':') || (c == '@') || (c == '/') || (c == '%') || (c == '+');
}

static void escape_log_field(const char *src, char *dst, size_t dst_size)
{
    size_t used = 0;

    if (!dst || dst_size == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;

    for (const unsigned char *p = (const unsigned char *)src; (*p != '\0') && (used + 1 < dst_size);
         p++) {
        if (log_char_is_safe(*p)) {
            dst[used++] = (char)*p;
            dst[used] = '\0';
        } else if (used + 4 < dst_size) {
            dst[used++] = '\\';
            dst[used++] = 'x';
            dst[used++] = hex_digit((*p >> 4U) & 0x0fU);
            dst[used++] = hex_digit(*p & 0x0fU);
            dst[used] = '\0';
        } else {
            break;
        }
    }
}

static void escape_log_ids(const char *correlation_id, const char *session_id,
                           char *escaped_correlation_id, size_t escaped_correlation_id_size,
                           char *escaped_session_id, size_t escaped_session_id_size)
{
    escape_log_field(correlation_id ? correlation_id : "unknown", escaped_correlation_id,
                     escaped_correlation_id_size);
    escape_log_field(session_id ? session_id : "unknown", escaped_session_id,
                     escaped_session_id_size);
}

static int resize_error_handler(Display *display, XErrorEvent *event)
{
    (void)display;
    (void)event;
    g_x11_resize_error = 1;
    return 0;
}

static int keyboard_error_handler(Display *display, XErrorEvent *event)
{
    (void)display;
    (void)event;
    g_x11_keyboard_error = 1;
    return 0;
}

static Display *open_backend_display(const char *display_name, const char *correlation_id,
                                     const char *session_id)
{
    Display *display = NULL;

    for (int attempt = 0; attempt < 50; attempt++) {
        display = XOpenDisplay(display_name);
        if (display)
            break;
        usleep(100000);
    }
    if (!display) {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };
        char escaped_display[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        escape_log_field(display_name ? display_name : "unknown", escaped_display,
                         sizeof(escaped_display));
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to open display %s",
               escaped_correlation_id, escaped_session_id, escaped_display);
        return NULL;
    }

    int event_base = 0;
    int error_base = 0;
    int major = 0;
    int minor = 0;
    if (!XTestQueryExtension(display, &event_base, &error_base, &major, &minor)) {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };
        char escaped_display[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        escape_log_field(display_name ? display_name : "unknown", escaped_display,
                         sizeof(escaped_display));
        syslog(LOG_ERR, "correlation_id=%s session_id=%s display %s lacks XTest",
               escaped_correlation_id, escaped_session_id, escaped_display);
        XCloseDisplay(display);
        return NULL;
    }
    return display;
}

static int inject_keyboard_event(Display *display, const frdpAgentInputEvent *event)
{
    DWORD scancode = (DWORD)(event->param1 & 0xFF);
    DWORD vkcode = 0;
    DWORD keycode = 0;

    if (event->flags & KBD_FLAGS_EXTENDED)
        scancode |= KBDEXT;

    vkcode = GetVirtualKeyCodeFromVirtualScanCode(scancode, WINPR_KBD_TYPE_IBM_ENHANCED);
    if (event->flags & KBD_FLAGS_EXTENDED)
        vkcode |= KBDEXT;

    keycode = GetKeycodeFromVirtualKeyCode(vkcode, WINPR_KEYCODE_TYPE_XKB);
    if (keycode == 0)
        return -1;

    XTestFakeKeyEvent(display, keycode, (event->flags & KBD_FLAGS_RELEASE) ? False : True,
                      CurrentTime);
    return 0;
}

static KeySym unicode_to_keysym(uint32_t codepoint)
{
    switch (codepoint) {
        case 0x08:
            return XK_BackSpace;
        case 0x09:
            return XK_Tab;
        case 0x0D:
            return XK_Return;
        case 0x1B:
            return XK_Escape;
        case 0x7F:
            return XK_Delete;
        default:
            break;
    }

    if ((codepoint < 0x20) || (codepoint > 0xFFFF) ||
        ((codepoint >= 0xD800) && (codepoint <= 0xDFFF)))
        return NoSymbol;
    if (codepoint <= 0xFF)
        return (KeySym)codepoint;
    return (KeySym)(0x01000000UL | codepoint);
}

static int find_unused_keycode(Display *display, int *min_keycode, int *keysyms_per_keycode,
                               KeySym **mapping)
{
    int max_keycode = 0;
    int count = 0;

    if (!display || !min_keycode || !keysyms_per_keycode || !mapping)
        return 0;
    XDisplayKeycodes(display, min_keycode, &max_keycode);
    if ((*min_keycode <= 0) || (max_keycode < *min_keycode))
        return 0;

    count = max_keycode - *min_keycode + 1;
    *mapping = XGetKeyboardMapping(display, (KeyCode)*min_keycode, count, keysyms_per_keycode);
    if (!*mapping || (*keysyms_per_keycode <= 0))
        return 0;

    for (int keycode = max_keycode; keycode >= *min_keycode; keycode--) {
        int used = 0;
        KeySym *entry = &(*mapping)[(keycode - *min_keycode) * (*keysyms_per_keycode)];

        for (int i = 0; i < *keysyms_per_keycode; i++) {
            if (entry[i] != NoSymbol) {
                used = 1;
                break;
            }
        }
        if (!used)
            return keycode;
    }
    return 0;
}

static int inject_keysym_once(Display *display, KeySym keysym)
{
    int rc = -1;
    int min_keycode = 0;
    int keycode = 0;
    int keysyms_per_keycode = 0;
    KeySym *mapping = NULL;
    KeySym *original = NULL;
    KeySym *replacement = NULL;
    XErrorHandler previous_handler = NULL;
    int handler_set = 0;

    if (!display || (keysym == NoSymbol))
        return -1;

    /* Avoid layout/modifier ambiguity by sending the symbol through a spare keycode. */
    keycode = find_unused_keycode(display, &min_keycode, &keysyms_per_keycode, &mapping);
    if ((keycode == 0) || !mapping || (keysyms_per_keycode <= 0))
        goto out;

    original = (KeySym *)calloc((size_t)keysyms_per_keycode, sizeof(KeySym));
    replacement = (KeySym *)calloc((size_t)keysyms_per_keycode, sizeof(KeySym));
    if (!original || !replacement)
        goto out;

    memcpy(original, &mapping[(keycode - min_keycode) * keysyms_per_keycode],
           (size_t)keysyms_per_keycode * sizeof(KeySym));
    replacement[0] = keysym;

    g_x11_keyboard_error = 0;
    previous_handler = XSetErrorHandler(keyboard_error_handler);
    handler_set = 1;

    XChangeKeyboardMapping(display, keycode, keysyms_per_keycode, replacement, 1);
    XSync(display, False);
    if (g_x11_keyboard_error)
        goto restore;

    if (!XTestFakeKeyEvent(display, (KeyCode)keycode, True, CurrentTime) ||
        !XTestFakeKeyEvent(display, (KeyCode)keycode, False, CurrentTime))
        goto restore;
    XSync(display, False);
    if (!g_x11_keyboard_error)
        rc = 0;

restore:
    g_x11_keyboard_error = 0;
    XChangeKeyboardMapping(display, keycode, keysyms_per_keycode, original, 1);
    XSync(display, False);
    if (g_x11_keyboard_error)
        rc = -1;

out:
    if (handler_set)
        XSetErrorHandler(previous_handler);
    free(replacement);
    free(original);
    if (mapping)
        XFree(mapping);
    return rc;
}

static int inject_unicode_event(Display *display, const frdpAgentInputEvent *event)
{
    KeySym keysym = NoSymbol;
    uint32_t codepoint = 0;

    if (!display || !event)
        return -1;
    if (event->flags & KBD_FLAGS_RELEASE)
        return 0;

    codepoint = (uint32_t)(event->param1 & 0xFFFF);
    keysym = unicode_to_keysym(codepoint);
    if (keysym == NoSymbol)
        return -1;
    return inject_keysym_once(display, keysym);
}

static void inject_button_event(Display *display, unsigned int button, Bool down)
{
    if (button)
        XTestFakeButtonEvent(display, button, down, CurrentTime);
}

static int inject_mouse_event(Display *display, const frdpAgentInputEvent *event)
{
    const uint32_t flags = event->flags;
    const int x = event->param1;
    const int y = event->param2;
    unsigned int button = 0;
    Bool down = (flags & PTR_FLAGS_DOWN) ? True : False;

    if (flags & PTR_FLAGS_WHEEL) {
        button = (flags & PTR_FLAGS_WHEEL_NEGATIVE) ? 5 : 4;
        XTestFakeButtonEvent(display, button, True, CurrentTime);
        XTestFakeButtonEvent(display, button, False, CurrentTime);
        return 0;
    }
    if (flags & PTR_FLAGS_HWHEEL) {
        button = (flags & PTR_FLAGS_WHEEL_NEGATIVE) ? 7 : 6;
        XTestFakeButtonEvent(display, button, True, CurrentTime);
        XTestFakeButtonEvent(display, button, False, CurrentTime);
        return 0;
    }
    if (flags & PTR_FLAGS_MOVE)
        XTestFakeMotionEvent(display, 0, x, y, CurrentTime);

    if (flags & PTR_FLAGS_BUTTON1)
        button = 1;
    else if (flags & PTR_FLAGS_BUTTON2)
        button = 3;
    else if (flags & PTR_FLAGS_BUTTON3)
        button = 2;
    inject_button_event(display, button, down);
    return 0;
}

static int inject_rel_mouse_event(Display *display, const frdpAgentInputEvent *event)
{
    const uint32_t flags = event->flags;
    unsigned int button = 0;
    Bool down = (flags & PTR_FLAGS_DOWN) ? True : False;

    if (flags & PTR_FLAGS_MOVE)
        XTestFakeRelativeMotionEvent(display, event->param1, event->param2, CurrentTime);

    if (flags & PTR_FLAGS_BUTTON1)
        button = 1;
    else if (flags & PTR_FLAGS_BUTTON2)
        button = 3;
    else if (flags & PTR_FLAGS_BUTTON3)
        button = 2;
    else if (flags & PTR_XFLAGS_BUTTON1)
        button = 8;
    else if (flags & PTR_XFLAGS_BUTTON2)
        button = 9;
    inject_button_event(display, button, down);
    return 0;
}

static int inject_extended_mouse_event(Display *display, const frdpAgentInputEvent *event)
{
    const uint32_t flags = event->flags;
    unsigned int button = 0;
    Bool down = (flags & PTR_XFLAGS_DOWN) ? True : False;

    XTestFakeMotionEvent(display, 0, event->param1, event->param2, CurrentTime);
    if (flags & PTR_XFLAGS_BUTTON1)
        button = 8;
    else if (flags & PTR_XFLAGS_BUTTON2)
        button = 9;
    inject_button_event(display, button, down);
    return 0;
}

static int inject_input_event(Display *display, const frdpAgentInputEvent *event)
{
    int rc = 0;

    if (!display || !event)
        return -1;
    XLockDisplay(display);
    XTestGrabControl(display, True);
    switch (event->event_type) {
        case FRDP_AGENT_INPUT_SYNC:
            rc = 0;
            break;
        case FRDP_AGENT_INPUT_KEYBOARD:
            rc = inject_keyboard_event(display, event);
            break;
        case FRDP_AGENT_INPUT_UNICODE:
            rc = inject_unicode_event(display, event);
            break;
        case FRDP_AGENT_INPUT_MOUSE:
            rc = inject_mouse_event(display, event);
            break;
        case FRDP_AGENT_INPUT_REL_MOUSE:
            rc = inject_rel_mouse_event(display, event);
            break;
        case FRDP_AGENT_INPUT_EXT_MOUSE:
            rc = inject_extended_mouse_event(display, event);
            break;
        default:
            rc = -1;
            break;
    }
    XTestGrabControl(display, False);
    XFlush(display);
    XUnlockDisplay(display);
    return rc;
}

static unsigned char extract_ximage_channel(unsigned long pixel, unsigned long mask)
{
    const unsigned int max_bits = (unsigned int)(sizeof(unsigned long) * 8U);
    unsigned int shift = 0;
    unsigned int bits = 0;
    unsigned long value = 0;

    if (mask == 0)
        return 0;
    while (shift < max_bits && ((mask >> shift) & 1UL) == 0)
        shift++;
    if (shift == max_bits)
        return 0;
    value = (pixel & mask) >> shift;
    while ((shift + bits) < max_bits && ((mask >> (shift + bits)) & 1UL) != 0)
        bits++;
    if (bits == 0)
        return 0;
    if (bits >= 8)
        return (unsigned char)(value >> (bits - 8));
    return (unsigned char)((value * 255UL) / ((1UL << bits) - 1UL));
}

static void frame_state_set_dirty_rect(frdpAgentFrameState *state, int x, int y, uint32_t width,
                                       uint32_t height, unsigned char dirty)
{
    int64_t left = x;
    int64_t top = y;
    int64_t right = (int64_t)x + width;
    int64_t bottom = (int64_t)y + height;
    uint32_t col_start = 0;
    uint32_t col_end = 0;
    uint32_t row_start = 0;
    uint32_t row_end = 0;

    if (!state || !state->dirty_tiles || state->dirty_cols == 0 || state->dirty_rows == 0 ||
        width == 0 || height == 0)
        return;
    if (right <= 0 || bottom <= 0 || left >= state->screen_width || top >= state->screen_height)
        return;
    if (left < 0)
        left = 0;
    if (top < 0)
        top = 0;
    if (right > state->screen_width)
        right = state->screen_width;
    if (bottom > state->screen_height)
        bottom = state->screen_height;
    if (right <= left || bottom <= top)
        return;

    col_start = (uint32_t)left / FRDP_AGENT_FRAME_TILE_MAX;
    col_end = ((uint32_t)right - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    row_start = (uint32_t)top / FRDP_AGENT_FRAME_TILE_MAX;
    row_end = ((uint32_t)bottom - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    if (col_end >= state->dirty_cols)
        col_end = state->dirty_cols - 1U;
    if (row_end >= state->dirty_rows)
        row_end = state->dirty_rows - 1U;

    for (uint32_t row = row_start; row <= row_end; row++) {
        for (uint32_t col = col_start; col <= col_end; col++) {
            state->dirty_tiles[((size_t)row * state->dirty_cols) + col] = dirty;
        }
    }
}

static int frame_state_refresh_geometry(frdpAgentFrameState *state)
{
    int screen = 0;
    int width = 0;
    int height = 0;
    uint32_t cols = 0;
    uint32_t rows = 0;
    size_t count = 0;
    unsigned char *dirty_tiles = NULL;

    if (!state || !state->display)
        return -1;

    XLockDisplay(state->display);
    screen = DefaultScreen(state->display);
    width = DisplayWidth(state->display, screen);
    height = DisplayHeight(state->display, screen);
    state->root = RootWindow(state->display, screen);
    XUnlockDisplay(state->display);

    if (width <= 0 || height <= 0)
        return -1;
    cols = ((uint32_t)width + FRDP_AGENT_FRAME_TILE_MAX - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    rows = ((uint32_t)height + FRDP_AGENT_FRAME_TILE_MAX - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    if (cols == 0 || rows == 0 || cols > SIZE_MAX / rows)
        return -1;
    count = (size_t)cols * rows;
    if (count > SIZE_MAX / sizeof(*dirty_tiles))
        return -1;
    if (state->dirty_tiles && state->screen == screen && state->screen_width == (uint32_t)width &&
        state->screen_height == (uint32_t)height && state->dirty_cols == cols &&
        state->dirty_rows == rows)
        return 0;

    dirty_tiles = (unsigned char *)calloc(count, sizeof(*dirty_tiles));
    if (!dirty_tiles)
        return -1;
    memset(dirty_tiles, 1, count);
    free(state->dirty_tiles);
    state->dirty_tiles = dirty_tiles;
    state->screen = screen;
    state->screen_width = (uint32_t)width;
    state->screen_height = (uint32_t)height;
    state->dirty_cols = cols;
    state->dirty_rows = rows;
    return 0;
}

static void frame_state_mark_all_dirty(frdpAgentFrameState *state)
{
    size_t count = 0;

    if (!state || !state->dirty_tiles || state->dirty_cols == 0 || state->dirty_rows == 0)
        return;
    if (state->dirty_cols > SIZE_MAX / state->dirty_rows)
        return;
    count = (size_t)state->dirty_cols * state->dirty_rows;
    memset(state->dirty_tiles, 1, count);
}

static int frame_state_rect_dirty(const frdpAgentFrameState *state, int x, int y, uint32_t width,
                                  uint32_t height)
{
    int64_t left = x;
    int64_t top = y;
    int64_t right = (int64_t)x + width;
    int64_t bottom = (int64_t)y + height;
    uint32_t col_start = 0;
    uint32_t col_end = 0;
    uint32_t row_start = 0;
    uint32_t row_end = 0;

    if (!state || !state->dirty_tiles || state->dirty_cols == 0 || state->dirty_rows == 0 ||
        width == 0 || height == 0)
        return 1;
    if (right <= 0 || bottom <= 0 || left >= state->screen_width || top >= state->screen_height)
        return 1;
    if (left < 0)
        left = 0;
    if (top < 0)
        top = 0;
    if (right > state->screen_width)
        right = state->screen_width;
    if (bottom > state->screen_height)
        bottom = state->screen_height;
    if (right <= left || bottom <= top)
        return 1;

    col_start = (uint32_t)left / FRDP_AGENT_FRAME_TILE_MAX;
    col_end = ((uint32_t)right - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    row_start = (uint32_t)top / FRDP_AGENT_FRAME_TILE_MAX;
    row_end = ((uint32_t)bottom - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    if (col_end >= state->dirty_cols)
        col_end = state->dirty_cols - 1U;
    if (row_end >= state->dirty_rows)
        row_end = state->dirty_rows - 1U;

    for (uint32_t row = row_start; row <= row_end; row++) {
        for (uint32_t col = col_start; col <= col_end; col++) {
            if (state->dirty_tiles[((size_t)row * state->dirty_cols) + col])
                return 1;
        }
    }
    return 0;
}

static int frame_state_find_dirty_tile(const frdpAgentFrameState *state, uint32_t start_x,
                                       uint32_t start_y, uint32_t *x, uint32_t *y,
                                       uint32_t *width, uint32_t *height)
{
    uint32_t start_col = 0;
    uint32_t start_row = 0;
    size_t count = 0;
    size_t start = 0;

    if (!state || !state->dirty_tiles || state->dirty_cols == 0 || state->dirty_rows == 0 ||
        !x || !y || !width || !height)
        return 0;
    if (state->dirty_cols > SIZE_MAX / state->dirty_rows)
        return 0;
    count = (size_t)state->dirty_cols * state->dirty_rows;
    start_col = start_x / FRDP_AGENT_FRAME_TILE_MAX;
    start_row = start_y / FRDP_AGENT_FRAME_TILE_MAX;
    if (start_col >= state->dirty_cols)
        start_col = state->dirty_cols - 1U;
    if (start_row >= state->dirty_rows)
        start_row = state->dirty_rows - 1U;
    start = ((size_t)start_row * state->dirty_cols) + start_col;

    for (size_t i = 0; i < count; i++) {
        const size_t index = (start + i) % count;
        const uint32_t col = (uint32_t)(index % state->dirty_cols);
        const uint32_t row = (uint32_t)(index / state->dirty_cols);
        const uint32_t tile_x = col * FRDP_AGENT_FRAME_TILE_MAX;
        const uint32_t tile_y = row * FRDP_AGENT_FRAME_TILE_MAX;

        if (!state->dirty_tiles[index])
            continue;
        *x = tile_x;
        *y = tile_y;
        *width = FRDP_AGENT_FRAME_TILE_MAX;
        *height = FRDP_AGENT_FRAME_TILE_MAX;
        if (*width > state->screen_width - *x)
            *width = state->screen_width - *x;
        if (*height > state->screen_height - *y)
            *height = state->screen_height - *y;
        return (*width > 0 && *height > 0) ? 1 : 0;
    }
    return 0;
}

static void frame_state_process_damage_events(frdpAgentFrameState *state)
{
    XEvent event;
    uint32_t processed = 0;

    if (!state || !state->display || !state->damage_enabled)
        return;

    memset(&event, 0, sizeof(event));
    XLockDisplay(state->display);
    while (processed < FRDP_AGENT_DAMAGE_EVENT_LIMIT &&
           XCheckTypedEvent(state->display, state->damage_event, &event)) {
        const XDamageNotifyEvent *damage_event = (const XDamageNotifyEvent *)&event;
        frame_state_set_dirty_rect(state, damage_event->area.x, damage_event->area.y,
                                   damage_event->area.width, damage_event->area.height, 1);
        XDamageSubtract(state->display, state->damage, None, None);
        processed++;
    }
    if (processed >= FRDP_AGENT_DAMAGE_EVENT_LIMIT)
        frame_state_mark_all_dirty(state);
    XUnlockDisplay(state->display);
}

static int frame_state_init(frdpAgentFrameState *state, Display *display,
                            const char *correlation_id, const char *session_id)
{
    int damage_event = 0;
    int damage_error = 0;
    int major = 0;
    int minor = 0;

    if (!state || !display)
        return -1;
    memset(state, 0, sizeof(*state));
    state->display = display;
    if (frame_state_refresh_geometry(state) != 0)
        return -1;

    XLockDisplay(display);
    if (XDamageQueryExtension(display, &damage_event, &damage_error) &&
        XDamageQueryVersion(display, &major, &minor) && major >= 1) {
        state->damage = XDamageCreate(display, state->root, XDamageReportDeltaRectangles);
        if (state->damage) {
            state->damage_event = damage_event + XDamageNotify;
            state->damage_enabled = 1;
            XDamageSubtract(display, state->damage, None, None);
            XSync(display, False);
        }
    }
    XUnlockDisplay(display);

    char escaped_correlation_id[256] = { 0 };
    char escaped_session_id[256] = { 0 };

    escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                   sizeof(escaped_correlation_id), escaped_session_id, sizeof(escaped_session_id));
    if (state->damage_enabled) {
        syslog(LOG_INFO, "correlation_id=%s session_id=%s enabled XDamage dirty tile tracking",
               escaped_correlation_id, escaped_session_id);
    } else {
        syslog(LOG_WARNING,
               "correlation_id=%s session_id=%s XDamage unavailable; using capture-all tiles",
               escaped_correlation_id, escaped_session_id);
    }
    return 0;
}

static void frame_state_uninit(frdpAgentFrameState *state)
{
    if (!state)
        return;
    if (state->display && state->damage) {
        XLockDisplay(state->display);
        XDamageDestroy(state->display, state->damage);
        XUnlockDisplay(state->display);
    }
    free(state->dirty_tiles);
    memset(state, 0, sizeof(*state));
}

static int capture_frame_tile(frdpAgentFrameState *state, const frdpAgentFrameRequest *request,
                              frdpAgentFrameResponse *response, unsigned char **pixels)
{
    Display *display = NULL;
    XImage *image = NULL;
    unsigned char *buffer = NULL;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t capture_x = 0;
    uint32_t capture_y = 0;
    uint32_t capture_width = 0;
    uint32_t capture_height = 0;

    if (!state || !state->display || !request || !response || !pixels)
        return -1;
    *pixels = NULL;
    if (request->flags & ~(FRDP_AGENT_FRAME_REQUEST_FORCE | FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
        return -1;
    if ((request->flags & FRDP_AGENT_FRAME_REQUEST_FORCE) &&
        (request->flags & FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
        return -1;
    display = state->display;
    if (frame_state_refresh_geometry(state) != 0)
        return -1;
    frame_state_process_damage_events(state);
    if (request->x >= state->screen_width || request->y >= state->screen_height)
        return -1;

    width = request->width;
    height = request->height;
    if (width == 0 || height == 0)
        return -1;
    if (width > FRDP_AGENT_FRAME_TILE_MAX)
        width = FRDP_AGENT_FRAME_TILE_MAX;
    if (height > FRDP_AGENT_FRAME_TILE_MAX)
        height = FRDP_AGENT_FRAME_TILE_MAX;
    if (width > state->screen_width - request->x)
        width = state->screen_width - request->x;
    if (height > state->screen_height - request->y)
        height = state->screen_height - request->y;
    if (width == 0 || height == 0 || width > UINT32_MAX / 4 ||
        height > UINT32_MAX / (width * 4U))
        return -1;

    response->x = request->x;
    response->y = request->y;
    response->width = width;
    response->height = height;
    response->bpp = 32;
    capture_x = request->x;
    capture_y = request->y;
    capture_width = width;
    capture_height = height;
    if (!(request->flags & FRDP_AGENT_FRAME_REQUEST_FORCE) && state->damage_enabled) {
        if (request->flags & FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY) {
            if (!frame_state_find_dirty_tile(state, request->x, request->y, &capture_x,
                                            &capture_y, &capture_width, &capture_height)) {
                response->success = 1;
                response->flags = FRDP_AGENT_FRAME_RESPONSE_UNCHANGED;
                return 0;
            }
        } else if (!frame_state_rect_dirty(state, (int)request->x, (int)request->y, width,
                                          height)) {
            response->success = 1;
            response->flags = FRDP_AGENT_FRAME_RESPONSE_UNCHANGED;
            return 0;
        }
    }
    response->x = capture_x;
    response->y = capture_y;
    response->width = capture_width;
    response->height = capture_height;

    buffer = (unsigned char *)calloc((size_t)capture_width * capture_height, 4);
    if (!buffer)
        return -1;

    XLockDisplay(display);
    image = XGetImage(display, state->root, (int)capture_x, (int)capture_y,
                      capture_width, capture_height, AllPlanes, ZPixmap);
    XUnlockDisplay(display);
    if (!image) {
        free(buffer);
        return -1;
    }

    for (uint32_t row = 0; row < capture_height; row++) {
        const uint32_t src_y = capture_height - row - 1U;
        unsigned char *dst = buffer + ((size_t)row * capture_width * 4U);
        for (uint32_t col = 0; col < capture_width; col++) {
            const unsigned long pixel = XGetPixel(image, (int)col, (int)src_y);
            dst[(size_t)col * 4U + 0] = extract_ximage_channel(pixel, image->blue_mask);
            dst[(size_t)col * 4U + 1] = extract_ximage_channel(pixel, image->green_mask);
            dst[(size_t)col * 4U + 2] = extract_ximage_channel(pixel, image->red_mask);
            dst[(size_t)col * 4U + 3] = 0xFF;
        }
    }
    XDestroyImage(image);
    frame_state_set_dirty_rect(state, (int)capture_x, (int)capture_y, capture_width,
                               capture_height, 0);

    response->success = 1;
    response->stride = capture_width * 4U;
    response->data_length = response->stride * capture_height;
    *pixels = buffer;
    return 0;
}

static int parse_env_fd(const char *name)
{
    char *end = NULL;
    long value = -1;
    const char *env = getenv(name);

    if (!env || env[0] == '\0')
        return -1;
    errno = 0;
    value = strtol(env, &end, 10);
    if (errno != 0 || !end || end[0] != '\0' || value < 0 || value > 1024 * 1024)
        return -1;
    return (int)value;
}

static int parse_control_fd(void)
{
    return parse_env_fd("FRDP_AGENT_CONTROL_FD");
}

static int parse_ready_fd(void)
{
    return parse_env_fd("FRDP_AGENT_READY_FD");
}

static int notify_agent_ready(int *fd)
{
    if (!fd || *fd < 0)
        return 0;

    const char marker = FRDP_AGENT_READY_MARKER;
    const ssize_t rc = write(*fd, &marker, sizeof(marker));
    close(*fd);
    *fd = -1;
    return (rc == (ssize_t)sizeof(marker)) ? 0 : -1;
}

static int set_cloexec(int fd)
{
    const int flags = fcntl(fd, F_GETFD);

    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int set_control_timeouts(int fd)
{
    struct timeval timeout;

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return 0;
}

static int verify_control_peer(int fd)
{
#ifdef __linux__
    struct ucred cred;
    socklen_t len = sizeof(cred);

    memset(&cred, 0, sizeof(cred));
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        return -1;
    return (cred.uid == 0) ? 0 : -1;
#else
    (void)fd;
    return -1;
#endif
}

static int recv_exact(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t total = 0;

    while (total < len) {
        const ssize_t rc = recv(fd, p + total, len - total, 0);
        if (rc <= 0)
            return -1;
        total += (size_t)rc;
    }
    return 0;
}

static int send_exact(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t total = 0;
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif

    while (total < len) {
        const ssize_t rc = send(fd, p + total, len - total, flags);
        if (rc <= 0)
            return -1;
        total += (size_t)rc;
    }
    return 0;
}

static int validate_agent_ids(const char *event_correlation_id, const char *event_session_id,
                              const char *correlation_id, const char *session_id)
{
    if (strcmp(event_session_id, session_id) != 0)
        return -1;
    if (strcmp(correlation_id, "unknown") != 0 && strcmp(event_correlation_id, correlation_id) != 0)
        return -1;
    return 0;
}

static int resize_backend_display(Display *display, const frdpAgentResizeRequest *request,
                                  frdpAgentResizeResponse *response)
{
    int screen = 0;
    Window root = 0;
    int event_base = 0;
    int error_base = 0;
    int major = 0;
    int minor = 0;
    int mm_width = 0;
    int mm_height = 0;
    XErrorHandler previous_handler = NULL;

    if (!display || !request || !response || request->width == 0 || request->height == 0 ||
        request->width > FRDP_AGENT_DISPLAY_SIZE_MAX ||
        request->height > FRDP_AGENT_DISPLAY_SIZE_MAX)
        return -1;

    XLockDisplay(display);
    screen = DefaultScreen(display);
    root = RootWindow(display, screen);
    if (!XRRQueryExtension(display, &event_base, &error_base) ||
        !XRRQueryVersion(display, &major, &minor) || major < 1) {
        XUnlockDisplay(display);
        return -1;
    }

    mm_width = DisplayWidthMM(display, screen);
    mm_height = DisplayHeightMM(display, screen);
    if (mm_width <= 0)
        mm_width = (int)((request->width * 254U) / 960U);
    if (mm_height <= 0)
        mm_height = (int)((request->height * 254U) / 960U);
    if (mm_width <= 0)
        mm_width = 1;
    if (mm_height <= 0)
        mm_height = 1;

    g_x11_resize_error = 0;
    previous_handler = XSetErrorHandler(resize_error_handler);
    XRRSetScreenSize(display, root, (int)request->width, (int)request->height, mm_width,
                     mm_height);
    XSync(display, False);
    XSetErrorHandler(previous_handler);
    if (g_x11_resize_error != 0 || DisplayWidth(display, screen) != (int)request->width ||
        DisplayHeight(display, screen) != (int)request->height) {
        XUnlockDisplay(display);
        return -1;
    }

    response->success = 1;
    response->width = request->width;
    response->height = request->height;
    XUnlockDisplay(display);
    return 0;
}

static int handle_input_message(int fd, Display *display, uint32_t payload_len,
                                const char *correlation_id, const char *session_id)
{
    frdpAgentInputEvent event;

    memset(&event, 0, sizeof(event));

    if (payload_len != sizeof(event))
        return -1;
    if (recv_exact(fd, &event, sizeof(event)) != 0)
        return -1;

    event.correlation_id[sizeof(event.correlation_id) - 1] = '\0';
    event.session_id[sizeof(event.session_id) - 1] = '\0';
    if (validate_agent_ids(event.correlation_id, event.session_id, correlation_id, session_id) != 0) {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected mismatched input event",
               escaped_correlation_id, escaped_session_id);
        return -1;
    }

    return inject_input_event(display, &event);
}

static int send_frame_response(int fd, const frdpAgentFrameResponse *response,
                               const unsigned char *pixels)
{
    frdpIpcHeader header;

    memset(&header, 0, sizeof(header));
    header.type = FRDP_IPC_AGENT_FRAME_RESPONSE;
    header.payload_len = sizeof(*response);
    if (send_exact(fd, &header, sizeof(header)) != 0)
        return -1;
    if (send_exact(fd, response, sizeof(*response)) != 0)
        return -1;
    if (response->success && response->data_length > 0) {
        if (!pixels)
            return -1;
        if (send_exact(fd, pixels, response->data_length) != 0)
            return -1;
    }
    return 0;
}

static int send_resize_response(int fd, const frdpAgentResizeResponse *response)
{
    frdpIpcHeader header;

    memset(&header, 0, sizeof(header));
    header.type = FRDP_IPC_AGENT_RESIZE_RESPONSE;
    header.payload_len = sizeof(*response);
    if (send_exact(fd, &header, sizeof(header)) != 0)
        return -1;
    return send_exact(fd, response, sizeof(*response));
}

static int handle_resize_message(int fd, Display *display, uint32_t payload_len,
                                 const char *correlation_id, const char *session_id)
{
    frdpAgentResizeRequest request;
    frdpAgentResizeResponse response;
    int rc = -1;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    if (payload_len != sizeof(request))
        return -1;
    if (recv_exact(fd, &request, sizeof(request)) != 0)
        return -1;
    request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
    request.session_id[sizeof(request.session_id) - 1] = '\0';

    snprintf(response.correlation_id, sizeof(response.correlation_id), "%s", correlation_id);
    snprintf(response.session_id, sizeof(response.session_id), "%s", session_id);
    if (validate_agent_ids(request.correlation_id, request.session_id, correlation_id,
                           session_id) != 0) {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected mismatched resize request",
               escaped_correlation_id, escaped_session_id);
        snprintf(response.error, sizeof(response.error), "%s", "mismatched ids");
    } else if (resize_backend_display(display, &request, &response) != 0) {
        snprintf(response.error, sizeof(response.error), "%s", "resize failed");
    } else {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        syslog(LOG_INFO, "correlation_id=%s session_id=%s resized display to %ux%u",
               escaped_correlation_id, escaped_session_id, response.width, response.height);
    }

    rc = send_resize_response(fd, &response);
    return rc;
}

static int handle_frame_message(int fd, frdpAgentFrameState *frame_state, uint32_t payload_len,
                                const char *correlation_id, const char *session_id)
{
    frdpAgentFrameRequest request;
    frdpAgentFrameResponse response;
    unsigned char *pixels = NULL;
    int rc = -1;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    if (payload_len != sizeof(request))
        return -1;
    if (recv_exact(fd, &request, sizeof(request)) != 0)
        return -1;
    request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
    request.session_id[sizeof(request.session_id) - 1] = '\0';

    snprintf(response.correlation_id, sizeof(response.correlation_id), "%s", correlation_id);
    snprintf(response.session_id, sizeof(response.session_id), "%s", session_id);
    if (validate_agent_ids(request.correlation_id, request.session_id, correlation_id,
                           session_id) != 0) {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected mismatched frame request",
               escaped_correlation_id, escaped_session_id);
        snprintf(response.error, sizeof(response.error), "%s", "mismatched ids");
    } else if (capture_frame_tile(frame_state, &request, &response, &pixels) != 0) {
        snprintf(response.error, sizeof(response.error), "%s", "capture failed");
    }

    rc = send_frame_response(fd, &response, pixels);
    free(pixels);
    return rc;
}

static int handle_control_client(int fd, frdpAgentFrameState *frame_state, const char *correlation_id,
                                  const char *session_id)
{
    frdpIpcHeader header;

    memset(&header, 0, sizeof(header));

    if (set_control_timeouts(fd) != 0 || verify_control_peer(fd) != 0)
        return -1;
    if (recv_exact(fd, &header, sizeof(header)) != 0)
        return -1;

    switch (header.type) {
        case FRDP_IPC_AGENT_INPUT:
            return handle_input_message(fd, frame_state ? frame_state->display : NULL,
                                        header.payload_len, correlation_id, session_id);
        case FRDP_IPC_AGENT_FRAME_REQUEST:
            return handle_frame_message(fd, frame_state, header.payload_len, correlation_id, session_id);
        case FRDP_IPC_AGENT_RESIZE_REQUEST:
            return handle_resize_message(fd, frame_state ? frame_state->display : NULL,
                                         header.payload_len, correlation_id, session_id);
        default:
            return -1;
    }
}

static int wait_for_backend_exit(pid_t pid, int control_fd, frdpAgentFrameState *frame_state,
                                 const char *correlation_id,
                                 const char *session_id, int *stop_requested)
{
    int status = 0;

    if (stop_requested)
        *stop_requested = 0;

    while (1) {
        if (g_stop_requested) {
            if (stop_requested)
                *stop_requested = 1;
            return status;
        }

        const pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid)
            return status;
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return status;
        }

        if (control_fd < 0) {
            usleep(200000);
            continue;
        }

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = control_fd;
        pfd.events = POLLIN;
        const int poll_status = poll(&pfd, 1, 500);
        if (poll_status < 0) {
            if (errno == EINTR)
                continue;
            return status;
        }
        if (poll_status == 0 || (pfd.revents & POLLIN) == 0)
            continue;

        const int cfd = accept(control_fd, NULL, NULL);
        if (cfd < 0)
            continue;
        if (handle_control_client(cfd, frame_state, correlation_id, session_id) != 0) {
            char escaped_correlation_id[256] = { 0 };
            char escaped_session_id[256] = { 0 };

            escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                           sizeof(escaped_correlation_id), escaped_session_id,
                           sizeof(escaped_session_id));
            syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected agent control event",
                   escaped_correlation_id, escaped_session_id);
        }
        close(cfd);
    }
}

static int terminate_backend(pid_t pid)
{
    int status = 0;

    kill(pid, SIGTERM);
    for (int x = 0; x < 10; x++) {
        const pid_t stop_rc = waitpid(pid, &status, WNOHANG);
        if (stop_rc == pid)
            return status;
        if (stop_rc < 0) {
            if (errno == EINTR)
                continue;
            return status;
        }
        usleep(100000);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            break;
    }
    return status;
}

static void backend_exec_failed(int fd)
{
    const char marker = '!';

    if (fd >= 0) {
        const ssize_t rc = write(fd, &marker, sizeof(marker));
        (void)rc;
    }
    _exit(127);
}

static int wait_for_backend_exec(int fd, pid_t pid)
{
    struct pollfd pfd;
    char marker = 0;
    int status = 0;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLHUP;
    const int poll_status = poll(&pfd, 1, 10000);
    if (poll_status <= 0) {
        kill(pid, SIGKILL);
        for (int x = 0; x < 20; x++) {
            const pid_t rc = waitpid(pid, &status, WNOHANG);
            if (rc == pid || rc < 0)
                break;
            usleep(100000);
        }
        return -1;
    }

    const ssize_t rc = read(fd, &marker, sizeof(marker));
    if (rc == 0)
        return 0;

    for (int x = 0; x < 20; x++) {
        const pid_t wait_rc = waitpid(pid, &status, WNOHANG);
        if (wait_rc == pid || wait_rc < 0)
            break;
        usleep(100000);
    }
    return -1;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    openlog("frdp-session-agent", LOG_PID, LOG_USER);
    XInitThreads();

    if (install_signal_handlers() != 0) {
        syslog(LOG_ERR, "failed to install signal handlers");
        closelog();
        return 1;
    }

    const char *correlation_id = getenv("FRDP_CORRELATION_ID");
    if (!correlation_id) {
        correlation_id = "unknown";
    }
    const char *session_id = getenv("FRDP_SESSION_ID");
    if (!session_id) {
        session_id = "unknown";
    }
    char escaped_correlation_id[256] = { 0 };
    char escaped_session_id[256] = { 0 };

    escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                   sizeof(escaped_correlation_id), escaped_session_id, sizeof(escaped_session_id));
    int ready_fd = parse_ready_fd();
    if (ready_fd >= 0 && set_cloexec(ready_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark ready fd close-on-exec",
               escaped_correlation_id, escaped_session_id);
        close(ready_fd);
        closelog();
        return 1;
    }
    int control_fd = parse_control_fd();
    if (control_fd >= 0 && set_cloexec(control_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark control fd close-on-exec",
               escaped_correlation_id, escaped_session_id);
        if (ready_fd >= 0)
            close(ready_fd);
        closelog();
        return 1;
    }

    /* Determine display and geometry from environment. */
    const char *display = getenv("DISPLAY");
    if (!display) {
        display = getenv("FRDP_DISPLAY");
    }
    if (!display) {
        display = ":99";
    }
    const char *geometry = getenv("FRDP_GEOMETRY");
    if (!geometry) {
        geometry = "1024x768x24";
    }
    char escaped_display[256] = { 0 };
    char escaped_geometry[256] = { 0 };

    escape_log_field(display, escaped_display, sizeof(escaped_display));
    escape_log_field(geometry, escaped_geometry, sizeof(escaped_geometry));

    syslog(LOG_INFO, "correlation_id=%s session_id=%s display=%s geometry=%s session agent starting",
           escaped_correlation_id, escaped_session_id, escaped_display, escaped_geometry);

    int exec_pipe[2] = {-1, -1};
    if (pipe(exec_pipe) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to create backend exec pipe",
               escaped_correlation_id, escaped_session_id);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    if (fcntl(exec_pipe[1], F_SETFD, FD_CLOEXEC) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark backend exec pipe",
               escaped_correlation_id, escaped_session_id);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to fork for backend",
               escaped_correlation_id, escaped_session_id);
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    if (pid == 0) {
        close(exec_pipe[0]);
        if (control_fd >= 0)
            close(control_fd);
        if (ready_fd >= 0)
            close(ready_fd);
        /* Child: execute Xvfb.  Provide display and geometry. */
        execlp("Xvfb", "Xvfb", display, "-screen", "0", geometry, (char *)NULL);
        /* If exec fails, log to stderr and exit. */
        fprintf(stderr, "frdp-session-agent: failed to exec Xvfb\n");
        backend_exec_failed(exec_pipe[1]);
    }

    close(exec_pipe[1]);
    if (wait_for_backend_exec(exec_pipe[0], pid) != 0) {
        close(exec_pipe[0]);
        syslog(LOG_ERR, "correlation_id=%s session_id=%s backend failed to start",
               escaped_correlation_id, escaped_session_id);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    close(exec_pipe[0]);

    syslog(LOG_INFO, "correlation_id=%s session_id=%s backend started", escaped_correlation_id,
           escaped_session_id);

    Display *xdisplay = open_backend_display(display, correlation_id, session_id);
    if (!xdisplay) {
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    frdpAgentFrameState frame_state;
    if (frame_state_init(&frame_state, xdisplay, correlation_id, session_id) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to initialize frame state",
               escaped_correlation_id, escaped_session_id);
        XCloseDisplay(xdisplay);
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }
    if (notify_agent_ready(&ready_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to report agent readiness",
               escaped_correlation_id, escaped_session_id);
        frame_state_uninit(&frame_state);
        XCloseDisplay(xdisplay);
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (control_fd >= 0)
            close(control_fd);
        closelog();
        return 1;
    }

    /* TODO: add compression and update scheduling policy. */
    /* TODO: add Unicode/text input injection with explicit layout handling. */
    /* TODO: process clipboard/audio channels. */

    /* Wait for the display server to exit. */
    int stop_requested = 0;
    int status = wait_for_backend_exit(pid, control_fd, &frame_state, correlation_id, session_id,
                                       &stop_requested);
    if (stop_requested) {
        status = terminate_backend(pid);
    } else {
        frame_state_uninit(&frame_state);
        XCloseDisplay(xdisplay);
    }
    if (control_fd >= 0)
        close(control_fd);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s display server exited with status %d",
               escaped_correlation_id, escaped_session_id, WEXITSTATUS(status));
    }
    syslog(LOG_INFO, "correlation_id=%s session_id=%s display server exited, terminating agent",
           escaped_correlation_id, escaped_session_id);
    closelog();
    return 0;
}
