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
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/Xutil.h>
#include <X11/extensions/Xdamage.h>
#include <X11/extensions/Xrandr.h>
#include <X11/extensions/XTest.h>

#include <freerdp/input.h>

#include <winpr/input.h>
#include <winpr/platform.h>

#include "../ipc/frdp-ipc.h"
#include "../config/trusted-path.h"
#include "clipboard_x11.h"
#include "input_policy.h"

#define FRDP_AGENT_READY_MARKER 'R'
#define FRDP_AGENT_FRAME_TILE_MAX 120U
#define FRDP_AGENT_DAMAGE_EVENT_LIMIT 256U
#define FRDP_AGENT_DISPLAY_SIZE_MAX 8192U
#define FRDP_AGENT_CONTROL_STALL_MS 10000U
#define FRDP_XAUTH_COOKIE_SIZE 16U
#define FRDP_XAUTH_FAMILY_WILD 65535U

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

typedef struct {
    frdpAgentUnicodeInputState unicode;
    char correlation_id[sizeof(((frdpAgentInputEvent *)0)->correlation_id)];
} frdpAgentInputState;

typedef enum
{
	FRDP_AGENT_BACKEND_XVFB = 0,
	FRDP_AGENT_BACKEND_XORG_DUMMY = 1
} frdpAgentDisplayBackend;

static volatile int g_x11_resize_error = 0;
static volatile int g_x11_keyboard_error = 0;
static volatile sig_atomic_t g_stop_requested = 0;
static _Atomic uint64_t g_control_progress_ms = 0;

#if defined(FRDP_AGENT_TESTING)
static int g_test_refresh_fault_consumed = 0;

static int test_resize_fault_is(const char* name)
{
	const char* fault = getenv("FRDP_AGENT_TEST_RESIZE_FAULT");

	return fault && strcmp(fault, name) == 0;
}

static int test_refresh_fault_once(void)
{
	if (!g_test_refresh_fault_consumed && test_resize_fault_is("refresh"))
	{
		g_test_refresh_fault_consumed = 1;
		return 1;
	}
	return 0;
}
#endif

static uint64_t agent_monotonic_ms(void)
{
    struct timespec now = { 0 };

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static void note_control_progress(void)
{
    atomic_store_explicit(&g_control_progress_ms, agent_monotonic_ms(), memory_order_release);
}

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

static int parse_backend_geometry(const char* geometry, uint32_t* width, uint32_t* height,
                                  uint32_t* depth)
{
	unsigned int parsed_width = 0;
	unsigned int parsed_height = 0;
	unsigned int parsed_depth = 0;
	char trailing = '\0';

	if (!geometry || !width || !height || !depth ||
	    sscanf(geometry, "%ux%ux%u%c", &parsed_width, &parsed_height, &parsed_depth, &trailing) !=
	        3)
		return -1;
	if (parsed_width == 0U || parsed_height == 0U || parsed_width > FRDP_AGENT_DISPLAY_SIZE_MAX ||
	    parsed_height > FRDP_AGENT_DISPLAY_SIZE_MAX || parsed_depth < 8U || parsed_depth > 32U)
		return -1;
	*width = parsed_width;
	*height = parsed_height;
	*depth = parsed_depth;
	return 0;
}

static int load_display_backend(frdpAgentDisplayBackend* backend, const char** xorg_path,
                                const char** xorg_config)
{
	const char* name = getenv("FRDP_DISPLAY_BACKEND");

	if (!backend || !xorg_path || !xorg_config)
		return -1;
	*xorg_path = NULL;
	*xorg_config = NULL;
	if (!name || strcmp(name, "xvfb") == 0)
	{
		*backend = FRDP_AGENT_BACKEND_XVFB;
		return 0;
	}
	if (strcmp(name, "xorg-dummy") != 0)
		return -1;
	*xorg_path = getenv("FRDP_XORG_PATH");
	*xorg_config = getenv("FRDP_XORG_CONFIG");
	if (!frdp_trusted_root_file(*xorg_path, 1) || !frdp_trusted_root_file(*xorg_config, 0))
		return -1;
	*backend = FRDP_AGENT_BACKEND_XORG_DUMMY;
	return 0;
}

static int write_exact(int fd, const void* data, size_t size)
{
	const unsigned char* current = (const unsigned char*)data;

	while (size > 0)
	{
		const ssize_t rc = write(fd, current, size);

		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
			return -1;
		current += (size_t)rc;
		size -= (size_t)rc;
	}
	return 0;
}

static int write_xauthority_field(int fd, const void* data, size_t size)
{
	const unsigned char length[2] = { (unsigned char)((size >> 8U) & 0xffU),
	                                  (unsigned char)(size & 0xffU) };

	if (size > UINT16_MAX || write_exact(fd, length, sizeof(length)) != 0)
		return -1;
	return size == 0 ? 0 : write_exact(fd, data, size);
}

static void erase_secret(void* data, size_t size)
{
	volatile unsigned char* current = (volatile unsigned char*)data;

	while (size-- > 0)
		*current++ = 0;
}

static int fill_random(void* data, size_t size)
{
	unsigned char* current = (unsigned char*)data;
	int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	while (size > 0)
	{
		const ssize_t rc = read(fd, current, size);

		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
		{
			close(fd);
			return -1;
		}
		current += (size_t)rc;
		size -= (size_t)rc;
	}
	close(fd);
	return 0;
}

static int create_xauthority(const char* display, char* authority_path, size_t authority_path_size)
{
	static const char auth_name[] = "MIT-MAGIC-COOKIE-1";
	char template[] = "/tmp/.frdp-xauthority-XXXXXX";
	unsigned char cookie[FRDP_XAUTH_COOKIE_SIZE] = { 0 };
	const char* number = display ? strrchr(display, ':') : NULL;
	const char* number_end = NULL;
	const unsigned char family[2] = { 0xffU, 0xffU };
	int fd = -1;
	int flags = 0;
	int ok = 0;
	int path_length = 0;

	if (!number || *(++number) == '\0' || !authority_path || authority_path_size == 0)
		return -1;
	number_end = number;
	while (*number_end >= '0' && *number_end <= '9')
		number_end++;
	if (number_end == number || (*number_end != '\0' && *number_end != '.'))
		return -1;

	fd = mkstemp(template);
	if (fd < 0)
		return -1;
	flags = fcntl(fd, F_GETFD);
	if (fchmod(fd, S_IRUSR | S_IWUSR) != 0 || fill_random(cookie, sizeof(cookie)) != 0 ||
	    write_exact(fd, family, sizeof(family)) != 0 || write_xauthority_field(fd, NULL, 0) != 0 ||
	    write_xauthority_field(fd, number, (size_t)(number_end - number)) != 0 ||
	    write_xauthority_field(fd, auth_name, sizeof(auth_name) - 1U) != 0 ||
	    write_xauthority_field(fd, cookie, sizeof(cookie)) != 0 || fsync(fd) != 0 ||
	    lseek(fd, 0, SEEK_SET) < 0 || flags < 0 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0)
		goto cleanup;
	path_length = snprintf(authority_path, authority_path_size, "/proc/self/fd/%d", fd);
	if (path_length < 0 || (size_t)path_length >= authority_path_size ||
	    setenv("XAUTHORITY", authority_path, 1) != 0)
		goto cleanup;
	ok = 1;

cleanup:
	erase_secret(cookie, sizeof(cookie));
	if (unlink(template) != 0)
		ok = 0;
	if (!ok)
	{
		close(fd);
		return -1;
	}
	return fd;
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

    return (KeySym)frdp_agent_unicode_scalar_to_keysym(codepoint);
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

static int inject_unicode_event(Display *display, const frdpAgentInputEvent *event,
                                frdpAgentUnicodeInputState *state)
{
    KeySym keysym = NoSymbol;
    uint32_t codepoint = 0;
    int decode_status = 0;

    if (!display || !event || !state)
        return -1;
    decode_status = frdp_agent_unicode_input_decode(state, event, &codepoint);
    if (decode_status < 0)
        return -1;
    if (decode_status == 0)
        return 0;

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

static int inject_input_event(Display *display, const frdpAgentInputEvent *event,
                              frdpAgentInputState *state)
{
    int rc = 0;

    if (!display || !event || !state)
        return -1;
    if (event->event_type != FRDP_AGENT_INPUT_UNICODE)
        frdp_agent_unicode_input_reset(&state->unicode);
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
            rc = inject_unicode_event(display, event, &state->unicode);
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

static int root_window_size(Display* display, Window root, uint32_t* width, uint32_t* height)
{
	XWindowAttributes attributes;

	if (!display || root == None || !width || !height)
		return -1;
	memset(&attributes, 0, sizeof(attributes));
	if (!XGetWindowAttributes(display, root, &attributes) || attributes.width <= 0 ||
	    attributes.height <= 0)
		return -1;
	*width = (uint32_t)attributes.width;
	*height = (uint32_t)attributes.height;
	return 0;
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
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t cols = 0;
    uint32_t rows = 0;
    size_t count = 0;
    unsigned char *dirty_tiles = NULL;

    if (!state || !state->display)
        return -1;

    XLockDisplay(state->display);
    screen = DefaultScreen(state->display);
    state->root = RootWindow(state->display, screen);
    const int geometry_status = root_window_size(state->display, state->root, &width, &height);
    XUnlockDisplay(state->display);

    if (geometry_status != 0)
        return -1;
    cols = (width + FRDP_AGENT_FRAME_TILE_MAX - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    rows = (height + FRDP_AGENT_FRAME_TILE_MAX - 1U) / FRDP_AGENT_FRAME_TILE_MAX;
    if (cols == 0 || rows == 0 || cols > SIZE_MAX / rows)
        return -1;
    count = (size_t)cols * rows;
    if (count > SIZE_MAX / sizeof(*dirty_tiles))
        return -1;
    if (state->dirty_tiles && state->screen == screen && state->screen_width == width &&
        state->screen_height == height && state->dirty_cols == cols && state->dirty_rows == rows)
        return 0;

    dirty_tiles = (unsigned char *)calloc(count, sizeof(*dirty_tiles));
    if (!dirty_tiles)
        return -1;
    memset(dirty_tiles, 1, count);
    free(state->dirty_tiles);
    state->dirty_tiles = dirty_tiles;
    state->screen = screen;
    state->screen_width = width;
    state->screen_height = height;
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

static void frame_state_free_dirty_tiles(frdpAgentFrameState *state)
{
    if (!state)
        return;
    free(state->dirty_tiles);
    state->dirty_tiles = NULL;
    state->dirty_cols = 0;
    state->dirty_rows = 0;
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
    frame_state_free_dirty_tiles(state);
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
    if (request->flags &
        ~((uint32_t)FRDP_AGENT_FRAME_REQUEST_FORCE | (uint32_t)FRDP_AGENT_FRAME_REQUEST_DIRTY_ONLY))
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

static int parse_heartbeat_fd(void)
{
    return parse_env_fd("FRDP_AGENT_HEARTBEAT_FD");
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

static int create_cloexec_pipe(int pipefd[2])
{
    if (!pipefd)
        return -1;

#if defined(__linux__) && defined(O_CLOEXEC)
    if (pipe2(pipefd, O_CLOEXEC) == 0)
        return 0;
    if (errno != EINVAL && errno != ENOSYS)
        return -1;
#endif

    if (pipe(pipefd) != 0)
        return -1;
    if (set_cloexec(pipefd[0]) != 0 || set_cloexec(pipefd[1]) != 0) {
        int saved = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        pipefd[0] = -1;
        pipefd[1] = -1;
        errno = saved;
        return -1;
    }
    return 0;
}

static int accept_cloexec(int fd)
{
    int cfd = -1;

#if defined(__linux__) && defined(SOCK_CLOEXEC)
    cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if ((cfd == -1) && (errno == EINVAL || errno == ENOSYS))
#endif
        cfd = accept(fd, NULL, NULL);
    if (cfd < 0)
        return -1;
    if (set_cloexec(cfd) != 0) {
        int saved = errno;
        close(cfd);
        errno = saved;
        return -1;
    }
    return cfd;
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
	(void)correlation_id;
	if (!event_correlation_id || event_correlation_id[0] == '\0')
		return -1;
    if (strcmp(event_session_id, session_id) != 0)
        return -1;
    return 0;
}

static RRMode output_mode_for_size(const XRRScreenResources* resources, const XRROutputInfo* output,
                                   uint32_t width, uint32_t height)
{
	if (!resources || !output)
		return None;
	for (int output_mode = 0; output_mode < output->nmode; output_mode++)
	{
		for (int mode = 0; mode < resources->nmode; mode++)
		{
			if (resources->modes[mode].id == output->modes[output_mode] &&
			    resources->modes[mode].width == width && resources->modes[mode].height == height)
				return resources->modes[mode].id;
		}
	}
	return None;
}

static int resize_physical_mm(uint32_t pixels)
{
	const uint32_t millimeters = (pixels * 254U) / 960U;

	return (millimeters > 0U) ? (int)millimeters : 1;
}

static int set_screen_size_checked(Display* display, Window root, uint32_t width, uint32_t height)
{
	g_x11_resize_error = 0;
	XRRSetScreenSize(display, root, (int)width, (int)height, resize_physical_mm(width),
	                 resize_physical_mm(height));
	XSync(display, False);
	return (g_x11_resize_error == 0) ? 0 : -1;
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
	uint32_t old_width = 0;
	uint32_t old_height = 0;
	uint32_t staging_width = 0;
	uint32_t staging_height = 0;
	RROutput primary = None;
	RROutput output = None;
	RRMode mode = None;
	XRRScreenResources* resources = NULL;
	XRRScreenResources* rollback_resources = NULL;
	XRRScreenResources* verify_resources = NULL;
	XRROutputInfo* output_info = NULL;
	XRRCrtcInfo* crtc_info = NULL;
	XRRCrtcInfo* verify_crtc_info = NULL;
	XErrorHandler previous_handler = NULL;
	int handler_set = 0;
	int crtc_changed = 0;
	int rollback_failed = 0;
	int staging_restore_status = 0;
	int rc = -1;
	Status crtc_status = Success;

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
	if (root_window_size(display, root, &old_width, &old_height) != 0)
		goto out;
	if (old_width == request->width && old_height == request->height)
	{
		response->success = 1;
		response->width = request->width;
		response->height = request->height;
		XUnlockDisplay(display);
		return 0;
	}

	resources = XRRGetScreenResourcesCurrent(display, root);
	if (!resources)
		goto out;
	primary = XRRGetOutputPrimary(display, root);
	for (int pass = 0; pass < 2 && output == None; pass++)
	{
		for (int index = 0; index < resources->noutput; index++)
		{
			const RROutput candidate = resources->outputs[index];

			if ((pass == 0 && (primary == None || candidate != primary)) ||
			    (pass == 1 && candidate == primary))
				continue;
			XRROutputInfo* candidate_info = XRRGetOutputInfo(display, resources, candidate);
			if (!candidate_info)
				continue;
			const RRMode candidate_mode =
			    output_mode_for_size(resources, candidate_info, request->width, request->height);
			if (candidate_info->connection == RR_Connected && candidate_info->crtc != None &&
			    candidate_mode != None)
			{
				output = candidate;
				output_info = candidate_info;
				mode = candidate_mode;
				break;
			}
			XRRFreeOutputInfo(candidate_info);
		}
	}
	if (output == None || !output_info || mode == None)
		goto out;
	crtc_info = XRRGetCrtcInfo(display, resources, output_info->crtc);
	if (!crtc_info || crtc_info->mode == None || crtc_info->noutput != 1 ||
	    crtc_info->outputs[0] != output)
		goto out;

	staging_width = (old_width > request->width) ? old_width : request->width;
	staging_height = (old_height > request->height) ? old_height : request->height;
	previous_handler = XSetErrorHandler(resize_error_handler);
	handler_set = 1;
	if ((staging_width != old_width || staging_height != old_height) &&
	    set_screen_size_checked(display, root, staging_width, staging_height) != 0)
		goto rollback;
	g_x11_resize_error = 0;
	crtc_status =
	    XRRSetCrtcConfig(display, resources, output_info->crtc, resources->configTimestamp, 0, 0,
	                     mode, crtc_info->rotation, &output, 1);
	if (crtc_status != Success)
		goto rollback;
	crtc_changed = 1;
	XSync(display, False);
#if defined(FRDP_AGENT_TESTING)
	if (test_resize_fault_is("after-crtc") || test_resize_fault_is("rollback"))
		goto rollback;
#endif
	if (g_x11_resize_error != 0 ||
	    set_screen_size_checked(display, root, request->width, request->height) != 0)
		goto rollback;
	uint32_t applied_width = 0;
	uint32_t applied_height = 0;
	if (root_window_size(display, root, &applied_width, &applied_height) != 0 ||
	    applied_width != request->width || applied_height != request->height)
		goto rollback;

	response->success = 1;
    response->width = request->width;
    response->height = request->height;
	rc = 0;
	goto out;

rollback:
	staging_restore_status = set_screen_size_checked(display, root, staging_width, staging_height);
	if (staging_restore_status != 0 && crtc_changed)
		rollback_failed = 1;
	if (crtc_changed)
	{
		rollback_resources = XRRGetScreenResourcesCurrent(display, root);
		if (rollback_resources)
		{
			g_x11_resize_error = 0;
			crtc_status = XRRSetCrtcConfig(
			    display, rollback_resources, output_info->crtc,
			    rollback_resources->configTimestamp, crtc_info->x, crtc_info->y, crtc_info->mode,
			    crtc_info->rotation, crtc_info->outputs, crtc_info->noutput);
			XSync(display, False);
			if (crtc_status != Success || g_x11_resize_error != 0)
				rollback_failed = 1;
		}
		else
			rollback_failed = 1;
	}
	verify_resources = XRRGetScreenResourcesCurrent(display, root);
	if (crtc_changed && verify_resources)
		verify_crtc_info =
		    XRRGetCrtcInfo(display, verify_resources, output_info->crtc);
	if (crtc_changed &&
	    (!verify_resources || !verify_crtc_info || verify_crtc_info->x != crtc_info->x ||
	     verify_crtc_info->y != crtc_info->y || verify_crtc_info->mode != crtc_info->mode ||
	     verify_crtc_info->rotation != crtc_info->rotation ||
	     verify_crtc_info->noutput != crtc_info->noutput))
		rollback_failed = 1;
	if (crtc_changed && verify_crtc_info && verify_crtc_info->noutput == crtc_info->noutput)
	{
		for (int index = 0; index < crtc_info->noutput; index++)
		{
			if (verify_crtc_info->outputs[index] != crtc_info->outputs[index])
				rollback_failed = 1;
		}
	}
	if (set_screen_size_checked(display, root, old_width, old_height) != 0)
		rollback_failed = 1;
	uint32_t restored_width = 0;
	uint32_t restored_height = 0;
	if (root_window_size(display, root, &restored_width, &restored_height) != 0 ||
	    restored_width != old_width || restored_height != old_height)
		rollback_failed = 1;
#if defined(FRDP_AGENT_TESTING)
	if (test_resize_fault_is("rollback"))
		rollback_failed = 1;
#endif
	if (rollback_failed)
		rc = -2;

out:
	if (handler_set)
		XSetErrorHandler(previous_handler);
	if (crtc_info)
		XRRFreeCrtcInfo(crtc_info);
	if (output_info)
		XRRFreeOutputInfo(output_info);
	if (resources)
		XRRFreeScreenResources(resources);
	if (rollback_resources)
		XRRFreeScreenResources(rollback_resources);
	if (verify_crtc_info)
		XRRFreeCrtcInfo(verify_crtc_info);
	if (verify_resources)
		XRRFreeScreenResources(verify_resources);
	XUnlockDisplay(display);
	return rc;
}

static int handle_input_message(int fd, Display *display, frdpAgentInputState *input_state,
                                uint32_t payload_len,
                                const char *correlation_id, const char *session_id)
{
    frdpAgentInputEvent event;

    memset(&event, 0, sizeof(event));

    if (!input_state)
        return -1;
    if (frdp_ipc_recv_agent_input_event_payload(fd, &event, payload_len) != 0) {
        frdp_agent_unicode_input_reset(&input_state->unicode);
        return -1;
    }

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
        frdp_agent_unicode_input_reset(&input_state->unicode);
        return -1;
    }
    if (!frdp_agent_input_event_payload_is_valid(&event)) {
        char escaped_correlation_id[256] = { 0 };
        char escaped_session_id[256] = { 0 };

        escape_log_ids(correlation_id, session_id, escaped_correlation_id,
                       sizeof(escaped_correlation_id), escaped_session_id,
                       sizeof(escaped_session_id));
        syslog(LOG_WARNING, "correlation_id=%s session_id=%s rejected malformed input event",
               escaped_correlation_id, escaped_session_id);
        frdp_agent_unicode_input_reset(&input_state->unicode);
        return -1;
    }

    if (strcmp(input_state->correlation_id, event.correlation_id) != 0) {
        frdp_agent_unicode_input_reset(&input_state->unicode);
        snprintf(input_state->correlation_id, sizeof(input_state->correlation_id), "%s",
                 event.correlation_id);
    }

    return inject_input_event(display, &event, input_state);
}

static int send_frame_response(int fd, const frdpAgentFrameResponse *response,
                               const unsigned char *pixels)
{
    if (frdp_ipc_send_agent_frame_response(fd, response) != 0)
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
    return frdp_ipc_send_agent_resize_response(fd, response);
}

static int handle_resize_message(int fd, frdpAgentFrameState* frame_state, uint32_t payload_len,
                                 const char* correlation_id, const char* session_id)
{
    frdpAgentResizeRequest request;
	frdpAgentResizeResponse response;
	frdpAgentResizeRequest rollback_request;
	frdpAgentResizeResponse rollback_response;
	int rc = -1;
	int refresh_failed = 0;
	int resize_status = -1;
	uint32_t old_width = 0;
	uint32_t old_height = 0;

	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));
	memset(&rollback_request, 0, sizeof(rollback_request));
	memset(&rollback_response, 0, sizeof(rollback_response));

    if (frdp_ipc_recv_agent_resize_request_payload(fd, &request, payload_len) != 0)
        return -1;
    request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
    request.session_id[sizeof(request.session_id) - 1] = '\0';

    snprintf(response.correlation_id, sizeof(response.correlation_id), "%s", request.correlation_id);
    snprintf(response.session_id, sizeof(response.session_id), "%s", request.session_id);
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
	}
	else if (!frame_state)
	{
		snprintf(response.error, sizeof(response.error), "%s", "resize failed");
	}
	else
	{
		old_width = frame_state->screen_width;
		old_height = frame_state->screen_height;
		resize_status = resize_backend_display(frame_state->display, &request, &response);
		if (resize_status == 0)
		{
#if defined(FRDP_AGENT_TESTING)
			refresh_failed = test_refresh_fault_once();
#endif
			if (!refresh_failed)
				refresh_failed = frame_state_refresh_geometry(frame_state) != 0;
			if (refresh_failed)
			{
				rollback_request.width = old_width;
				rollback_request.height = old_height;
				rollback_request.color_depth = request.color_depth;
				if (resize_backend_display(frame_state->display, &rollback_request,
				                           &rollback_response) != 0 ||
				    frame_state_refresh_geometry(frame_state) != 0)
					resize_status = -2;
				else
					resize_status = -1;
			}
		}
		if (resize_status != 0)
		{
			response.success = 0;
			response.width = 0;
			response.height = 0;
			snprintf(response.error, sizeof(response.error), "%s", "resize failed");
			if (resize_status == -2)
				g_stop_requested = 1;
		}
		else
		{
			char escaped_correlation_id[256] = { 0 };
			char escaped_session_id[256] = { 0 };

			escape_log_ids(correlation_id, session_id, escaped_correlation_id,
			               sizeof(escaped_correlation_id), escaped_session_id,
			               sizeof(escaped_session_id));
			syslog(LOG_INFO, "correlation_id=%s session_id=%s resized display to %ux%u",
			       escaped_correlation_id, escaped_session_id, response.width, response.height);
		}
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

    if (frdp_ipc_recv_agent_frame_request_payload(fd, &request, payload_len) != 0)
        return -1;
    request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
    request.session_id[sizeof(request.session_id) - 1] = '\0';

    snprintf(response.correlation_id, sizeof(response.correlation_id), "%s", request.correlation_id);
    snprintf(response.session_id, sizeof(response.session_id), "%s", request.session_id);
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

typedef struct {
    int fd;
    char session_id[64];
} frdpAgentHeartbeatThreadContext;

static void *heartbeat_thread_main(void *arg)
{
    frdpAgentHeartbeatThreadContext *context = (frdpAgentHeartbeatThreadContext *)arg;

    if (!context || (set_control_timeouts(context->fd) != 0))
        return NULL;
    for (;;) {
        frdpAgentHeartbeat heartbeat = { 0 };

        if (frdp_ipc_recv_agent_heartbeat_request_packet(context->fd, &heartbeat) != 0) {
            if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
                continue;
            break;
        }
        heartbeat.session_id[sizeof(heartbeat.session_id) - 1] = '\0';
        const uint64_t now_ms = agent_monotonic_ms();
        const uint64_t progress_ms =
            atomic_load_explicit(&g_control_progress_ms, memory_order_acquire);

        if ((heartbeat.nonce == 0) ||
            (strcmp(heartbeat.session_id, context->session_id) != 0))
            break;
        if ((now_ms == 0) || (progress_ms == 0) || (now_ms < progress_ms) ||
            ((now_ms - progress_ms) > FRDP_AGENT_CONTROL_STALL_MS))
            continue;
        if (frdp_ipc_send_agent_heartbeat_response_packet(context->fd, &heartbeat) != 0)
            break;
    }
    return NULL;
}

static void init_clipboard_response(frdpAgentClipboardResponse *response,
                                    const char *correlation_id, const char *session_id)
{
    memset(response, 0, sizeof(*response));
    snprintf(response->correlation_id, sizeof(response->correlation_id), "%s", correlation_id);
    snprintf(response->session_id, sizeof(response->session_id), "%s", session_id);
}

static int handle_clipboard_set_message(int fd, frdpAgentClipboardX11 *clipboard,
                                        uint32_t payload_len, const char *correlation_id,
                                        const char *session_id)
{
    frdpAgentClipboardRequest request = { 0 };
    frdpAgentClipboardResponse response = { 0 };
    uint8_t *text = NULL;
    int rc = -1;

    if (frdp_ipc_recv_agent_clipboard_set_request_payload(fd, &request, &text, payload_len) != 0)
        return -1;
    request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
    request.session_id[sizeof(request.session_id) - 1] = '\0';
    init_clipboard_response(&response, request.correlation_id, request.session_id);
    if (validate_agent_ids(request.correlation_id, request.session_id, correlation_id,
                           session_id) != 0) {
        snprintf(response.error, sizeof(response.error), "%s", "mismatched ids");
    } else if (frdp_agent_clipboard_x11_set_text(clipboard, text, request.text_length,
                                                  request.max_text_bytes) != 0) {
        snprintf(response.error, sizeof(response.error), "%s", "clipboard set failed");
    } else {
        response.success = 1;
    }
    rc = frdp_ipc_send_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_SET_RESPONSE,
                                                 &response, NULL);
    free(text);
    return rc;
}

static int handle_clipboard_get_message(int fd, frdpAgentClipboardX11 *clipboard,
                                        uint32_t payload_len, const char *correlation_id,
                                        const char *session_id)
{
    frdpAgentClipboardRequest request = { 0 };
    frdpAgentClipboardResponse response = { 0 };
    uint8_t *text = NULL;
    int rc = -1;

    if (frdp_ipc_recv_agent_clipboard_get_request_payload(fd, &request, payload_len) != 0)
        return -1;
    request.correlation_id[sizeof(request.correlation_id) - 1] = '\0';
    request.session_id[sizeof(request.session_id) - 1] = '\0';
    init_clipboard_response(&response, request.correlation_id, request.session_id);
    if (validate_agent_ids(request.correlation_id, request.session_id, correlation_id,
                           session_id) != 0) {
        snprintf(response.error, sizeof(response.error), "%s", "mismatched ids");
    } else if (frdp_agent_clipboard_x11_get_text(clipboard, request.max_text_bytes, &text,
                                                  &response.text_length) != 0) {
        snprintf(response.error, sizeof(response.error), "%s", "clipboard get failed");
    } else {
        response.success = 1;
    }
    rc = frdp_ipc_send_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_GET_RESPONSE,
                                                 &response, text);
    free(text);
    return rc;
}

static int handle_control_client(int fd, frdpAgentFrameState *frame_state,
                                 frdpAgentClipboardX11 *clipboard,
                                 frdpAgentInputState *input_state, const char *correlation_id,
                                 const char *session_id)
{
    frdpIpcHeader header;

    memset(&header, 0, sizeof(header));

    if (set_control_timeouts(fd) != 0 || verify_control_peer(fd) != 0)
        return -1;
    if (frdp_ipc_recv_header(fd, &header) != (int)sizeof(header))
        return -1;

    switch (header.type) {
        case FRDP_IPC_AGENT_INPUT:
            return handle_input_message(fd, frame_state ? frame_state->display : NULL, input_state,
                                        header.payload_len, correlation_id, session_id);
        case FRDP_IPC_AGENT_FRAME_REQUEST:
            return handle_frame_message(fd, frame_state, header.payload_len, correlation_id, session_id);
        case FRDP_IPC_AGENT_RESIZE_REQUEST:
			return handle_resize_message(fd, frame_state, header.payload_len, correlation_id,
			                             session_id);
		case FRDP_IPC_AGENT_CLIPBOARD_SET_REQUEST:
            return handle_clipboard_set_message(fd, clipboard, header.payload_len, correlation_id,
                                                session_id);
        case FRDP_IPC_AGENT_CLIPBOARD_GET_REQUEST:
            return handle_clipboard_get_message(fd, clipboard, header.payload_len, correlation_id,
                                                session_id);
        default:
            return -1;
    }
}

static int wait_for_backend_exit(pid_t pid, int control_fd, frdpAgentFrameState *frame_state,
                                 frdpAgentClipboardX11 *clipboard, const char *correlation_id,
                                 const char *session_id, int *stop_requested)
{
    int status = 0;
    frdpAgentInputState input_state = { 0 };

    if (stop_requested)
        *stop_requested = 0;

    while (1) {
        note_control_progress();
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

        struct pollfd pfds[2] = { { 0 } };
        nfds_t count = 0;
        int control_index = -1;
        int x11_index = -1;

        if (control_fd >= 0) {
            control_index = (int)count;
            pfds[count].fd = control_fd;
            pfds[count].events = POLLIN;
            count++;
        }
        if (clipboard && clipboard->display) {
            if (XPending(clipboard->display) > 0)
                frdp_agent_clipboard_x11_process_events(clipboard);
            x11_index = (int)count;
            pfds[count].fd = ConnectionNumber(clipboard->display);
            pfds[count].events = POLLIN;
            count++;
        }
        const int poll_status = poll(pfds, count, 500);
        if (poll_status < 0) {
            if (errno == EINTR)
                continue;
            return status;
        }
        if ((x11_index >= 0) &&
            ((pfds[x11_index].revents & POLLIN) || (XPending(clipboard->display) > 0)))
            frdp_agent_clipboard_x11_process_events(clipboard);
        if ((poll_status == 0) || (control_index < 0) ||
            ((pfds[control_index].revents & POLLIN) == 0))
            continue;

        const int cfd = accept_cloexec(control_fd);
        if (cfd < 0)
            continue;
        if (handle_control_client(cfd, frame_state, clipboard, &input_state, correlation_id,
                                  session_id) != 0) {
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

WINPR_NORETURN(static void backend_exec_failed(int fd))
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
    int heartbeat_fd = parse_heartbeat_fd();
    if (heartbeat_fd >= 0 && set_cloexec(heartbeat_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to mark heartbeat fd close-on-exec",
               escaped_correlation_id, escaped_session_id);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        close(heartbeat_fd);
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
	frdpAgentDisplayBackend backend = FRDP_AGENT_BACKEND_XVFB;
	const char* xorg_path = NULL;
	const char* xorg_config = NULL;
	uint32_t initial_width = 0;
	uint32_t initial_height = 0;
	uint32_t initial_depth = 0;

	if (load_display_backend(&backend, &xorg_path, &xorg_config) != 0 ||
	    parse_backend_geometry(geometry, &initial_width, &initial_height, &initial_depth) != 0)
	{
		syslog(LOG_ERR, "correlation_id=%s session_id=%s invalid display backend configuration",
		       escaped_correlation_id, escaped_session_id);
		if (ready_fd >= 0)
			close(ready_fd);
		if (control_fd >= 0)
			close(control_fd);
		if (heartbeat_fd >= 0)
			close(heartbeat_fd);
		closelog();
		return 1;
	}
	char escaped_display[256] = { 0 };
    char escaped_geometry[256] = { 0 };

    escape_log_field(display, escaped_display, sizeof(escaped_display));
    escape_log_field(geometry, escaped_geometry, sizeof(escaped_geometry));

	syslog(
	    LOG_INFO,
	    "correlation_id=%s session_id=%s display=%s geometry=%s backend=%s session agent starting",
	    escaped_correlation_id, escaped_session_id, escaped_display, escaped_geometry,
	    (backend == FRDP_AGENT_BACKEND_XORG_DUMMY) ? "xorg-dummy" : "xvfb");
	char authority_path[64] = { 0 };
	int authority_fd = create_xauthority(display, authority_path, sizeof(authority_path));

	if (authority_fd < 0)
	{
		syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to create Xauthority",
		       escaped_correlation_id, escaped_session_id);
		if (ready_fd >= 0)
			close(ready_fd);
		if (control_fd >= 0)
			close(control_fd);
		if (heartbeat_fd >= 0)
			close(heartbeat_fd);
		closelog();
		return 1;
	}

	int exec_pipe[2] = {-1, -1};
    if (create_cloexec_pipe(exec_pipe) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to create backend exec pipe",
               escaped_correlation_id, escaped_session_id);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
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
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
        closelog();
        return 1;
    }
    if (pid == 0) {
        close(exec_pipe[0]);
        if (control_fd >= 0)
            close(control_fd);
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
        if (ready_fd >= 0)
            close(ready_fd);
		if (backend == FRDP_AGENT_BACKEND_XORG_DUMMY)
		{
			execl(xorg_path, xorg_path, display, "-config", xorg_config, "-auth", authority_path,
			      "-noreset", "-nolisten", "tcp", "-logfile", "/dev/null", (char*)NULL);
		}
		else
		{
			execlp("Xvfb", "Xvfb", display, "-screen", "0", geometry, "-auth", authority_path,
			       "-nolisten", "tcp", (char*)NULL);
		}
		fprintf(stderr, "frdp-session-agent: failed to exec display backend\n");
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
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
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
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
        closelog();
        return 1;
    }
	if (backend == FRDP_AGENT_BACKEND_XORG_DUMMY)
	{
		frdpAgentResizeRequest request = {
			.width = initial_width,
			.height = initial_height,
			.color_depth = initial_depth,
		};
		frdpAgentResizeResponse response = { 0 };

		if (resize_backend_display(xdisplay, &request, &response) != 0)
		{
			syslog(LOG_ERR,
			       "correlation_id=%s session_id=%s failed to apply initial display geometry",
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
			if (heartbeat_fd >= 0)
				close(heartbeat_fd);
			close(authority_fd);
			closelog();
			return 1;
		}
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
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
        closelog();
        return 1;
    }
    frdpAgentClipboardX11 clipboard;
    if (frdp_agent_clipboard_x11_init(&clipboard, xdisplay) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to initialize clipboard state",
               escaped_correlation_id, escaped_session_id);
        frame_state_uninit(&frame_state);
        XCloseDisplay(xdisplay);
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (ready_fd >= 0)
            close(ready_fd);
        if (control_fd >= 0)
            close(control_fd);
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
        closelog();
        return 1;
    }
    pthread_t heartbeat_thread;
    int heartbeat_thread_started = 0;
    frdpAgentHeartbeatThreadContext heartbeat_context = { .fd = heartbeat_fd };

    snprintf(heartbeat_context.session_id, sizeof(heartbeat_context.session_id), "%s", session_id);
    note_control_progress();
    if (heartbeat_fd >= 0) {
        if (pthread_create(&heartbeat_thread, NULL, heartbeat_thread_main, &heartbeat_context) != 0) {
            syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to start heartbeat thread",
                   escaped_correlation_id, escaped_session_id);
            frdp_agent_clipboard_x11_uninit(&clipboard);
            frame_state_uninit(&frame_state);
            XCloseDisplay(xdisplay);
            kill(pid, SIGTERM);
            usleep(200000);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            if (ready_fd >= 0)
                close(ready_fd);
            if (control_fd >= 0)
                close(control_fd);
            close(heartbeat_fd);
			close(authority_fd);
            closelog();
            return 1;
        }
        heartbeat_thread_started = 1;
    }
    if (notify_agent_ready(&ready_fd) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s failed to report agent readiness",
               escaped_correlation_id, escaped_session_id);
        frdp_agent_clipboard_x11_uninit(&clipboard);
        frame_state_uninit(&frame_state);
        XCloseDisplay(xdisplay);
        kill(pid, SIGTERM);
        usleep(200000);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        if (control_fd >= 0)
            close(control_fd);
        if (heartbeat_thread_started) {
            shutdown(heartbeat_fd, SHUT_RDWR);
            (void)pthread_join(heartbeat_thread, NULL);
        }
        if (heartbeat_fd >= 0)
            close(heartbeat_fd);
		close(authority_fd);
        closelog();
        return 1;
    }

    /* TODO: add compression and update scheduling policy. */
    /* TODO: add IME and layout-aware text input handling. */
    /* TODO: process audio channels. */

    /* Wait for the display server to exit. */
    int stop_requested = 0;
    int status = wait_for_backend_exit(pid, control_fd, &frame_state, &clipboard, correlation_id,
                                       session_id, &stop_requested);
    if (stop_requested) {
        frdp_agent_clipboard_x11_uninit(&clipboard);
        frame_state_free_dirty_tiles(&frame_state);
        status = terminate_backend(pid);
    } else {
        frdp_agent_clipboard_x11_uninit(&clipboard);
        frame_state_uninit(&frame_state);
        XCloseDisplay(xdisplay);
    }
    if (control_fd >= 0)
        close(control_fd);
    if (heartbeat_thread_started) {
        shutdown(heartbeat_fd, SHUT_RDWR);
        (void)pthread_join(heartbeat_thread, NULL);
    }
	if (heartbeat_fd >= 0)
		close(heartbeat_fd);
	close(authority_fd);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        syslog(LOG_ERR, "correlation_id=%s session_id=%s display server exited with status %d",
               escaped_correlation_id, escaped_session_id, WEXITSTATUS(status));
    }
    syslog(LOG_INFO, "correlation_id=%s session_id=%s display server exited, terminating agent",
           escaped_correlation_id, escaped_session_id);
    closelog();
    return 0;
}
