#include "clipboard_x11.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <X11/Xatom.h>

#include <winpr/string.h>

#define FRDP_AGENT_CLIPBOARD_X11_TIMEOUT_MS 500
#define FRDP_AGENT_CLIPBOARD_X11_REQUEST_OVERHEAD_WORDS 64UL

static uint64_t clipboard_monotonic_ms(void)
{
	struct timespec now = { 0 };

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return 0;
	return ((uint64_t)now.tv_sec * 1000U) + ((uint64_t)now.tv_nsec / 1000000U);
}

static int clipboard_text_valid(const uint8_t* text, uint32_t text_length, uint32_t max_text_bytes)
{
	WCHAR* wide = NULL;

	if ((max_text_bytes == 0) || (text_length > max_text_bytes) || ((text_length > 0) && !text) ||
	    ((text_length > 0) && memchr(text, '\0', text_length)))
		return 0;
	if (text_length == 0)
		return 1;
	wide = ConvertUtf8NToWCharAlloc((const char*)text, text_length, NULL);
	if (!wide)
		return 0;
	free(wide);
	return 1;
}

static void clipboard_send_selection_notify(frdpAgentClipboardX11* clipboard,
                                            const XSelectionRequestEvent* request, Atom property)
{
	XEvent reply = { 0 };

	reply.xselection.type = SelectionNotify;
	reply.xselection.display = request->display;
	reply.xselection.requestor = request->requestor;
	reply.xselection.selection = request->selection;
	reply.xselection.target = request->target;
	reply.xselection.property = property;
	reply.xselection.time = request->time;
	XSendEvent(clipboard->display, request->requestor, False, 0, &reply);
	XFlush(clipboard->display);
}

static void clipboard_handle_selection_request(frdpAgentClipboardX11* clipboard,
                                               const XSelectionRequestEvent* request)
{
	Atom property = request->property;

	if (!clipboard || !request || (request->selection != clipboard->clipboard))
		return;
	if (property == None)
		property = request->target;
	if (request->target == clipboard->targets)
	{
		const Atom targets[] = { clipboard->targets, clipboard->utf8_string };

		XChangeProperty(clipboard->display, request->requestor, property, XA_ATOM, 32,
		                PropModeReplace, (const unsigned char*)targets,
		                (int)(sizeof(targets) / sizeof(targets[0])));
	}
	else if ((request->target == clipboard->utf8_string) && clipboard->owned_text)
	{
		XChangeProperty(clipboard->display, request->requestor, property, clipboard->utf8_string, 8,
		                PropModeReplace, clipboard->owned_text, (int)clipboard->owned_text_length);
	}
	else
	{
		property = None;
	}
	clipboard_send_selection_notify(clipboard, request, property);
}

void frdp_agent_clipboard_x11_process_events(frdpAgentClipboardX11* clipboard)
{
	XEvent event = { 0 };

	if (!clipboard || !clipboard->display)
		return;
	while (XCheckTypedEvent(clipboard->display, SelectionRequest, &event))
		clipboard_handle_selection_request(clipboard, &event.xselectionrequest);
	while (XCheckTypedEvent(clipboard->display, SelectionClear, &event))
	{
		if (event.xselectionclear.selection == clipboard->clipboard)
		{
			free(clipboard->owned_text);
			clipboard->owned_text = NULL;
			clipboard->owned_text_length = 0;
		}
	}
}

int frdp_agent_clipboard_x11_init(frdpAgentClipboardX11* clipboard, Display* display)
{
	if (!clipboard || !display)
	{
		errno = EINVAL;
		return -1;
	}
	memset(clipboard, 0, sizeof(*clipboard));
	clipboard->display = display;
	clipboard->clipboard = XInternAtom(display, "CLIPBOARD", False);
	clipboard->utf8_string = XInternAtom(display, "UTF8_STRING", False);
	clipboard->targets = XInternAtom(display, "TARGETS", False);
	clipboard->property = XInternAtom(display, "FRDP_CLIPBOARD", False);
	const long request_words = XMaxRequestSize(display);
	if (request_words > (long)FRDP_AGENT_CLIPBOARD_X11_REQUEST_OVERHEAD_WORDS)
	{
		const unsigned long payload_words =
		    (unsigned long)request_words - FRDP_AGENT_CLIPBOARD_X11_REQUEST_OVERHEAD_WORDS;
		clipboard->max_property_bytes =
		    (payload_words > (UINT32_MAX / 4U)) ? UINT32_MAX : (uint32_t)(payload_words * 4U);
	}
	clipboard->window =
	    XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 1, 1, 0, 0, 0);
	if ((clipboard->clipboard == None) || (clipboard->utf8_string == None) ||
	    (clipboard->targets == None) || (clipboard->property == None) ||
	    (clipboard->window == None) || (clipboard->max_property_bytes == 0U))
	{
		frdp_agent_clipboard_x11_uninit(clipboard);
		errno = EIO;
		return -1;
	}
	XFlush(display);
	return 0;
}

void frdp_agent_clipboard_x11_uninit(frdpAgentClipboardX11* clipboard)
{
	if (!clipboard)
		return;
	free(clipboard->owned_text);
	if (clipboard->display && (clipboard->window != None))
		XDestroyWindow(clipboard->display, clipboard->window);
	memset(clipboard, 0, sizeof(*clipboard));
}

int frdp_agent_clipboard_x11_set_text(frdpAgentClipboardX11* clipboard, const uint8_t* text,
                                      uint32_t text_length, uint32_t max_text_bytes)
{
	uint8_t* copy = NULL;

	if (!clipboard || !clipboard->display || (clipboard->window == None) ||
	    (text_length > clipboard->max_property_bytes) ||
	    !clipboard_text_valid(text, text_length, max_text_bytes))
	{
		errno = EINVAL;
		return -1;
	}
	copy = (uint8_t*)calloc((size_t)text_length + 1U, 1U);
	if (!copy)
		return -1;
	if (text_length > 0)
		memcpy(copy, text, text_length);
	free(clipboard->owned_text);
	clipboard->owned_text = copy;
	clipboard->owned_text_length = text_length;
	XSetSelectionOwner(clipboard->display, clipboard->clipboard, clipboard->window, CurrentTime);
	XFlush(clipboard->display);
	if (XGetSelectionOwner(clipboard->display, clipboard->clipboard) != clipboard->window)
	{
		free(clipboard->owned_text);
		clipboard->owned_text = NULL;
		clipboard->owned_text_length = 0;
		errno = EIO;
		return -1;
	}
	return 0;
}

static int clipboard_copy_owned(const frdpAgentClipboardX11* clipboard, uint32_t max_text_bytes,
                                uint8_t** text, uint32_t* text_length)
{
	uint8_t* copy = NULL;

	if (clipboard->owned_text_length > max_text_bytes)
	{
		errno = EMSGSIZE;
		return -1;
	}
	copy = (uint8_t*)calloc((size_t)clipboard->owned_text_length + 1U, 1U);
	if (!copy)
		return -1;
	if (clipboard->owned_text_length > 0)
		memcpy(copy, clipboard->owned_text, clipboard->owned_text_length);
	*text = copy;
	*text_length = clipboard->owned_text_length;
	return 0;
}

static int clipboard_read_property(frdpAgentClipboardX11* clipboard, uint32_t max_text_bytes,
                                   uint8_t** text, uint32_t* text_length)
{
	Atom actual_type = None;
	int actual_format = 0;
	unsigned long item_count = 0;
	unsigned long bytes_after = 0;
	unsigned char* property = NULL;
	uint8_t* copy = NULL;
	const unsigned long request_length = ((unsigned long)max_text_bytes / 4UL) + 1UL;
	int status = 0;

	status = XGetWindowProperty(clipboard->display, clipboard->window, clipboard->property, 0,
	                            (long)request_length, True, clipboard->utf8_string, &actual_type,
	                            &actual_format, &item_count, &bytes_after, &property);
	if ((status != Success) || (actual_type != clipboard->utf8_string) || (actual_format != 8) ||
	    (bytes_after != 0) || (item_count > max_text_bytes) || ((item_count > 0) && !property) ||
	    !clipboard_text_valid(property, (uint32_t)item_count, max_text_bytes))
	{
		if (property)
			XFree(property);
		errno = EMSGSIZE;
		return -1;
	}
	copy = (uint8_t*)calloc((size_t)item_count + 1U, 1U);
	if (!copy)
	{
		if (property)
			XFree(property);
		return -1;
	}
	if (item_count > 0)
		memcpy(copy, property, item_count);
	if (property)
		XFree(property);
	*text = copy;
	*text_length = (uint32_t)item_count;
	return 0;
}

int frdp_agent_clipboard_x11_get_text(frdpAgentClipboardX11* clipboard, uint32_t max_text_bytes,
                                      uint8_t** text, uint32_t* text_length)
{
	const uint64_t start = clipboard_monotonic_ms();
	const uint64_t deadline = start + FRDP_AGENT_CLIPBOARD_X11_TIMEOUT_MS;
	Window owner = None;

	if (!clipboard || !clipboard->display || !text || !text_length || (max_text_bytes == 0))
	{
		errno = EINVAL;
		return -1;
	}
	*text = NULL;
	*text_length = 0;
	if (max_text_bytes > clipboard->max_property_bytes)
		max_text_bytes = clipboard->max_property_bytes;
	owner = XGetSelectionOwner(clipboard->display, clipboard->clipboard);
	if (owner == clipboard->window)
		return clipboard_copy_owned(clipboard, max_text_bytes, text, text_length);
	if (owner == None)
	{
		*text = (uint8_t*)calloc(1U, 1U);
		return *text ? 0 : -1;
	}
	XDeleteProperty(clipboard->display, clipboard->window, clipboard->property);
	XConvertSelection(clipboard->display, clipboard->clipboard, clipboard->utf8_string,
	                  clipboard->property, clipboard->window, CurrentTime);
	XFlush(clipboard->display);
	while (clipboard_monotonic_ms() < deadline)
	{
		XEvent event = { 0 };
		struct pollfd pfd = { .fd = ConnectionNumber(clipboard->display), .events = POLLIN };
		const uint64_t now = clipboard_monotonic_ms();
		int timeout = (int)(deadline - now);

		while (
		    XCheckTypedWindowEvent(clipboard->display, clipboard->window, SelectionNotify, &event))
		{
			if ((event.xselection.selection == clipboard->clipboard) &&
			    (event.xselection.target == clipboard->utf8_string))
			{
				if (event.xselection.property == None)
				{
					errno = ENODATA;
					return -1;
				}
				return clipboard_read_property(clipboard, max_text_bytes, text, text_length);
			}
		}
		frdp_agent_clipboard_x11_process_events(clipboard);
		if (timeout < 0)
			timeout = 0;
		if ((poll(&pfd, 1, timeout) < 0) && (errno != EINTR))
			return -1;
	}
	errno = ETIMEDOUT;
	return -1;
}
