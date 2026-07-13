#ifndef FRDP_SESSION_AGENT_CLIPBOARD_X11_H
#define FRDP_SESSION_AGENT_CLIPBOARD_X11_H

#include <stdint.h>

#include <X11/Xlib.h>

typedef struct
{
	Display* display;
	Window window;
	Atom clipboard;
	Atom utf8_string;
	Atom targets;
	Atom property;
	uint8_t* owned_text;
	uint32_t owned_text_length;
	uint32_t max_property_bytes;
} frdpAgentClipboardX11;

int frdp_agent_clipboard_x11_init(frdpAgentClipboardX11* clipboard, Display* display);
void frdp_agent_clipboard_x11_uninit(frdpAgentClipboardX11* clipboard);
int frdp_agent_clipboard_x11_set_text(frdpAgentClipboardX11* clipboard, const uint8_t* text,
                                      uint32_t text_length, uint32_t max_text_bytes);
int frdp_agent_clipboard_x11_get_text(frdpAgentClipboardX11* clipboard, uint32_t max_text_bytes,
                                      uint8_t** text, uint32_t* text_length);
void frdp_agent_clipboard_x11_process_events(frdpAgentClipboardX11* clipboard);

#endif
