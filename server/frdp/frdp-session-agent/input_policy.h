#ifndef FRDP_SESSION_AGENT_INPUT_POLICY_H
#define FRDP_SESSION_AGENT_INPUT_POLICY_H

#include "../ipc/frdp-ipc.h"

typedef struct {
    uint16_t pending_high_surrogate;
} frdpAgentUnicodeInputState;

int frdp_agent_input_event_payload_is_valid(const frdpAgentInputEvent *event);
uint32_t frdp_agent_unicode_scalar_to_keysym(uint32_t codepoint);
void frdp_agent_unicode_input_reset(frdpAgentUnicodeInputState *state);
int frdp_agent_unicode_input_decode(frdpAgentUnicodeInputState *state,
                                    const frdpAgentInputEvent *event, uint32_t *codepoint);

#endif
