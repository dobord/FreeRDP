#include <winpr/crt.h>
#include <winpr/error.h>
#include <winpr/wtsapi.h>

#include <freerdp/channels/channels.h>
#include <freerdp/channels/drdynvc.h>
#include <freerdp/channels/wtsvc.h>
#include <freerdp/peer.h>

#include "../server.h"

typedef struct
{
	UINT32 calls;
	DWORD sessionId;
	DWORD flags;
	char channelName[64];
} dvc_auth_state;

static BOOL deny_dvc(void* userdata, DWORD SessionId, const char* channelName, DWORD flags)
{
	dvc_auth_state* state = userdata;

	if (!state || !channelName)
		return FALSE;

	state->calls++;
	state->sessionId = SessionId;
	state->flags = flags;
	(void)strncpy(state->channelName, channelName, sizeof(state->channelName) - 1);
	state->channelName[sizeof(state->channelName) - 1] = '\0';
	return FALSE;
}

static BOOL set_joined_drdynvc(freerdp_peer* client)
{
	if (!client || !client->context || !client->context->rdp || !client->context->rdp->mcs)
		return FALSE;

	rdpMcs* mcs = client->context->rdp->mcs;
	if (!mcs->channels || (mcs->channelMaxCount < 1))
		return FALSE;

	rdpMcsChannel* channel = &mcs->channels[0];
	ZeroMemory(channel, sizeof(*channel));
	(void)strncpy(channel->Name, DRDYNVC_SVC_CHANNEL_NAME, sizeof(channel->Name) - 1);
	channel->Name[sizeof(channel->Name) - 1] = '\0';
	channel->ChannelId = 1001;
	channel->joined = TRUE;
	mcs->channelCount = 1;
	return TRUE;
}

static BOOL test_dvc_authorization_denies_before_create_request(void)
{
	BOOL rc = FALSE;
	HANDLE opened = nullptr;
	HANDLE server = nullptr;
	rdpPeerChannel drdynvc = WINPR_C_ARRAY_INIT;
	dvc_auth_state state = WINPR_C_ARRAY_INIT;
	freerdp_peer* client = freerdp_peer_new(-1);

	if (!client)
		goto fail;
	if (!freerdp_peer_context_new(client))
		goto fail;

	if (!WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi()))
		goto fail;

	server = WTSOpenServerA((LPSTR)client->context);
	if (!server || (server == INVALID_HANDLE_VALUE))
		goto fail;

	WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)server;
	WTSVirtualChannelManagerSetDVCChannelAuthorizationCallback(server, deny_dvc, &state);

	SetLastError(ERROR_SUCCESS);
	opened = WTSVirtualChannelOpenEx(vcm->SessionId, "rdpgfx", WTS_CHANNEL_OPTION_DYNAMIC);
	if (opened)
		goto fail;
	if (GetLastError() != ERROR_NOT_FOUND)
		goto fail;
	if (state.calls != 0)
		goto fail;

	if (!set_joined_drdynvc(client))
		goto fail;
	vcm->drdynvc_channel = &drdynvc;
	vcm->drdynvc_state = DRDYNVC_STATE_READY;

	SetLastError(ERROR_SUCCESS);
	opened = WTSVirtualChannelOpenEx(vcm->SessionId, "rdpgfx", WTS_CHANNEL_OPTION_DYNAMIC);
	if (opened)
		goto fail;
	if (GetLastError() != ERROR_ACCESS_DENIED)
		goto fail;
	if (state.calls != 1)
		goto fail;
	if (state.sessionId != vcm->SessionId)
		goto fail;
	if (state.flags != WTS_CHANNEL_OPTION_DYNAMIC)
		goto fail;
	if (strcmp(state.channelName, "rdpgfx") != 0)
		goto fail;

	rc = TRUE;

fail:
	if (opened)
		(void)WTSVirtualChannelClose(opened);
	if (client && client->context)
	{
		WTSVirtualChannelManager* vcm = (WTSVirtualChannelManager*)server;
		if (vcm && (vcm != INVALID_HANDLE_VALUE))
			vcm->drdynvc_channel = nullptr;
		if (server && (server != INVALID_HANDLE_VALUE))
			WTSCloseServer(server);
		freerdp_peer_context_free(client);
	}
	freerdp_peer_free(client);
	return rc;
}

int TestWtsDvcAuthorization(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (!test_dvc_authorization_denies_before_create_request())
		return -1;

	return 0;
}
