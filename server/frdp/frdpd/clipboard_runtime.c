/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd cliprdr runtime
 *
 * Licensed under the Apache License, Version 2.0.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>

#include <winpr/winsock.h>
#include <winpr/sysinfo.h>

#include <freerdp/log.h>

#include "clipboard.h"
#include "clipboard_runtime.h"
#include "frdpd_audit.h"

#define TAG SERVER_TAG("frdpd.clipboard")
#define FRDPD_CLIPBOARD_POLL_INTERVAL_MS 500ULL
#define FRDPD_CLIPBOARD_IPC_TIMEOUT_MS 2000

static const frdpClipboardPolicy* frdpd_clipboard_policy(const frdpdPeerContext* context)
{
	return context ? &context->clipboard : NULL;
}

static BOOL frdpd_clipboard_set_ipc_timeout(int fd)
{
	struct timeval timeout = { FRDPD_CLIPBOARD_IPC_TIMEOUT_MS / 1000,
		                       (FRDPD_CLIPBOARD_IPC_TIMEOUT_MS % 1000) * 1000 };

	return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0) &&
	       (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
}

static BOOL frdpd_clipboard_request_init(const frdpdPeerContext* context,
                                         frdpAgentClipboardRequest* request, UINT32 max_text_bytes,
                                         UINT32 text_length)
{
	if (!context || !request || !context->managed_session_open ||
	    (context->agent_socket[0] == '\0') || (context->session_id[0] == '\0') ||
	    (max_text_bytes == 0U) || (max_text_bytes > FRDP_IPC_AGENT_CLIPBOARD_MAX_TEXT_BYTES) ||
	    (text_length > max_text_bytes))
		return FALSE;
	if ((snprintf(request->correlation_id, sizeof(request->correlation_id), "%s",
	              context->correlation_id) < 0) ||
	    (strlen(context->correlation_id) >= sizeof(request->correlation_id)) ||
	    (snprintf(request->session_id, sizeof(request->session_id), "%s", context->session_id) <
	     0) ||
	    (strlen(context->session_id) >= sizeof(request->session_id)))
		return FALSE;
	request->max_text_bytes = max_text_bytes;
	request->text_length = text_length;
	return TRUE;
}

static BOOL frdpd_clipboard_response_valid(const frdpdPeerContext* context,
                                           const frdpAgentClipboardResponse* response,
                                           UINT32 max_text_bytes)
{
	return context && response && response->success && (response->text_length <= max_text_bytes) &&
	       (memchr(response->correlation_id, '\0', sizeof(response->correlation_id)) != NULL) &&
	       (memchr(response->session_id, '\0', sizeof(response->session_id)) != NULL) &&
	       (memchr(response->error, '\0', sizeof(response->error)) != NULL) &&
	       (strcmp(response->correlation_id, context->correlation_id) == 0) &&
	       (strcmp(response->session_id, context->session_id) == 0);
}

static BOOL frdpd_clipboard_agent_set(frdpdPeerContext* context, const BYTE* text,
                                      UINT32 text_length, UINT32 max_text_bytes)
{
	frdpAgentClipboardRequest request = { 0 };
	frdpAgentClipboardResponse response = { 0 };
	BYTE* response_text = NULL;
	int fd = -1;
	BOOL rc = FALSE;

	if ((!text && (text_length != 0U)) ||
	    !frdpd_clipboard_request_init(context, &request, max_text_bytes, text_length))
		return FALSE;
	fd = frdp_ipc_connect(context->agent_socket);
	if ((fd < 0) || !frdpd_clipboard_set_ipc_timeout(fd) ||
	    (frdp_ipc_send_agent_clipboard_set_request(fd, &request, text) != 0) ||
	    (frdp_ipc_recv_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_SET_RESPONSE,
	                                            &response, &response_text) != 0))
		goto out;
	if (frdpd_clipboard_response_valid(context, &response, max_text_bytes) &&
	    (response.text_length == 0U))
		rc = TRUE;

out:
	free(response_text);
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	return rc;
}

static BOOL frdpd_clipboard_agent_get(frdpdPeerContext* context, UINT32 max_text_bytes, BYTE** text,
                                      UINT32* text_length)
{
	frdpAgentClipboardRequest request = { 0 };
	frdpAgentClipboardResponse response = { 0 };
	BYTE* response_text = NULL;
	int fd = -1;
	BOOL rc = FALSE;

	if (!text || !text_length ||
	    !frdpd_clipboard_request_init(context, &request, max_text_bytes, 0U))
		return FALSE;
	*text = NULL;
	*text_length = 0;
	fd = frdp_ipc_connect(context->agent_socket);
	if ((fd < 0) || !frdpd_clipboard_set_ipc_timeout(fd) ||
	    (frdp_ipc_send_agent_clipboard_get_request(fd, &request) != 0) ||
	    (frdp_ipc_recv_agent_clipboard_response(fd, FRDP_IPC_AGENT_CLIPBOARD_GET_RESPONSE,
	                                            &response, &response_text) != 0))
		goto out;
	if (!frdpd_clipboard_response_valid(context, &response, max_text_bytes) ||
	    ((response.text_length != 0U) && !response_text) ||
	    (response_text && (memchr(response_text, '\0', response.text_length) != NULL)))
		goto out;
	*text = response_text;
	*text_length = response.text_length;
	response_text = NULL;
	rc = TRUE;

out:
	free(response_text);
	if (fd >= 0)
		(void)frdp_ipc_close(fd);
	return rc;
}

static UINT frdpd_clipboard_send_format_list_response(CliprdrServerContext* clipboard, BOOL success)
{
	CLIPRDR_FORMAT_LIST_RESPONSE response = { 0 };

	response.common.msgType = CB_FORMAT_LIST_RESPONSE;
	response.common.msgFlags = success ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
	return clipboard->ServerFormatListResponse(clipboard, &response);
}

static UINT frdpd_clipboard_client_format_list(CliprdrServerContext* clipboard,
                                               const CLIPRDR_FORMAT_LIST* format_list)
{
	frdpdPeerContext* context = clipboard ? (frdpdPeerContext*)clipboard->custom : NULL;
	const frdpClipboardPolicy* policy = frdpd_clipboard_policy(context);
	CLIPRDR_FORMAT_DATA_REQUEST request = { 0 };
	BOOL unicode_text = FALSE;
	BOOL clear_text = FALSE;
	const BOOL valid_formats = format_list && (format_list->formats || (format_list->numFormats == 0U));

	if (!clipboard || !context || !policy || !format_list)
		return ERROR_INVALID_PARAMETER;
	if (frdpd_clipboard_client_to_server_enabled(policy) && valid_formats)
	{
		for (UINT32 i = 0; i < format_list->numFormats; i++)
		{
			if (format_list->formats[i].formatId == CF_UNICODETEXT)
			{
				unicode_text = TRUE;
				break;
			}
		}
	}
	EnterCriticalSection(&context->clipboard_lock);
	if (context->clipboard_client_data_pending)
	{
		if (!unicode_text && valid_formats)
		{
			context->clipboard_client_data_pending = FALSE;
			clear_text = TRUE;
		}
		unicode_text = FALSE;
	}
	else if (unicode_text)
		context->clipboard_client_data_pending = TRUE;
	else if (valid_formats && frdpd_clipboard_client_to_server_enabled(policy))
		clear_text = TRUE;
	LeaveCriticalSection(&context->clipboard_lock);
	if (frdpd_clipboard_send_format_list_response(clipboard, TRUE) != CHANNEL_RC_OK)
		return ERROR_INTERNAL_ERROR;
	if (clear_text)
	{
		if (frdpd_clipboard_agent_set(context, NULL, 0U, policy->max_text_bytes))
		{
			EnterCriticalSection(&context->clipboard_lock);
			context->clipboard_last_hash = frdpd_clipboard_hash(NULL, 0U);
			context->clipboard_last_length = 0U;
			context->clipboard_announced = TRUE;
			LeaveCriticalSection(&context->clipboard_lock);
		}
	}
	if (!unicode_text)
		return CHANNEL_RC_OK;
	request.common.msgType = CB_FORMAT_DATA_REQUEST;
	request.common.dataLen = 4U;
	request.requestedFormatId = CF_UNICODETEXT;
	if (clipboard->ServerFormatDataRequest(clipboard, &request) != CHANNEL_RC_OK)
	{
		EnterCriticalSection(&context->clipboard_lock);
		context->clipboard_client_data_pending = FALSE;
		LeaveCriticalSection(&context->clipboard_lock);
		return ERROR_INTERNAL_ERROR;
	}
	return CHANNEL_RC_OK;
}

static UINT
frdpd_clipboard_client_format_data_response(CliprdrServerContext* clipboard,
                                            const CLIPRDR_FORMAT_DATA_RESPONSE* format_response)
{
	frdpdPeerContext* context = clipboard ? (frdpdPeerContext*)clipboard->custom : NULL;
	const frdpClipboardPolicy* policy = frdpd_clipboard_policy(context);
	BYTE* text = NULL;
	UINT32 text_length = 0;
	BOOL pending = FALSE;

	if (!clipboard || !context || !policy || !format_response)
		return ERROR_INVALID_PARAMETER;
	EnterCriticalSection(&context->clipboard_lock);
	pending = context->clipboard_client_data_pending;
	context->clipboard_client_data_pending = FALSE;
	LeaveCriticalSection(&context->clipboard_lock);
	if (!pending || !frdpd_clipboard_client_to_server_enabled(policy) ||
	    (format_response->common.msgFlags != CB_RESPONSE_OK) ||
	    !frdpd_clipboard_utf16le_to_utf8(format_response->requestedFormatData,
	                                     format_response->common.dataLen, policy->max_text_bytes,
	                                     &text, &text_length))
		return CHANNEL_RC_OK;
	if (!frdpd_clipboard_agent_set(context, text, text_length, policy->max_text_bytes))
	{
		free(text);
		return CHANNEL_RC_OK;
	}
	EnterCriticalSection(&context->clipboard_lock);
	context->clipboard_last_hash = frdpd_clipboard_hash(text, text_length);
	context->clipboard_last_length = text_length;
	context->clipboard_announced = TRUE;
	LeaveCriticalSection(&context->clipboard_lock);
	free(text);
	return CHANNEL_RC_OK;
}

static UINT
frdpd_clipboard_client_format_data_request(CliprdrServerContext* clipboard,
                                           const CLIPRDR_FORMAT_DATA_REQUEST* format_request)
{
	frdpdPeerContext* context = clipboard ? (frdpdPeerContext*)clipboard->custom : NULL;
	const frdpClipboardPolicy* policy = frdpd_clipboard_policy(context);
	CLIPRDR_FORMAT_DATA_RESPONSE response = { 0 };
	BYTE* text = NULL;
	BYTE* wide = NULL;
	UINT32 text_length = 0;
	UINT32 wide_length = 0;
	BOOL success = FALSE;
	UINT rc = CHANNEL_RC_OK;

	if (!clipboard || !context || !policy || !format_request)
		return ERROR_INVALID_PARAMETER;
	if ((format_request->requestedFormatId == CF_UNICODETEXT) &&
	    frdpd_clipboard_server_to_client_enabled(policy) &&
	    frdpd_clipboard_agent_get(context, policy->max_text_bytes, &text, &text_length) &&
	    frdpd_clipboard_utf8_to_utf16le(text, text_length, policy->max_text_bytes, &wide,
	                                    &wide_length))
		success = TRUE;

	response.common.msgType = CB_FORMAT_DATA_RESPONSE;
	response.common.msgFlags = success ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
	response.common.dataLen = success ? wide_length : 0U;
	response.requestedFormatData = success ? wide : NULL;
	rc = clipboard->ServerFormatDataResponse(clipboard, &response);
	free(wide);
	free(text);
	return rc;
}

static UINT
frdpd_clipboard_client_file_contents_request(CliprdrServerContext* clipboard,
                                             const CLIPRDR_FILE_CONTENTS_REQUEST* file_request)
{
	CLIPRDR_FILE_CONTENTS_RESPONSE response = { 0 };

	if (!clipboard || !file_request)
		return ERROR_INVALID_PARAMETER;
	response.common.msgType = CB_FILECONTENTS_RESPONSE;
	response.common.msgFlags = CB_RESPONSE_FAIL;
	response.streamId = file_request->streamId;
	return clipboard->ServerFileContentsResponse(clipboard, &response);
}

static BOOL frdpd_clipboard_announce_if_changed(frdpdPeerContext* context,
                                                const frdpClipboardPolicy* policy)
{
	CLIPRDR_FORMAT format = { CF_UNICODETEXT, NULL };
	CLIPRDR_FORMAT_LIST list = { 0 };
	BYTE* text = NULL;
	UINT32 text_length = 0;
	UINT64 hash = 0;
	BOOL changed = FALSE;

	if (!frdpd_clipboard_server_to_client_enabled(policy))
		return TRUE;
	if (!frdpd_clipboard_agent_get(context, policy->max_text_bytes, &text, &text_length))
		return TRUE;
	hash = frdpd_clipboard_hash(text, text_length);
	EnterCriticalSection(&context->clipboard_lock);
	changed = !context->clipboard_announced || (hash != context->clipboard_last_hash) ||
	          (text_length != context->clipboard_last_length);
	if (changed)
	{
		context->clipboard_last_hash = hash;
		context->clipboard_last_length = text_length;
		context->clipboard_announced = TRUE;
	}
	LeaveCriticalSection(&context->clipboard_lock);
	free(text);
	if (!changed)
		return TRUE;

	list.common.msgType = CB_FORMAT_LIST;
	list.numFormats = 1U;
	list.formats = &format;
	return context->clipboard_context->ServerFormatList(context->clipboard_context, &list) ==
	       CHANNEL_RC_OK;
}

BOOL frdpd_clipboard_runtime_service(frdpdPeerContext* context)
{
	const frdpClipboardPolicy* policy = frdpd_clipboard_policy(context);
	const UINT64 now = GetTickCount64();

	if (!context || !policy || !context->cliprdr_joined ||
	    (policy->mode != FRDP_CLIPBOARD_MODE_TEXT))
		return TRUE;
	if (!context->clipboard_context)
	{
		context->clipboard_context = cliprdr_server_context_new(context->vcm);
		if (!context->clipboard_context)
		{
			frdpd_audit_peer_event(context, LOG_WARNING, "channel.activation", "failed", "cliprdr",
			                       "context-create");
			return FALSE;
		}
		context->clipboard_context->custom = context;
		context->clipboard_context->rdpcontext = &context->_p;
		context->clipboard_context->streamFileClipEnabled = FALSE;
		context->clipboard_context->fileClipNoFilePaths = FALSE;
		context->clipboard_context->canLockClipData = FALSE;
		context->clipboard_context->ClientFormatList = frdpd_clipboard_client_format_list;
		context->clipboard_context->ClientFormatDataRequest =
		    frdpd_clipboard_client_format_data_request;
		context->clipboard_context->ClientFormatDataResponse =
		    frdpd_clipboard_client_format_data_response;
		context->clipboard_context->ClientFileContentsRequest =
		    frdpd_clipboard_client_file_contents_request;
		if (context->clipboard_context->Start(context->clipboard_context) != CHANNEL_RC_OK)
		{
			frdpd_audit_peer_event(context, LOG_WARNING, "channel.activation", "failed", "cliprdr",
			                       "start");
			cliprdr_server_context_free(context->clipboard_context);
			context->clipboard_context = NULL;
			context->cliprdr_joined = FALSE;
			return TRUE;
		}
		context->clipboard_started = TRUE;
		WLog_INFO(TAG, "correlation_id=%s text clipboard channel ready", context->correlation_id);
		frdpd_audit_peer_event(context, LOG_INFO, "channel.activation", "ready", "cliprdr",
		                       "text-clipboard");
	}
	if (!context->managed_session_open ||
	    ((now - context->clipboard_last_poll_tick) < FRDPD_CLIPBOARD_POLL_INTERVAL_MS))
		return TRUE;
	context->clipboard_last_poll_tick = now;
	return frdpd_clipboard_announce_if_changed(context, policy);
}

void frdpd_clipboard_runtime_stop(frdpdPeerContext* context)
{
	if (!context || !context->clipboard_context)
		return;
	if (context->clipboard_started)
		(void)context->clipboard_context->Stop(context->clipboard_context);
	context->clipboard_started = FALSE;
	cliprdr_server_context_free(context->clipboard_context);
	context->clipboard_context = NULL;
}
