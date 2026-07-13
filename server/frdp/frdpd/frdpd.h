/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Experimental frdpd server internals
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef FREERDP_SERVER_FRDPD_H
#define FREERDP_SERVER_FRDPD_H

#include <sys/types.h>

#include <winpr/stream.h>

#include <freerdp/codec/nsc.h>
#include <freerdp/freerdp.h>
#include <freerdp/peer.h>

#include "../config/frdp-config.h"
#include "../ipc/frdp-ipc.h"
#include "frdpd_pam.h"

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct
	{
		const char* bind_address;
		const char* cert_path;
		const char* key_path;
		const char* pam_service;
		const char* auth_socket;
		const char* ntlm_sam_file;
		int ntlm_sam_fd;
		char ntlm_sam_fd_path[64];
		const char* session_socket;
		UINT16 port;
		UINT32 max_connections;
		volatile LONG active_connections;
		BOOL allow_tls_fallback;
		BOOL ntlm_fallback;
		frdpdDomainMode domain_mode;
		frdpChannelPolicy channels;
		frdpClipboardPolicy clipboard;
	} frdpdServerConfig;

	typedef struct
	{
		rdpContext _p;
		char correlation_id[64];
		char session_id[64];
		char session_display[32];
		char agent_socket[108];
		BOOL managed_session_open;
		BOOL agent_input_warned;
		BOOL agent_frame_warned;
		BOOL framebuffer_active;
		BOOL framebuffer_output_suppressed;
		UINT32 framebuffer_next_x;
		UINT32 framebuffer_next_y;
		UINT64 framebuffer_last_tick;
		UINT32 framebuffer_hash_cols;
		UINT32 framebuffer_hash_rows;
		UINT64* framebuffer_hashes;
		NSC_CONTEXT* framebuffer_nsc;
		wStream* framebuffer_nsc_stream;
		BOOL framebuffer_nsc_warned;
		HANDLE vcm;
		char* pam_user;
		char authorization_id[192];
		uid_t uid;
		gid_t gid;
		UINT32 group_count;
		UINT64 groups[FRDP_IPC_MAX_AUTH_GROUPS];
		BOOL has_posix_account;
		frdpdPamAuthStatus auth_status;
		int pam_status;
	} frdpdPeerContext;

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_SERVER_FRDPD_H */
