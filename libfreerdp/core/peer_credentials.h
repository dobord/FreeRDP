#ifndef FREERDP_LIB_CORE_PEER_CREDENTIALS_H
#define FREERDP_LIB_CORE_PEER_CREDENTIALS_H

#include <winpr/sspi.h>

#include <freerdp/api.h>
#include <freerdp/settings.h>

WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL peer_copy_nla_logon_identity(
    SEC_WINNT_AUTH_IDENTITY* identity, const SEC_WINNT_AUTH_IDENTITY_INFO* nlaIdentity,
    rdpSettings* settings);

#endif /* FREERDP_LIB_CORE_PEER_CREDENTIALS_H */
