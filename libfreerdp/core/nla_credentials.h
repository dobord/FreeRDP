#ifndef FREERDP_LIB_CORE_NLA_CREDENTIALS_H
#define FREERDP_LIB_CORE_NLA_CREDENTIALS_H

#include <winpr/sspi.h>

#include <freerdp/api.h>

typedef BOOL (*nla_credentials_source_fn)(void* context, SecBuffer* output);
typedef BOOL (*nla_credentials_transform_fn)(void* context, const SecBuffer* input,
                                             SecBuffer* output);
typedef BOOL (*nla_credentials_sink_fn)(void* context, SecBuffer* input);

WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL nla_credentials_encode_encrypt(void* context, SecBuffer* plaintext,
                                                  SecBuffer* ciphertext,
                                                  nla_credentials_source_fn encode,
                                                  nla_credentials_transform_fn encrypt);

WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL nla_credentials_decrypt_decode(void* context, SecBuffer* ciphertext,
                                                  SecBuffer* plaintext,
                                                  nla_credentials_transform_fn decrypt,
                                                  nla_credentials_sink_fn decode);

#endif /* FREERDP_LIB_CORE_NLA_CREDENTIALS_H */
