#ifndef FRDP_SESMAND_SESSION_METADATA_H
#define FRDP_SESMAND_SESSION_METADATA_H

#include "session_state.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define FRDP_SESMAND_SESSION_ID_SIZE 37
#define FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE 128

typedef struct
{
	char session_id[FRDP_SESMAND_SESSION_ID_SIZE];
	uid_t uid;
	pid_t agent_pid;
	pid_t pgid;
	unsigned long long agent_start_ticks;
	frdpSesmandSessionState state;
	int display_number;
	uint64_t agent_socket_dev;
	uint64_t agent_socket_ino;
	uint64_t display_reservation_dev;
	uint64_t display_reservation_ino;
} frdpSesmandSessionMetadata;

typedef int (*frdpSesmandSessionMetadataVisitor)(const frdpSesmandSessionMetadata* metadata,
                                                 uint64_t file_dev, uint64_t file_ino,
                                                 void* context);

typedef enum
{
	FRDP_SESMAND_SESSION_METADATA_SAVE_ERROR = -1,
	FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED = 0,
	FRDP_SESMAND_SESSION_METADATA_SAVE_DURABILITY_UNCERTAIN = 1
} frdpSesmandSessionMetadataSaveResult;

int frdp_sesmand_session_metadata_is_valid(const frdpSesmandSessionMetadata* metadata);
int frdp_sesmand_session_metadata_filename(char* dst, size_t dst_size, const char* session_id);
frdpSesmandSessionMetadataSaveResult frdp_sesmand_session_metadata_save(
    const char* dir, const frdpSesmandSessionMetadata* metadata, uint64_t* file_dev,
    uint64_t* file_ino);
int frdp_sesmand_session_metadata_visit(const char* dir,
                                        frdpSesmandSessionMetadataVisitor visitor, void* context);
int frdp_sesmand_session_metadata_remove(const char* dir, const char* session_id,
                                         uint64_t expected_dev, uint64_t expected_ino);

#endif
