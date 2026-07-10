#define _GNU_SOURCE

#include "session_metadata.h"

#include "display_policy.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRDP_METADATA_PREFIX "frdp-session-"
#define FRDP_METADATA_SUFFIX ".meta"
#define FRDP_METADATA_TEMP_PREFIX ".frdp-session-tmp-"

static const unsigned char METADATA_MAGIC[8] = { 'F', 'R', 'D', 'P', 'S', 'M', '0', '1' };

static void write_u32_le(unsigned char* dst, uint32_t value)
{
	dst[0] = (unsigned char)(value & 0xffU);
	dst[1] = (unsigned char)((value >> 8U) & 0xffU);
	dst[2] = (unsigned char)((value >> 16U) & 0xffU);
	dst[3] = (unsigned char)((value >> 24U) & 0xffU);
}

static void write_u64_le(unsigned char* dst, uint64_t value)
{
	for (unsigned int x = 0; x < 8U; x++)
		dst[x] = (unsigned char)((value >> (x * 8U)) & 0xffU);
}

static uint32_t read_u32_le(const unsigned char* src)
{
	return ((uint32_t)src[0]) | ((uint32_t)src[1] << 8U) | ((uint32_t)src[2] << 16U) |
	       ((uint32_t)src[3] << 24U);
}

static uint64_t read_u64_le(const unsigned char* src)
{
	uint64_t value = 0;

	for (unsigned int x = 0; x < 8U; x++)
		value |= (uint64_t)src[x] << (x * 8U);
	return value;
}

static int session_id_is_valid(const char* session_id)
{
	if (!session_id || (strlen(session_id) != (FRDP_SESMAND_SESSION_ID_SIZE - 1U)))
		return 0;
	for (size_t x = 0; x < (FRDP_SESMAND_SESSION_ID_SIZE - 1U); x++)
	{
		const char c = session_id[x];

		if ((x == 8U) || (x == 13U) || (x == 18U) || (x == 23U))
		{
			if (c != '-')
				return 0;
		}
		else if (!(((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f'))))
			return 0;
	}
	return 1;
}

int frdp_sesmand_session_metadata_is_valid(const frdpSesmandSessionMetadata* metadata)
{
	if (!metadata || !session_id_is_valid(metadata->session_id) ||
	    (metadata->uid == (uid_t)-1) || (metadata->agent_pid <= 1) ||
	    (metadata->pgid != metadata->agent_pid) || (metadata->agent_start_ticks == 0) ||
	    !frdp_sesmand_session_state_is_valid(metadata->state) ||
	    !frdp_sesmand_display_number_is_valid(metadata->display_number) ||
	    (metadata->agent_socket_dev == 0) || (metadata->agent_socket_ino == 0) ||
	    (metadata->display_reservation_dev == 0) ||
	    (metadata->display_reservation_ino == 0))
		return 0;
	return 1;
}

int frdp_sesmand_session_metadata_filename(char* dst, size_t dst_size, const char* session_id)
{
	int rc = 0;

	if (!dst || (dst_size == 0) || !session_id_is_valid(session_id))
		return -1;
	rc = snprintf(dst, dst_size, FRDP_METADATA_PREFIX "%s" FRDP_METADATA_SUFFIX, session_id);
	return ((rc >= 0) && ((size_t)rc < dst_size)) ? 0 : -1;
}

static int metadata_filename_is_valid(const char* filename)
{
	char expected[96] = { 0 };
	const size_t prefix_len = strlen(FRDP_METADATA_PREFIX);
	const size_t suffix_len = strlen(FRDP_METADATA_SUFFIX);
	const size_t expected_len = prefix_len + FRDP_SESMAND_SESSION_ID_SIZE - 1U + suffix_len;
	char session_id[FRDP_SESMAND_SESSION_ID_SIZE] = { 0 };

	if (!filename || (strlen(filename) != expected_len) ||
	    (strncmp(filename, FRDP_METADATA_PREFIX, prefix_len) != 0))
		return 0;
	memcpy(session_id, filename + prefix_len, sizeof(session_id) - 1U);
	if (frdp_sesmand_session_metadata_filename(expected, sizeof(expected), session_id) != 0)
		return 0;
	return strcmp(filename, expected) == 0;
}

static int open_metadata_dir(const char* dir)
{
	struct stat st = { 0 };
	int flags = O_RDONLY;
	int fd = -1;

	if (!dir || (dir[0] != '/'))
		return -1;
#ifdef O_DIRECTORY
	flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
	fd = open(dir, flags);
	if (fd < 0)
		return -1;
	if ((fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) || (fstat(fd, &st) != 0) ||
	    !S_ISDIR(st.st_mode) || (st.st_uid != geteuid()) ||
	    ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0))
	{
		close(fd);
		return -1;
	}
	return fd;
}

static int write_all(int fd, const unsigned char* data, size_t size)
{
	size_t offset = 0;

	while (offset < size)
	{
		ssize_t rc = write(fd, data + offset, size - offset);

		if ((rc < 0) && (errno == EINTR))
			continue;
		if (rc <= 0)
			return -1;
		offset += (size_t)rc;
	}
	return 0;
}

static int read_exact_file(int fd, unsigned char* data, size_t size)
{
	size_t offset = 0;
	unsigned char extra = 0;

	while (offset < size)
	{
		ssize_t rc = read(fd, data + offset, size - offset);

		if ((rc < 0) && (errno == EINTR))
			continue;
		if (rc <= 0)
			return -1;
		offset += (size_t)rc;
	}
	for (;;)
	{
		const ssize_t rc = read(fd, &extra, sizeof(extra));

		if ((rc < 0) && (errno == EINTR))
			continue;
		return (rc == 0) ? 0 : -1;
	}
}

static void metadata_encode(const frdpSesmandSessionMetadata* metadata,
                            unsigned char wire[FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE])
{
	memset(wire, 0, FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE);
	memcpy(wire, METADATA_MAGIC, sizeof(METADATA_MAGIC));
	write_u32_le(&wire[8], 1U);
	write_u32_le(&wire[12], FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE);
	memcpy(&wire[16], metadata->session_id, sizeof(metadata->session_id));
	write_u64_le(&wire[56], (uint64_t)metadata->uid);
	write_u64_le(&wire[64], (uint64_t)metadata->agent_pid);
	write_u64_le(&wire[72], (uint64_t)metadata->pgid);
	write_u64_le(&wire[80], (uint64_t)metadata->agent_start_ticks);
	write_u32_le(&wire[88], (uint32_t)metadata->state);
	write_u32_le(&wire[92], (uint32_t)metadata->display_number);
	write_u64_le(&wire[96], metadata->agent_socket_dev);
	write_u64_le(&wire[104], metadata->agent_socket_ino);
	write_u64_le(&wire[112], metadata->display_reservation_dev);
	write_u64_le(&wire[120], metadata->display_reservation_ino);
}

static int metadata_decode(const unsigned char wire[FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE],
                           frdpSesmandSessionMetadata* metadata)
{
	const uint64_t uid_value = read_u64_le(&wire[56]);
	const uint64_t pid_value = read_u64_le(&wire[64]);
	const uint64_t pgid_value = read_u64_le(&wire[72]);
	const uint32_t state_value = read_u32_le(&wire[88]);
	const uint32_t display_value = read_u32_le(&wire[92]);
	uid_t uid = (uid_t)uid_value;
	pid_t pid = (pid_t)pid_value;
	pid_t pgid = (pid_t)pgid_value;

	if (!metadata || (memcmp(wire, METADATA_MAGIC, sizeof(METADATA_MAGIC)) != 0) ||
	    (read_u32_le(&wire[8]) != 1U) ||
	    (read_u32_le(&wire[12]) != FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE) ||
	    (wire[FRDP_SESMAND_SESSION_ID_SIZE + 15U] != '\0') || (wire[53] != 0) ||
	    (wire[54] != 0) || (wire[55] != 0) || ((uint64_t)uid != uid_value) ||
	    (pid <= 1) || ((uint64_t)pid != pid_value) || (pgid <= 1) ||
	    ((uint64_t)pgid != pgid_value) || (state_value > (uint32_t)INT32_MAX) ||
	    (display_value > (uint32_t)INT32_MAX))
		return -1;

	memset(metadata, 0, sizeof(*metadata));
	memcpy(metadata->session_id, &wire[16], sizeof(metadata->session_id));
	metadata->uid = uid;
	metadata->agent_pid = pid;
	metadata->pgid = pgid;
	metadata->agent_start_ticks = read_u64_le(&wire[80]);
	metadata->state = (frdpSesmandSessionState)state_value;
	metadata->display_number = (int)display_value;
	metadata->agent_socket_dev = read_u64_le(&wire[96]);
	metadata->agent_socket_ino = read_u64_le(&wire[104]);
	metadata->display_reservation_dev = read_u64_le(&wire[112]);
	metadata->display_reservation_ino = read_u64_le(&wire[120]);
	return frdp_sesmand_session_metadata_is_valid(metadata) ? 0 : -1;
}

static int metadata_file_stat_is_secure(const struct stat* st)
{
	return st && S_ISREG(st->st_mode) && (st->st_uid == geteuid()) &&
	       ((st->st_mode & 0777) == 0600) && (st->st_nlink == 1);
}

static int metadata_load_at(int dir_fd, const char* filename,
                            frdpSesmandSessionMetadata* metadata, struct stat* file_stat)
{
	unsigned char wire[FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE] = { 0 };
	struct stat st = { 0 };
	int flags = O_RDONLY;
	int fd = -1;
	int rc = -1;

	if ((dir_fd < 0) || !metadata || !metadata_filename_is_valid(filename))
		return -1;
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif
	fd = openat(dir_fd, filename, flags);
	if (fd < 0)
		return -1;
	if ((fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) || (fstat(fd, &st) != 0) ||
	    !metadata_file_stat_is_secure(&st) || (read_exact_file(fd, wire, sizeof(wire)) != 0) ||
	    (metadata_decode(wire, metadata) != 0))
		goto out;
	{
		char expected[96] = { 0 };

		if ((frdp_sesmand_session_metadata_filename(expected, sizeof(expected),
		                                               metadata->session_id) != 0) ||
		    (strcmp(expected, filename) != 0))
			goto out;
	}
	if (file_stat)
		*file_stat = st;
	rc = 0;
out:
	close(fd);
	return rc;
}

frdpSesmandSessionMetadataSaveResult frdp_sesmand_session_metadata_save(
    const char* dir, const frdpSesmandSessionMetadata* metadata, uint64_t* file_dev,
    uint64_t* file_ino)
{
	unsigned char wire[FRDP_SESMAND_SESSION_METADATA_WIRE_SIZE] = { 0 };
	char filename[96] = { 0 };
	char temp_name[96] = { 0 };
	struct stat final_stat = { 0 };
	struct stat temp_stat = { 0 };
	int dir_fd = -1;
	int temp_fd = -1;
	int temp_created = 0;
	frdpSesmandSessionMetadataSaveResult rc = FRDP_SESMAND_SESSION_METADATA_SAVE_ERROR;

	if (!file_dev || !file_ino || !frdp_sesmand_session_metadata_is_valid(metadata) ||
	    (frdp_sesmand_session_metadata_filename(filename, sizeof(filename),
	                                             metadata->session_id) != 0))
		return FRDP_SESMAND_SESSION_METADATA_SAVE_ERROR;
	*file_dev = 0;
	*file_ino = 0;
	dir_fd = open_metadata_dir(dir);
	if (dir_fd < 0)
		return FRDP_SESMAND_SESSION_METADATA_SAVE_ERROR;
	metadata_encode(metadata, wire);
	for (unsigned int attempt = 0; attempt < 100U; attempt++)
	{
		if (snprintf(temp_name, sizeof(temp_name), FRDP_METADATA_TEMP_PREFIX "%ld-%u",
		             (long)getpid(), attempt) >= (int)sizeof(temp_name))
			goto out;
		temp_fd = openat(dir_fd, temp_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (temp_fd >= 0)
		{
			temp_created = 1;
			break;
		}
		if (errno != EEXIST)
			goto out;
	}
	if (temp_fd < 0)
		goto out;
	if ((fcntl(temp_fd, F_SETFD, FD_CLOEXEC) != 0) || (fchmod(temp_fd, 0600) != 0) ||
	    (fstat(temp_fd, &temp_stat) != 0) ||
	    !metadata_file_stat_is_secure(&temp_stat) || (write_all(temp_fd, wire, sizeof(wire)) != 0) ||
	    (fsync(temp_fd) != 0))
	{
		goto out;
	}
	if (close(temp_fd) != 0)
	{
		temp_fd = -1;
		goto out;
	}
	temp_fd = -1;
	if (renameat(dir_fd, temp_name, dir_fd, filename) != 0)
		goto out;
	temp_created = 0;
	*file_dev = (uint64_t)temp_stat.st_dev;
	*file_ino = (uint64_t)temp_stat.st_ino;
	rc = FRDP_SESMAND_SESSION_METADATA_SAVE_DURABILITY_UNCERTAIN;
	if ((fstatat(dir_fd, filename, &final_stat, AT_SYMLINK_NOFOLLOW) != 0) ||
	    (final_stat.st_dev != temp_stat.st_dev) || (final_stat.st_ino != temp_stat.st_ino) ||
	    !metadata_file_stat_is_secure(&final_stat) || (fsync(dir_fd) != 0))
		goto out;
	rc = FRDP_SESMAND_SESSION_METADATA_SAVE_COMMITTED;
out:
	if (temp_fd >= 0)
		close(temp_fd);
	if (temp_created)
		(void)unlinkat(dir_fd, temp_name, 0);
	close(dir_fd);
	return rc;
}

static int same_path_entry(int dir_fd, const char* name, const struct stat* opened)
{
	struct stat current = { 0 };

	if ((fstatat(dir_fd, name, &current, AT_SYMLINK_NOFOLLOW) != 0) || !opened)
		return 0;
	return (current.st_dev == opened->st_dev) && (current.st_ino == opened->st_ino) &&
	       ((current.st_mode & S_IFMT) == (opened->st_mode & S_IFMT));
}

static int remove_temporary_at(int dir_fd, const char* name)
{
	struct stat st = { 0 };

	if ((fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) ||
	    !metadata_file_stat_is_secure(&st) || !same_path_entry(dir_fd, name, &st))
		return -1;
	return unlinkat(dir_fd, name, 0);
}

int frdp_sesmand_session_metadata_visit(const char* dir,
	                                    frdpSesmandSessionMetadataVisitor visitor, void* context)
{
	DIR* stream = NULL;
	int dir_fd = -1;
	int scan_fd = -1;
	int removed_temp = 0;
	int rc = -1;

	if (!visitor)
		return -1;
	dir_fd = open_metadata_dir(dir);
	if (dir_fd < 0)
		return -1;
	scan_fd = dup(dir_fd);
	if ((scan_fd < 0) || (fcntl(scan_fd, F_SETFD, FD_CLOEXEC) != 0))
		goto out;
	stream = fdopendir(scan_fd);
	if (!stream)
		goto out;
	scan_fd = -1;
	for (;;)
	{
		errno = 0;
		struct dirent* entry = readdir(stream);

		if (!entry)
		{
			if (errno != 0)
				goto out;
			break;
		}
		if (strncmp(entry->d_name, FRDP_METADATA_TEMP_PREFIX,
		            strlen(FRDP_METADATA_TEMP_PREFIX)) == 0)
		{
			if (remove_temporary_at(dir_fd, entry->d_name) != 0)
				goto out;
			removed_temp = 1;
			continue;
		}
		if (strncmp(entry->d_name, FRDP_METADATA_PREFIX, strlen(FRDP_METADATA_PREFIX)) != 0)
			continue;
		{
			frdpSesmandSessionMetadata metadata = { 0 };
			struct stat file_stat = { 0 };

			if ((metadata_load_at(dir_fd, entry->d_name, &metadata, &file_stat) != 0) ||
			    (visitor(&metadata, (uint64_t)file_stat.st_dev, (uint64_t)file_stat.st_ino,
			             context) != 0))
				goto out;
		}
	}
	if (removed_temp && (fsync(dir_fd) != 0))
		goto out;
	rc = 0;
out:
	if (stream)
		closedir(stream);
	else if (scan_fd >= 0)
		close(scan_fd);
	if (dir_fd >= 0)
		close(dir_fd);
	return rc;
}

int frdp_sesmand_session_metadata_remove(const char* dir, const char* session_id,
                                         uint64_t expected_dev, uint64_t expected_ino)
{
	frdpSesmandSessionMetadata metadata = { 0 };
	char filename[96] = { 0 };
	struct stat file_stat = { 0 };
	int dir_fd = -1;
	int rc = -1;

	if ((expected_dev == 0) || (expected_ino == 0) ||
	    (frdp_sesmand_session_metadata_filename(filename, sizeof(filename), session_id) != 0))
		return -1;
	dir_fd = open_metadata_dir(dir);
	if (dir_fd < 0)
		return -1;
	if ((metadata_load_at(dir_fd, filename, &metadata, &file_stat) != 0) ||
	    ((uint64_t)file_stat.st_dev != expected_dev) ||
	    ((uint64_t)file_stat.st_ino != expected_ino) ||
	    !same_path_entry(dir_fd, filename, &file_stat) || (unlinkat(dir_fd, filename, 0) != 0) ||
	    (fsync(dir_fd) != 0))
		goto out;
	rc = 0;
out:
	close(dir_fd);
	return rc;
}
