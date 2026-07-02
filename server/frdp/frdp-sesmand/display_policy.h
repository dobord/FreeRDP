#ifndef FRDP_SESMAND_DISPLAY_POLICY_H
#define FRDP_SESMAND_DISPLAY_POLICY_H

#include <stddef.h>

#define FRDP_SESMAND_DISPLAY_MIN 100
#define FRDP_SESMAND_DISPLAY_MAX 65535

int frdp_sesmand_display_number_is_valid(int display);
int frdp_sesmand_display_reservation_path(char *dst, size_t dst_size, const char *dir,
                                          int display);
int frdp_sesmand_display_reservation_create(int display, const char *dir, int *reservation_fd,
                                            char *reservation_path,
                                            size_t reservation_path_size);
void frdp_sesmand_display_reservation_release(int *reservation_fd, const char *reservation_path);

#endif
