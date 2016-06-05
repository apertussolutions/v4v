
#ifndef _V4V_VFS_H
#define _V4V_VFS_H

#define V4VFS_MAGIC 0x56345644  /* "V4VD" */

int allocate_fd_with_private(void *private);
int setup_fs (void);
void unsetup_fs(void);

#endif
