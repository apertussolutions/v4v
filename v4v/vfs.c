

#include "v4v.h"
#include "vfs.h"
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/sched.h>


static struct vfsmount *v4v_mnt = NULL;
static const struct file_operations v4v_fops_stream;
static const struct dentry_operations v4vfs_dentry_operations;

#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37) ) /* get_sb_pseudo */
static int v4vfs_get_sb(struct file_system_type *fs_type, int flags,
              const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_pseudo(fs_type, "v4v:", NULL, V4VFS_MAGIC, mnt);
}
#else
static struct dentry *v4vfs_mount_pseudo(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "v4v:", NULL, &v4vfs_dentry_operations,
		  V4VFS_MAGIC);
}
#endif /* 2.6.37 get_sb_pseudo */

static struct file_system_type v4v_fs = {
	/* No owner field so module can be unloaded */
	.name = "v4vfs",
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37) ) /* get_sb_pseudo */
	.get_sb = v4vfs_get_sb,
#else
	.mount = v4vfs_mount_pseudo,
#endif /* 2.6.37 get_sb_pseudo */
	.kill_sb = kill_litter_super
};

static char *v4vfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	/* dynamic_dname is not exported */
	snprintf(buffer, buflen, "v4v:[%lu]", dentry->d_inode->i_ino);
	return buffer;
}

static const struct dentry_operations v4vfs_dentry_operations = {
	.d_dname = v4vfs_dname,
};

int allocate_fd_with_private(void *private)
{
	int fd;
	struct file *f;
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) )
	struct qstr name = { .name = "" };
	struct path path;
	struct inode *ind;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
	fd = get_unused_fd();
#else
	fd = get_unused_fd_flags(O_CLOEXEC);
#endif
	if (fd < 0)
		return fd;

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) )
	path.dentry = d_alloc_pseudo(v4v_mnt->mnt_sb, &name);
	if (unlikely(!path.dentry)) {
		put_unused_fd(fd);
		return -ENOMEM;
	}

	ind = new_inode(v4v_mnt->mnt_sb);
	ind->i_ino = get_next_ino();
	ind->i_fop = v4v_mnt->mnt_root->d_inode->i_fop;
	ind->i_state =  v4v_mnt->mnt_root->d_inode->i_state;
	ind->i_mode =  v4v_mnt->mnt_root->d_inode->i_mode;
	ind->i_uid = current_fsuid();
	ind->i_gid = current_fsgid();
	d_instantiate(path.dentry, ind);

	path.mnt = mntget(v4v_mnt);

	DEBUG_APPLE;
	f = alloc_file (&path,
#else
	f = alloc_file (v4v_mnt,
#endif
#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32) ) /* alloc_file */
		dget (v4v_mnt->mnt_root),
#endif
		FMODE_READ | FMODE_WRITE, &v4v_fops_stream);
	if (!f) {
		//FIXME putback fd?
		return -ENFILE;
	}

	f->private_data = private;

	fd_install (fd, f);

	return fd;
}

int setup_fs (void)
{
	int ret;

	ret = register_filesystem(&v4v_fs);
	if (ret) {
		printk(KERN_ERR "v4v: couldn't register tedious filesystem thingy\n");
		return ret;
	}

	v4v_mnt = kern_mount(&v4v_fs);
	if (IS_ERR(v4v_mnt)) {
		unregister_filesystem(&v4v_fs);
		ret = PTR_ERR(v4v_mnt);
		printk(KERN_ERR "v4v: couldn't mount tedious filesystem thingy\n");
		return ret;
	}

	return 0;
}

void unsetup_fs(void)
{
	mntput(v4v_mnt);
	unregister_filesystem(&v4v_fs);
}

