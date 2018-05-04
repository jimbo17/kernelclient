/*
 * cfs_super.h - CFS super block ops
 */

#ifndef CFS_SUPER_H
#define CFS_SUPER_H


struct cfs_inode {

    struct inode vfs_inode;/* end of cfs_inode*/
};

static inline struct cfs_inode *cfs_inode_from_vfs(struct inode *inode)
{
    return container_of(inode, struct cfs_inode, vfs_inode);
}

struct cfs_mount_options {
    int flags;
};

#endif
