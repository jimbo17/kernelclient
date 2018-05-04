
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/slab.h>

#include "cfs_pub.h"
#include "cfs_super.h"

static int cfs_parse_mount_options(struct cfs_mount_options **popts,
                           int flags, char *options, const char *dev_name)
{
    dprintk("flags: %d, dev_name: %s, options: %s\n", flags, dev_name, options);
    return -EINVAL;
}

struct dentry *cfs_mount(struct file_system_type *fs_type,
                    int flags, const char *dev_name, void *data) 
{
    struct dentry *res;
    struct cfs_mount_options *opts;
    int err = cfs_parse_mount_options(&opts, flags, data, dev_name);
    if (err) {
        res = ERR_PTR(err);
        goto out;
    }

out:
    return res;
}

void cfs_kill_sb(struct super_block *sb) {
    kill_anon_super(sb);
    dprintk("kill sb %p.\n", sb);
}

struct kmem_cache *cfs_inode_cachep;

static void cfs_inode_init_once(void *foo)
{
    struct cfs_inode *ci = foo;
    inode_init_once(&ci->vfs_inode);
}

static int __init init_caches(void)
{
    cfs_inode_cachep = kmem_cache_create("cfs_inode_cache",
                                 sizeof(struct cfs_inode),
                                 0,
                                 (SLAB_RECLAIM_ACCOUNT| SLAB_MEM_SPREAD),
                                 cfs_inode_init_once);
    if (NULL == cfs_inode_cachep) {
        return -ENOMEM;
    }
    return 0;
}

static void destroy_caches(void)
{
    kmem_cache_destroy(cfs_inode_cachep);
}    

static struct file_system_type cfs_fs_type = {
    .owner      = THIS_MODULE,
    .name       = "cfs",
    .mount      = cfs_mount,
    .kill_sb    = cfs_kill_sb,
    .fs_flags   = FS_RENAME_DOES_D_MOVE,
};
MODULE_ALIAS_FS("cfs");

static int __init cfs_init(void)
{
    int ret = init_caches();
    if (ret)
        goto out;

    int ret = init_messager_module();
    if (ret)
        goto out;

    ret = register_filesystem(&cfs_fs_type);
    if (ret) {
        eprintk("Failed to register filesystem, ret: %d!\n", ret);
        destroy_caches();
        goto out;
    }

    iprintk("filesystem registered succesfully.\n");

out:
    return ret;
}

static void __exit cfs_exit(void)
{
    int ret = unregister_filesystem(&cfs_fs_type);
    destroy_caches();

    if (likely(ret == 0)) {
        iprintk("Unregistered CFS filesystem succesfully.\n");
    } else {
        eprintk("Failed to unregister CFS filesystem, ret: %d!\n", ret);
    }
}

module_init(cfs_init);
module_exit(cfs_exit);

MODULE_AUTHOR("Jimbo Xia <xiajianbo@jd.com>");
MODULE_DESCRIPTION("Containerfs filesystem for Linux");
MODULE_LICENSE("GPL");
