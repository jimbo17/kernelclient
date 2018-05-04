/*
 * metanode_proto.h - define CFS metanode message protocol
 */

#ifndef METANODE_PROTO_H
#define METANODE_PROTO_H

#include "cfs_pub.h"

/* metanode message operation */
typedef enum metanode_op {
    OP_GET_METANODE_LEADER     = 0x1001,
    OP_CREATE_DIR,
    OP_STAT,
    OP_GET_INODE_INFO,
    OP_LIST,
    OP_DELETE_DIR,
    OP_RENAME,
    OP_CREATE_FILE,
    OP_DELETE_FILE,
    OP_GET_FILE_CHUNKS,
    OP_ALLOCATE_CHUNK,
    OP_SYNC_CHUNK,
    OP_ASYNC_CHUNK,
    OP_SYMLINK,
    OP_READ_LINK,
    OP_DELETE_SYMLINK,
    OP_GET_SYMLINK_INFO,
} METANODE_OP_E;

struct get_meta_leader_req {
    char    volid[CFS_UUID_LEN+1];
} __attribute__ ((packed));

struct get_meta_leader_ack {
    __le32  ret;/* Note that all 'ret' is int32 */
    char    leader[CFS_IP4PORT_LEN_MAX+1];
} __attribute__ ((packed));

struct metanode_file_req {
    char    volid[CFS_UUID_LEN+1];
    __le64  pinode;
    char    name[CFS_FILENAME_MAX+1];
} __attribute__ ((packed));

typedef struct metanode_file_req create_dir_req_t, stat_req_t, get_inode_info_req_t, delete_dir_req_t, 
        create_file_req_t, delete_file_req_t, get_file_chunks_req_t;

struct metanode_ack {
    __le32  ret;
} __attribute__ ((packed));

typedef struct metanode_ack delete_dir_ack_t, rename_dir_ack_t, delete_file_ack_t, sync_chunk_ack_t;

struct metanode_inode_ack {
    __le32  ret;
    __le64  inode;
} __attribute__ ((packed));

typedef struct metanode_inode_ack create_dir_ack_t, create_file_ack_t;

struct stat_ack {
    __le32  ret;
    __le32  inode_type;
    __le64  inode;
} __attribute__ ((packed));

struct chunk_info {
    __le64  chunk_id;
    __le32  chunk_size;
    __le64  block_group_id;
} __attribute__ ((packed));

struct inode_info {
    __le64  modifi_time;
    __le64  access_time;
    __le32  link;
    __le64  file_size;
    __le32  chunk_num;
    struct chunk_info chun_info[0];/* chunks info of this inode */
} __attribute__ ((packed));

struct get_inode_info_ack {
    __le32  ret;
    __le64  inode;
    /* inode_info must be the last field due to we dont know number of chunk_info[] */
    struct inode_info inode_info;
} __attribute__ ((packed));

struct list_req {
    char    volid[CFS_UUID_LEN+1];
    __le64  pinode;
    char    name[CFS_FILENAME_MAX+1];
    __le64  ginode;
} __attribute__ ((packed));

struct dirent_info {
    __le32  inode_type;
    __le64  inode;
    char    name[CFS_FILENAME_MAX+1];
} __attribute__ ((packed));

struct list_ack {
    __le32  ret;
    __le32  dirent_num;
    struct dirent_info dirents[0];
} __attribute__ ((packed));


struct rename_dir_req {
    char    volid[CFS_UUID_LEN+1];
    __le64  old_pinode;
    char    old_name[CFS_FILENAME_MAX+1];
    __le64  new_pinode;
    char    new_name[CFS_FILENAME_MAX+1];
} __attribute__ ((packed));

struct block_info {
    __le64  block_id;
    char    ip[CFS_IP_LEN_MAX+1];
    __le32  port;
    __le32  status;
    __le64  block_group_id;
    char    volid[CFS_UUID_LEN+1];
    __le32  path_len;
    char    path[0];
} __attribute__ ((packed));

struct block_group {
    __le32  block_num;
    struct block_info blocks[0];
} __attribute__ ((packed));

struct block_group_with_host {
    __le64  block_group_id;
    __le32  host_num;
    char    hosts[CFS_BLOCKGROUP_MAX][CFS_IP4PORT_LEN_MAX+1];
} __attribute__ ((packed));

struct chunk_info_with_bg {
    __le64 chunk_id;
    __le32 chunk_size;
    struct block_group block_group;
} __attribute__ ((packed));

struct get_file_chunks_ack {
    __le32  ret;
    __le64  inode;
    __le32  chunk_num;
    struct chunk_info_with_bg chunk_infos[0];
} __attribute__ ((packed));

struct allocate_chunk_req {
    char    volid[CFS_UUID_LEN+1];
} __attribute__ ((packed));

struct allocate_chunk_ack {
    __le32  ret;
    struct chunk_info_with_bg chunk_info;
} __attribute__ ((packed));

struct sync_chunk_req {
    char    volid[CFS_UUID_LEN+1];
    __le64  parent_inode_id;
    char    name[CFS_FILENAME_MAX+1];
    struct chunk_info chunk_info;
    __le64  size;
} __attribute__ ((packed));

#endif

