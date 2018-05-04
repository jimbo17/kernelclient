/*
 * volmgr_proto.h - define CFS volume manager message protocol
 */

#ifndef VOLMGR_PROTO_H
#define VOLMGR_PROTO_H

#include "cfs_pub.h"

/* volmgr message operation */
typedef enum volmgr_op {
    OP_GET_VOLMGR_RG     = 0x0001,
    OP_GET_METANODE_RG,
} VOLMGR_OP_E;

/* get volmgr raft-group info and leader */
struct get_volmgr_rg_req {
    __le32  reserved;
} __attribute__ ((packed));

struct get_volmgr_rg_ack {
    __le32  ret;/* Note that all 'ret' is int32 */
    char    peers[CFS_RG_COUNT][CFS_IP4PORT_LEN_MAX+1];
    __le32  leader;/* leader idx in peers[] */
} __attribute__ ((packed));

/* get metanodes raft-group info and leader for volume-id*/
struct get_metanode_rg_req {
    char    volid[CFS_UUID_LEN+1];
} __attribute__ ((packed));

struct metanode_info {
    __le64  id;
    char    host[CFS_IP4PORT_LEN_MAX+1];
    __le32  status;
    __le64  mem;
} __attribute__ ((packed));

struct get_metanode_rg_ack {
    __le32  ret;/* Note that all 'ret' is int32 */
    __le32  copies;
    struct metanode_info metanodes[CFS_RG_COUNT];
    __le32  leader;/* leader idx in metanodes[] */
} __attribute__ ((packed));

#endif

