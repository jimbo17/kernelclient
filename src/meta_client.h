/*
 * meta_client.h - client to volmgr cluster and metanode cluster
 */

#ifndef META_CLIENT_H
#define META_CLIENT_H

#include <linux/mutex.h>
#include <linux/rbtree.h>

#include "cfs_pub.h"
#include "cfs_messager.h"
#include "volmgr_proto.h"
#include "metanode_proto.h"

/* volmgr/metanode message header */
struct meta_msg_header {
    __le16  op;         /* message operation: volmgr_op/metanode_op */
    __le16  direction;  /* message direction: CFS_REQUEST or CFS_RESPONSE */
} __attribute__ ((packed));


struct meta_request {
    u64                     tid;
    struct rb_node          node;
    struct meta_client      *mc;
    struct meta_session     *ms;
    struct kref             ref;
    int                     err;
    struct completion       comp;
    unsigned long           timeout;  /* jiffies */
    u32                     flag_reply:1;
    struct cfs_msg          *msg; /* msg to send */
    struct cfs_msg          *ack; /* msg received */
};

struct meta_session {
    u32                     state;
    struct mutex            mutex;
    struct cfs_messager     msger;
    struct sockaddr_storage in_addr;
    struct completion       comp;
    struct kref             ref;
};

struct volmgr_info {
    char    host[CFS_IP4_LEN_MAX+1];/* only ip without port */
    struct sockaddr_storage addr;
};

struct meta_client {
    u32                     state;
    struct mutex            mutex;

    /* volmgrs and metanodes */
    char                    volid[CFS_UUID_LEN+1];
    struct volmgr_info      volmgr_infos[CFS_RG_COUNT];
    struct metanode_info    metanode_infos[CFS_RG_COUNT];
    struct meta_session     *volmgr_session;
    struct meta_session     *metanode_session;
    u32                     copies;

    /* requests management */
    struct rb_root          req_tree;
    u64                     last_tid;
   
};

/* Usage: alloc_req -> (fill req) -> get_req -> do_req -> (get ack) -> put_req */

extern struct meta_request *meta_client_alloc_req(struct meta_client *mc, u32 op);

extern void meta_client_get_req(struct meta_request *req);

extern void meta_client_release_req(struct kref *kref);

extern void meta_client_put_req(struct meta_request *req);

extern int meta_client_do_req(struct meta_client *mc, struct meta_request *req);

extern void meta_client_exit(struct meta_client *mc);

extern struct meta_client *meta_client_init(struct sockaddr_storage *volmgr_addrs);


#endif

