/*
 * cfs_messager.h - CFS message interface between kernel client and CFS Metadata/Data Nodes
 */

#ifndef CFS_MESSAGER_H
#define CFS_MESSAGER_H

#define CFS_MSG_VERSION_1     1

#define CFS_MSG_PROTOCOL_VOLMGR     1
#define CFS_MSG_PROTOCOL_METANODE   2
#define CFS_MSG_PROTOCOL_DATANODE   3

#define CFS_MSG_PROTOCOL_VOLMGR_PORT    (7705)
#define CFS_MSG_PROTOCOL_METANODE_PORT  (9905)
#define CFS_MSG_PROTOCOL_DATANODE_PORT  (8805)

/* CFS message header */
struct cfs_msg_header {
    __le16 version;     /* version of CFS messager protocol */
    __le16 proto;       /* message protocol type */
    __le64 seq;         /* message seq# for this session */
    __le32 front_len;   /* bytes of message request/ack header */
    __le32 data_len;    /* bytes of read/write data */
    __le32 crc;         /* crc of cfs_msg_header */
} __attribute__ ((packed));


/* CFS message : header + front(upper header) + possibly a data payload (pages). */
struct cfs_msg {
    struct cfs_msg_header header;
    void    *front;     /* pointer to upper request/ack header */
    struct list_head page_list;  /* list of read/write pages */

    /* for msg management */
    struct cfs_messager *msger;
    struct list_head  lh;
    struct kref kref;
};

/* callbacks definition. */
struct cfs_messager_operations {
    /* get/put upper structure reference */
	int (*get)(void *);
	void (*put)(void *);

    /* handle connection result: 0: ok, others: error */
    void (*handle_conn) (void *, int);

    /* handle an error, give the cfs_msg if sent error */
    void (*handle_err) (void *, struct cfs_msg *);

	/* handle a received message */
	void (*handle_msg) (void *, struct cfs_msg *);
};

/* CFS messager for one client/server peer connection */
struct cfs_messager {
    void    *private;
    struct cfs_messager_operations *ops;
    u16     proto;
	struct mutex    mutex;
    u32     flags;
    u32     state;

    /* socket infos */
    struct socket *sock;
    struct sockaddr_storage sock_addr;

    /* receiving */
    struct cfs_msg_header recv_msg_header;
    struct cfs_msg *recv_msg;
    u32     recv_state;
    u32     recv_len;

	/* sending */
	struct list_head send_queue;
    struct cfs_msg *sending_msg;
    u32     send_state;
	u64     sent_seq;
    struct kvec send_kvec[2], *sending_kvec; /* header+front */
    u32     kvec_num;
    u32     kvec_bytes;

    /* work for receiving/sending */
    struct delayed_work work;
    u32     work_state;
};

/* Return default network namespace */
static inline struct net *cfs_net_ns(void)
{
	return &init_net;
}


/* Usage: msg_alloc -> msg_get -> send -> msg_put */

extern void cfs_msg_put(struct cfs_msg *msg);

extern struct cfs_msg *cfs_msg_get(struct cfs_msg *msg);

extern struct cfs_msg *cfs_msg_alloc(size_t front_len, size_t data_len);

extern static void cfs_msg_free(struct cfs_msg *msg);
    
extern int cfs_messager_send(struct cfs_messager *msger, struct cfs_msg *msg);

extern int cfs_messager_close(struct cfs_messager *msger);

extern int cfs_messager_open(struct cfs_messager *msger, u16 proto, struct sockaddr_storage in_addr);

extern void cfs_messager_init(struct cfs_messager *msger, void *private, struct cfs_messager_operations *ops);

extern void exit_messager_module(void);

extern int init_messager_module(void);


#endif
