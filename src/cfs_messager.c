

#include "cfs_messager.h"

#define MAX_ADDRSTR_LEN	64	/* INET6_ADDRSTRLEN:48 + port:5 + Terminal:1 = 54 */

/*
 * CFS messager receiving state
 */
#define RECV_STATE_INITIAL  0
#define RECV_STATE_HEADER   1
#define RECV_STATE_FRONT	2
#define RECV_STATE_DATA     3
#define RECV_STATE_DONE     4
#define RECV_STATE_ERR      5

/*
 * CFS messager sending state
 */
#define SEND_STATE_INITIAL  0
#define SEND_STATE_HEADER   1 /* header+front */
#define SEND_STATE_DATA     2
#define SEND_STATE_DONE     3
#define SEND_STATE_ERR      4


/*
 * CFS messager flag bits
 */
#define FLAG_LOSSYTX              0  /* we can close channel or drop messages on errors */
#define FLAG_KEEPALIVE_PENDING    1  /* we need to send a keepalive */
#define FLAG_MESSAGE_PENDING      2  /* there are pending messages waiting to send */
#define FLAG_SOCK_CLOSED	      3  /* socket state changed to closed */
#define FLAG_BACKOFF              4  /* need to retry queuing delayed work */
#define FLAG_MSGER_STOPPING       5  /* messager is stopping */


/*
 * work queue for CFS messager sending/receiving messages
 */
static struct workqueue_struct *cfs_msger_workqueue;

#ifdef CONFIG_LOCKDEP
static struct lock_class_key cfs_socket_class;
#endif

static void cfs_cancel_work(struct cfs_messager *msger)
{
	if (cancel_delayed_work(&msger->work)) {
		dprintk("msger:%p cancel work success!\n", msger);
		msger->ops->put(msger->private);
	}
}


/*
 * Queue work on a messager if receiving a interrupt or user calling send on the socket.
 */
static int cfs_queue_work(struct cfs_messager *msger)
{
    
    /* get @msger reference to avoid conflict with connection close.*/
	if (!msger->ops->get(msger->private)) {
		eprintk("get msger:%p ref count failed!\n", msger);
		return -ENOENT;
	}
    
    /* trigger work with no delay. */
	if (!queue_delayed_work(cfs_msger_workqueue, &msger->work, 0)) {
		eprintk("work of msger:%p already queued\n", msger);
		msger->ops->put(msger->private);
		return -EBUSY;
	}

	dprintk("msger:%p queue work success!\n", msger);
	return 0;
}


/* data available on socket, or listen socket received a connect */
static void cfs_sk_data_ready(struct sock *sk, int count_unused)
{
	struct cfs_messager *msger = sk->sk_user_data;
	if (test_bit(FLAG_MSGER_STOPPING, &msger->flags)) {
        dprintk("%p messager is stopping\n", msger);
		return;
	}

	if (sk->sk_state != TCP_CLOSE_WAIT) {
        dprintk("%p data ready on sock\n", msger);
		cfs_queue_work(msger);
	} else {
		dprintk("%p sock is CLOSE_WAIT\n", msger);
	}
}

/* socket has buffer space for writing */
static void cfs_sk_write_space(struct sock *sk)
{
	struct cfs_messager *msger = sk->sk_user_data;

	if (test_bit(FLAG_MESSAGE_PENDING, &msger->flags)) {
		if (sk_stream_is_writeable(sk)) {
			dprintk("%p sock is writeable\n", msger);
			clear_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			cfs_queue_work(msger);
		}
	} else {
		dprintk("%p no pending messages\n", msger);
	}
}

/* socket's state has changed */
static void cfs_sk_state_change(struct sock *sk)
{
	struct cfs_messager *msger = sk->sk_user_data;

	dprintk("%p sock state change to: %u\n", msger, sk->sk_state);

	switch (sk->sk_state) {
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		set_bit(FLAG_SOCK_CLOSED, &msger->flags);
		cfs_queue_work(msger);
		break;
	case TCP_ESTABLISHED:
		cfs_queue_work(msger);
		break;
	default:
		break;
	}
}



/*
 * init socket 
 */
static void cfs_init_sock(struct socket *sock, struct cfs_messager *msger)
{
	struct sock *sk = sock->sk;
#ifdef CONFIG_LOCKDEP
    lockdep_set_class(&sk->sk_lock, &cfs_socket_class);
#endif
    sk->sk_allocation = GFP_NOFS;
	sk->sk_user_data = msger;
	sk->sk_data_ready = cfs_sk_data_ready;
	sk->sk_write_space = cfs_sk_write_space;
	sk->sk_state_change = ceph_sock_state_change;
}


/*
 * try tcp connecting to server
 */
int cfs_connect(struct cfs_messager *msger)
{
    struct sockaddr_storage *paddr = msger->sock_addr;
    struct socket *sock;
    int ret;
    char addr_buf[MAX_ADDRSTR_LEN];
    int optval = 1;

    BUG_ON(msger->sock);
    ret = __sock_create(cfs_net_ns(), paddr->ss_family, SOCK_STREAM, IPPROTO_TCP, &sock, 1);
    if (ret != 0)
        return ret;
    cfs_init_sock(sock, msger);

    dprintk("connecting to %s\n", cfs_ntop(paddr, addr_buf, sizeof(addr_buf)));

    ret = sock->ops->connect(sock, (struct sockaddr *)paddr, sizeof(*paddr), O_NONBLOCK);
    if (ret == -EINPROGRESS) {
        dprintk("connecting %s EINPROGRESS sk_state = %u\n", cfs_ntop(paddr, addr_buf, sizeof(addr_buf)), 
            sock->sk->sk_state);
    } else if (ret < 0) {
        eprintk("connecting %s error %d\n", cfs_ntop(paddr, addr_buf, sizeof(addr_buf)), ret);
        sock_release(sock);
        return ret;
    }

    ret = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&optval, sizeof(optval));
    if (ret)
        eprintk("kernel_setsockopt(TCP_NODELAY) failed: %d", ret);

    msger->sock = sock;
    return 0;
}

static int cfs_try_connect(struct cfs_messager *msger)
{
    if (msger->sock) {
        if (msger->sock->sk->sk_state == TCP_ESTABLISHED) {
            msger->state = CFS_STATE_WORKING;
            msger->recv_state = RECV_STATE_INITIAL;
            
            mutex_unlock(&msger->mutex);
            msger->ops.handle_conn(msger->private, 0);
            mutex_lock(&msger->mutex);
        }        
        return 0;
    }
    
    return cfs_connect(msger);
}

static int cfs_check_msg_header(struct cfs_messager *msger)
{
    dprintk("Received a msg with header: version:%u proto:%u, seq:%u, tid:%u, len:%u, crc:%u\n", 
        msger->recv_msg_header.version, msger->recv_msg_header.proto, msger->recv_msg_header.seq, 
        msger->recv_msg_header.tid, msger->recv_msg_header.data_len, msger->recv_msg_header.crc);

    if (msger->recv_msg_header.version != CFS_MSG_VERSION_1) {
        eprintk("invalid messager version: %u\n", msger->recv_msg_header.version);
        return -1;
    }
    if (msger->recv_msg_header.proto != msger->proto) {
        eprintk("invalid messager protocol: %u != msger proto: %u\n", msger->recv_msg_header.proto, msger->proto);
        return -1;
    }

    //checksum
    
    return 0;
}


static int cfs_recvmsg(struct cfs_messager *msger, void *base, size_t len)
{
	struct kvec iov;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };

    iov.iov_base = (void *)((char *)base + msger->recv_len);
    iov.iov_len = len - msger->recv_len;

	int ret = kernel_recvmsg(msger->sock, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
    if (ret > 0)
        msger->recv_len += ret;
	return ret;
}

static int cfs_recvpage()
{
    return 0;
}

static int cfs_sendmsg(struct cfs_messager *msger, struct kvec *iov, size_t num, size_t size, int more)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	msg.msg_flags |= (more ? MSG_MORE : MSG_EOR);

	return kernel_sendmsg(msger->sock, &msg, iov, num, size);
}

static int cfs_send_kvec(struct cfs_messager *msger, int more)
{
    int ret = 0;
    while (msger->kvec_bytes) {
        ret = kernel_sendmsg(msger, msger->sending_kvec, msger->kvec_num, msger->kvec_bytes, more);
        if (ret <= 0)
            return ret;

        msger->kvec_bytes -= ret;
        
    	while (ret >= msger->sending_kvec->iov_len) {
    		BUG_ON(msger->kvec_num == 0);
    		ret -= msger->sending_kvec->iov_len;
    		msger->sending_kvec++;
    		msger->kvec_num--;
    	}

    	if (ret) {
    		msger->sending_kvec->iov_len -= ret;
    		msger->sending_kvec->iov_base += ret;
    	}
    }

    msger->kvec_num = 0;
    return 1;
}

static int cfs_sendpage()
{
    return 0;
}

static int cfs_try_recv(struct cfs_messager *msger)
{
    int ret = 0;
    if (msger->recv_state == RECV_STATE_INITIAL) {
        msger->recv_len = 0;
        msger->recv_state = RECV_STATE_HEADER;
    }

    if (msger->recv_state == RECV_STATE_HEADER) {
        ret = cfs_recvmsg(msger, &msger->recv_msg_header, sizeof(struct cfs_msg_header));
        if (ret < 0) {
            return (ret == -EAGAIN ? 0 : ret);
        }
        if (msger->recv_len == sizeof(msger->recv_msg_header)) {
            msger->recv_state = RECV_STATE_FRONT;
            msger->recv_len = 0;
            ret = cfs_check_msg_header(msger)
            if (ret < 0) {
                return -EIO;
            }
            
            BUG_ON(msger->recv_msg);
            msger->recv_msg = cfs_msg_alloc(msger->recv_msg_header.middle_len, msger->recv_msg_header.data_len);
            if (msger->recv_msg == NULL) {
                return -ENOMEM;
            }
            memcpy(&msger->recv_msg->header, &msger->recv_msg_header, sizeof(struct cfs_msg_header));
        }
    }

    if (msger->recv_state == RECV_STATE_FRONT) {
        ret = cfs_recvmsg(msger, msger->recv_msg->front, msger->recv_msg->header.front_len);
        if (ret < 0) {
            return (ret == -EAGAIN ? 0 : ret);
        }
        if (msger->recv_len == msger->recv_msg->header.front_len) {
            msger->recv_state = msger->recv_msg->header.data_len ? RECV_STATE_DATA : RECV_STATE_DONE;
            msger->recv_len = 0;
        }
    }

    if (msger->recv_state == RECV_STATE_DATA) {
        ret = cfs_recvpage();
        if (ret < 0) {
            return (ret == -EAGAIN ? 0 : ret);
        }
        if (msger->recv_len == msger->recv_msg->header.data_len) {
            msger->recv_state = RECV_STATE_DONE;
        }
    }

    if (msger->recv_state == RECV_STATE_DONE) {
        struct cfs_msg *msg = msger->recv_msg;
        msger->recv_msg = NULL;
        
        mutex_unlock(&msger->mutex);
        msger->ops->handle_msg(msger->private, msg);
        mutex_lock(&msger->mutex);
        
        msger->recv_state = RECV_STATE_INITIAL;
        ret = 1;/* try to recv next */
    }
    
    return ret;
}

static void cfs_init_sending_msg(struct cfs_messager *msger, struct cfs_msg *msg)
{
    msg->header.version = cpu_to_le16(CFS_MSG_VERSION_1);
    msg->header.proto = cpu_to_le16(msger->proto);
    msg->header.seq = cpu_to_le64(msger->sent_seq++);
    
	u32 crc = crc32c(0, &msg->header, offsetof(struct cfs_msg_header, crc));
    msg->header.crc = cpu_to_le32(crc);

    msger->send_kvec[0].iov_base = &msger->sending_msg->header;
    msger->send_kvec[0].iov_len = sizeof(struct cfs_msg_header);
    msger->send_kvec[1].iov_base = msger->sending_msg->front;
    msger->send_kvec[1].iov_len = msger->sending_msg->header.front_len;
    msger->sending_kvec = msger->send_kvec;
    msger->kvec_num = 2;
    msger->kvec_bytes = msger->send_kvec[0].iov_len + msger->send_kvec[1].iov_len;
    msger->send_state = SEND_STATE_HEADER;
}

static int cfs_try_send(struct cfs_messager *msger)
{
    int ret = 0;
    struct cfs_msg *msg;

    if (msger->send_state == SEND_STATE_INITIAL) {
        if (list_empty(&msger->send_queue)) 
            return 0;
        msger->sending_msg = list_first_entry(&msger->out_queue, struct cfs_msg, lh);
        list_del(&msger->sending_msg->lh);
        cfs_init_sending_msg(msger->sending_msg);
    }
    
    if (msger->send_state == SEND_STATE_HEADER) {
        ret = cfs_send_kvec(msger, (msger->sending_msg->header.data_len ? 1 : 0))
        if (ret < 0) {
            return (ret == -EAGAIN ? 0 : ret);
        }
        if (msger->kvec_bytes == 0) {
            msger->send_state = (msger->sending_msg->header.data_len ? SEND_STATE_DATA : SEND_STATE_DONE);
        }
    }

    if (msger->send_state == SEND_STATE_DATA) {
        //TODO
    }

    if (msger->send_state == SEND_STATE_DONE) {

        cfs_msg_put(msger->sending_msg);
		msger->sending_msg = NULL;

        msger->send_state = SEND_STATE_INITIAL;
        ret = 1; /* try to send next */
    }

    return ret;
}


#define MSGER_ERROR_CONNECT    (-1)
#define MSGER_ERROR_SEND       (-2)
#define MSGER_ERROR_RECEIVE    (-3)
#define MSGER_ERROR_SOCK       (-4)

static void cfs_msger_error(struct cfs_messager *msger, int err)
{
    dprintk("cfs msger error: %d\n", err);
    msger->state = CFS_STATE_ERROR;

    mutex_unlock(&msger->mutex);
    switch (err) {            
        case MSGER_ERROR_RECEIVE:
            msger->ops.handle_err(msger->private, NULL);
            break;
            
        case MSGER_ERROR_SEND:
            msger->ops.handle_err(msger->private, msger->sending_msg);
            cfs_msg_put(msger->sending_msg);
    		msger->sending_msg = NULL;
            break;

        case MSGER_ERROR_CONNECT:
            msger->ops.handle_conn(msger->private, -1);
            break;
            
        case MSGER_ERROR_SOCK:
            msger->ops.handle_err(msger->private, NULL);
            break;
            
        default:
            msger->ops.handle_err(msger->private, NULL);
            break;
    }
    mutex_lock(&msger->mutex);
}

/*
 * Do some work on a connection. 
 */
static void cfs_msger_worker(struct work_struct *work)
{
	struct cfs_messager *msger = container_of(work, struct cfs_messager, work.work);
    int rret = 0, sret = 0, err = 0;

	mutex_lock(&msger->mutex);

    while (true) {
        if (msger->state == CFS_STATE_CLOSED || msger->state == CFS_STATE_CLOSING || msger->state == CFS_STATE_ERROR) {
    		dprintk("do nothing when msger is %u.\n", msger->state);
    		break;
        }

        if (test_bit(FLAG_SOCK_CLOSED, &msger->flags)) {
            err = MSGER_ERROR_SOCK;
            break;
        }
        
        if (msger->state == CFS_STATE_OPENING) {
            err = cfs_try_connect(msger);
            if (err != 0) {
                err = MSGER_ERROR_CONNECT;
            }
        }
        
        if (msger->state == CFS_STATE_WORKING) {
    		rret = cfs_try_recv(msger);
    		if (rret < 0) {
                err = MSGER_ERROR_RECEIVE;
    			break;
            }

    		sret = cfs_try_send(msger);
    		if (sret < 0) {
                err = MSGER_ERROR_SEND;
    			break;
            }

            /* nothing received or sent */
            if (rret == 0 && sret == 0) {
                break;
            }
        }
    }

	if (err != 0) {
        cfs_msger_error(msger, err);
    }
		
	mutex_unlock(&msger->mutex);

    /* Put @msger reference before return */
	msger->ops->put(msger->private);
}


static void cfs_msg_free(struct cfs_msg *msg)
{
    if (msg->msger) {
        msg->msger->ops->put(msg->msger->private);
        msg->msger = NULL;
    }
    //TODO: free pages
    
    if (msg->front)
        kvfree(msg->front);
    kvfree(msg);
}

/* interface to alloc new msg */
struct cfs_msg *cfs_msg_alloc(size_t front_len, size_t data_len)
{
    struct cfs_msg *msg = cfs_malloc(sizeof(struct cfs_msg), GFP_NOFS);
    if (msg == NULL)
        return NULL;
    memset(msg, 0, sizeof(struct cfs_msg));

    msg->front = cfs_malloc(front_len, GFP_NOFS);
    if (msg->front == NULL) {
        cfs_msg_free(msg)
        return NULL
    }
    msg->header.front_len = front_len;

    if (data_len) {
        //TODO: alloc pages
    }

    INIT_LIST_HEAD(&msg->lh);
    kref_init(&msg->kref);
    return msg;
}
EXPORT_SYMBOL(cfs_msg_alloc);

/* interface to get ref of @msg */
struct cfs_msg *cfs_msg_get(struct cfs_msg *msg)
{
	dprintk("%p ref %d\n", msg, atomic_read(&msg->kref.refcount));
	kref_get(&msg->kref);
	return msg;
}
EXPORT_SYMBOL(cfs_msg_get);

/* interface to put ref of @msg */
void cfs_msg_put(struct cfs_msg *msg)
{
	dprintk("%p ref %d\n", msg, atomic_read(&msg->kref.refcount));
	kref_put(&msg->kref, cfs_msg_free);
}
EXPORT_SYMBOL(cfs_msg_put);


/*
 * interface to send a msg to messager
 */
int cfs_messager_send(struct cfs_messager *msger, struct cfs_msg *msg)
{
	mutex_lock(&msger->mutex);

	if (msger->state != CFS_STATE_WORKING) {
		eprintk("msger %p is not working, dropping %p\n", msger, msg);
        goto fail_unlock;
	}

    if (!msger->ops->get(msger->private)) {
		eprintk("get msger:%p ref count failed!\n", msger);
        goto fail_unlock;
	}
    msg->msger = msger;

	BUG_ON(!list_empty(&msg->lh));
	list_add_tail(&msg->lh, &msger->send_queue);
	mutex_unlock(&msger->mutex);

	/* queue new work */
	if (test_and_set_bit(FLAG_MESSAGE_PENDING, msger->flags) == 0)
		cfs_queue_work(msger);
    return 0;

fail_unlock:
	cfs_msg_put(msg);
	mutex_unlock(&msger->mutex);
	return -1;
}
EXPORT_SYMBOL(cfs_messager_send);

/*
 * interface to close the messager
 */
int cfs_messager_close(struct cfs_messager *msger)
{
    mutex_lock(&msger->mutex);
    msger->state = CFS_STATE_CLOSING;
    mutex_unlock(&msger->mutex);
}
EXPORT_SYMBOL(cfs_messager_close);


/*
 * interface to open a messager with a new peer address.
 */
int cfs_messager_open(struct cfs_messager *msger, u16 proto, struct sockaddr_storage in_addr)
{
    mutex_lock(&msger->mutex);
    if (msger->state != CFS_STATE_CLOSED) {
        eprintk("please close msger first! state: %u\n", msger->state);
        mutex_unlock(&msger->mutex);
        return -EPERM;
    }
    msger->proto = proto;
    msger->sock_addr = in_addr;
    msger->state = CFS_STATE_OPENING;
    mutex_unlock(&msger->mutex);
    
    /* trigger tcp connect work */
    cfs_queue_work(msger);
    return 0;
}
EXPORT_SYMBOL(cfs_messager_open);


/*
 * interface to initialize a new messager which's memory provied by user.
 */
void cfs_messager_init(struct cfs_messager *msger, void *private, struct cfs_messager_operations *ops)
{
    memset(msger, 0, sizeof(*msger));
    msger->private = private;
    msger->ops = ops;

	mutex_init(&msger->mutex);
	INIT_LIST_HEAD(&msger->send_queue);
	INIT_DELAYED_WORK(&msger->work, cfs_msger_worker);
    msger->state = CFS_STATE_CLOSED;
}
EXPORT_SYMBOL(cfs_messager_init);

/*
 * interface to exit messager module.
 */
void exit_messager_module(void)
{
    if (cfs_msger_workqueue) {
        destroy_workqueue(cfs_msger_workqueue);
        cfs_msger_workqueue = NULL;
    }

}
EXPORT_SYMBOL(exit_messager_module);

/*
 * interface to init messager module.
 */
int init_messager_module(void)
{
	cfs_msger_workqueue = alloc_workqueue("cfs-msger", WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	if (NULL == cfs_msger_workqueue)
		return -ENOMEM;

    return 0;
}
EXPORT_SYMBOL(init_messager_module);

