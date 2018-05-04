
#include "meta_client.h"

/*
 * work queue for meta_client: update the leader of volmgrs and metanodes
 */
static struct workqueue_struct *meta_workqueue;

static void __insert_req(struct rb_root *root, struct meta_request *req)
{
    struct rb_node **node = &(root->rb_node), *parent = NULL;
    struct meta_request *tmp = NULL;

    while (*node) {
        parent = *node;
        tmp = container_of(*node, struct meta_request, node);
        if (req->tid < tmp->tid)
            node = &((*node)->rb_left);
        else if (req->tid > tmp->tid)
            node = &((*node)->rb_right);
        else
            BUG();
    }
    
    rb_link_node(&req->node, parent, node);
    rb_insert_color(&req->node, root);
}

static struct meta_request *__search_req(struct rb_root *root, u64 tid)
{
    struct meta_request *req = NULL
    struct rb_node *node = root->rb_node;
    while (node) {
        req = container_of(node, struct meta_request, node);
        if (tid < req->tid)
            node = node->rb_left;
        else if (tid > req->tid)
            node = node->rb_right;
        else
            return req;
    }
    return NULL;
}

static inline void __erase_req(struct rb_root *root, struct meta_request *req)
{
    rb_erase(&req->node, root);
}

static void __register_req(struct meta_client *mc, struct meta_request *req)
{
	req->tid = ++mc->last_tid;
	dprintk("mc_register_request %p tid %lld\n", req, req->tid);
    
	meta_client_get_req(req);
	__insert_req(&mc->req_tree, req);
}

static void __unregister_req(struct meta_client *mc, struct meta_request *req)
{
	dprintk("mc_unregister_request %p tid %lld\n", req, req->tid);

	__erase_req(&mc->req_tree, req);
	ceph_mdsc_put_request(req);
}

int __do_req(struct meta_client *mc, struct meta_request *req)
{
    struct cfs_msg *msg = cfs_msg_get(req->msg);
    int ret = cfs_messager_send(&ms->msger, msg);
    if (ret != 0) {

    }

}


void meta_client_get_req(struct meta_request *req)
{
	kref_get(&req->ref);
}

void meta_client_put_req(struct meta_request *req)
{
	kref_put(&req->ref, meta_client_release_req);
}

struct meta_request *meta_client_alloc_req(struct meta_client *mc, u32 op)
{
    struct meta_request *req = kzalloc(sizeof(*req), GFP_NOFS);
    if (!req)
        return ERR_PTR(-ENOMEM);

    req->mc = mc;
    RB_CLEAR_NODE(&req->node);
    kref_init(&req->ref);
    init_completion(&req->comp);
    //switch op
    size_t front_len = 0;

    req->msg = cfs_msg_alloc(front_len, 0);
    if (NULL == req->msg) {
        eprintk("cfs_msg_alloc front_len %lu failed\n", front_len);
        kfree(req);
        return ERR_PTR(-ENOMEM);
    }
    cfs_msg_get(req->msg);
    
    struct meta_msg_header *head = (struct meta_msg_header *)req->msg->front;
    head->op = (__le16)op;
    head->direction = CFS_REQUEST;

    return req;
}

int meta_client_do_req(struct meta_client *mc, struct meta_request *req)
{
    int ret = 0;
    dprintk("do request %p begin\n", req);
    
	mutex_lock(&mc->mutex);
	__register_req(mc, req);
	__do_req(mc, req);
    mutex_unlock(&mc->mutex);

    if (req->err) {
		ret = req->err;
		goto out;
	}

    unsigned long timeout = req->timeout ? req->timeout : MAX_SCHEDULE_TIMEOUT;
    long comp_ret = wait_for_completion_killable_timeout(&req->comp, timeout);
    if (comp_ret < 0)/* interrupted */
        ret = (int)comp_ret;
	else if (comp_ret == 0)/* timed out */
		ret = -EIO;

    if (req->flag_reply) {
		ret = le32_to_cpu(req->reply_info.head->result);
	} else if (ret < 0) {
		dout("aborted request %lld with %d\n", req->r_tid, err);
    }

out:
    dprintk("do request %p end, ret: %d\n", req, ret);
	return ret;
}

void meta_client_release_req(struct kref *kref)
{
    struct meta_request *req = container_of(kref, struct meta_request, ref);
    if (req->msg) {
        cfs_msg_put(req->msg);
        req->msg = NULL;
    }
    if (req->ack) {
        cfs_msg_put(req->ack);
        req->ack = NULL;
    }
    kfree(req);
}

static inline void __init_session(struct meta_session *ms)
{
    mutex_init(&ms->mutex);
    kref_init(&ms->ref);
    cfs_messager_init(&ms->msger, (void*)ms, cfs_meta_ops);
    init_completion(&ms->comp);
    ms->state == CFS_STATE_OPENING;
}

/* alloc new session and open it */
struct meta_session *mc_open_session(struct sockaddr_storage *addr, u16 proto)
{
    int ret;
    struct meta_session *ms = kzalloc(sizeof(*ms), GFP_NOFS);
    if (ms == NULL) {
        return ERR_PTR(-ENOMEM);
    }
    __init_session(ms);
    ms->in_addr = *addr;
    
    ret = cfs_messager_open(&ms->msger, proto, ms->in_addr);
    if (ret != 0) {
        return ERR_PTR(ret);
    }

    wait_for_completion(&ms->comp);

    if (ms->state != CFS_STATE_WORKING) {
        eprintk("open messager connect failed.\n");
        cfs_messager_close(&ms->msger);
        kfree(ms);
        return ERR_PTR(-EIO);
    }
    
    return ms;
}

/* release session memory */
int mc_release_session(struct meta_session *ms)
{
    cfs_messager_close(&ms->msger);
    kfree(ms);
}

int mc_get_session(void *private)
{
    struct meta_session *ms = (struct meta_session *)private;
    kref_get(&ms->ref);
}

void mc_put_session(void *private)
{
    struct meta_session *ms = (struct meta_session *)private;
    kref_put(&ms->ref, mc_release_session);
}

void mc_handle_conn(void *private, int err)
{
    struct meta_session *ms = (struct meta_session *)private;

    if (err != 0) {
        CFS_STATE_SET(ms->mutex, ms->state, CFS_STATE_ERROR);
    } else {
        CFS_STATE_SET(ms->mutex, ms->state, CFS_STATE_WORKING);
    }
    complete_all(&ms->comp);
}

void mc_handle_msg(void *private, struct cfs_msg *msg)
{

}

void mc_handle_err(void *private, struct cfs_msg *msg)
{
    if (NULL == msg) {
    
    }
}


static const struct cfs_messager_operations cfs_meta_ops = {
	.get = mc_get_session,
	.put = mc_put_session,
	.handle_conn = mc_handle_conn,
    .handle_err = mc_handle_err,
	.handle_msg = mc_handle_msg,
};

static int __get_metanode_leader(struct meta_client *mc)
{
    int ret = 0;
    if (mc->volmgr_session == NULL || mc->volmgr_session != CFS_STATE_WORKING) {
        eprintk("volmgr leader invalid!\n");
        return -1;
    }
    
    struct meta_request *req = meta_client_alloc_req(mc, OP_GET_METANODE_RG);
    if (req == NULL) {
        eprintk("alloc req failed!\n");
        return -1;
    }
    req->ms = mc->volmgr_leader;

    struct get_metanode_rg_req *r = (struct get_metanode_rg_req *)req->msg->front;
    strncpy(r->volid, mc->volid, CFS_UUID_LEN);
    r->volid[CFS_UUID_LEN] = '\0';
    
    meta_client_get_req(req);
    ret = meta_client_do_req(mc, req);
    if (ret != 0 || req->ack == NULL) {
        eprintk("do req failed!\n");
        goto out;
    }
    struct get_metanode_rg_ack *ack = (struct get_metanode_rg_ack *)req->ack->front;
    if (ack->ret != 0) {
        eprintk("ack ret: %d!\n", (int)ack->ret);
        goto out;
    }
    mc->copies = ack->copies;
    
    struct sockaddr_storage leader_addr;
    int count = 0;
    char *leader = ack->metanodes[ack->leader].host;
    int len = strlen(leader);
    ret = cfs_parse_hosts(leader, leader+len, &leader_addr, 1, &count);
    if (ret != 0 || count != 1) {
        eprintk("parse host %s failed ret: %d, count: %d\n", leader, ret, count);
        goto out;
    }
    cfs_set_addr_port(&leader_addr, CFS_MSG_PROTOCOL_METANODE_PORT)
    
    struct meta_session *ms = mc_open_session(&leader_addr, CFS_MSG_PROTOCOL_METANODE);
    if (IS_ERR_OR_NULL(ms)) {
        eprintk("connect to host %s failed, err: %ld\n", leader, PTR_ERR(ms));
        goto out;
    }
    mc_get_session((void *)ms);
    memcpy(&mc->metanode_infos, &ack->metanodes, sizeof(mc->metanode_infos));
    mc->metanode_session = ms;

    meta_client_put_req(req);
    return 0;
    
out:
    meta_client_put_req(req);
    return ret;
}

static int __get_volmgr_leader(struct meta_client *mc)
{
    int i, ret;
    struct meta_session *ms;
    struct meta_request *req;
    struct get_volmgr_rg_ack *ack;
    
    for (i = 0; i < CFS_RG_COUNT; i++) {
        req = NULL;
        ms = mc_open_session(&mc->volmgr_infos[i].addr, CFS_MSG_PROTOCOL_VOLMGR);
        if (IS_ERR_OR_NULL(ms)) {
            eprintk("%s: connect failed!\n", mc->volmgr_infos[i].host);
            goto next_session;
        }
        mc_get_session((void *)ms);
        
        req = meta_client_alloc_req(mc, OP_GET_VOLMGR_RG);
        if (req == NULL) {
            eprintk("%s: alloc req failed!\n", mc->volmgr_infos[i].host);
            goto next_session;
        }
        req->ms = ms;
        meta_client_get_req(req);
        
        ret = meta_client_do_req(mc, req);
        if (ret != 0 || req->ack == NULL) {
            eprintk("%s: do req failed!\n", mc->volmgr_infos[i].host);
            goto next_session;
        }
        ack = (struct get_volmgr_rg_ack *)req->ack->front;
        if (ack->ret != 0) {
            eprintk("%s: ack ret: %d!\n", mc->volmgr_infos[i].host, (int)ack->ret);
            goto next_session;
        }
        
        break;
        
    next_session:
        if (req)
            meta_client_put_req(req);
        if (ms)
            mc_put_session((void *)ms);
    }

    if (CFS_RG_COUNT == i) {
        return -1;
    }
    int curr_idx = i;

    /* get leader addr from ack */
    ack = (struct get_volmgr_rg_ack *)req->ack->front;
    char *leader = ack->peers[ack->leader];

    for (i = 0; i < CFS_RG_COUNT; i++) {
        int len = strlen(mc->volmgr_infos[i].host);
        if (!strncmp(ack->peers[ack->leader], mc->volmgr_infos[i].host, len)) {
            break;
        }
    }
    if (CFS_RG_COUNT == i) {
        eprintk("can't found leader: %s in hosts!\n", ack->peers[ack->leader]);
        goto out;
    }

    if (i != curr_idx) {
        mc_put_session((void *)ms);
        ms = mc_open_session(mc->volmgr_infos[i].addr, CFS_MSG_PROTOCOL_VOLMGR);
        if (IS_ERR_OR_NULL(ms)) {
            eprintk("%s: connect failed!\n", mc->volmgr_infos[i].host);
            ms = NULL;
            goto out;
        }
        mc_get_session((void *)ms);
    }
    
    dprintk("get volmgr leader: %d _ %u %s success.\n", i, ack->leader, ack->peers[ack->leader]);
    mc->volmgr_session = ms;/* make sure to keep ref of session */
    meta_client_put_req(req);
    return 0;

out:
    if (req)
        meta_client_put_req(req);
    if (ms)
        mc_put_session(ms);
    return -1;
}

void meta_client_exit(struct meta_client *mc)
{
    kfree(mc);
}

struct meta_client *meta_client_init(char *volmgr_hosts, char *volid)
{
    struct meta_client *mc = kzalloc(sizeof(*mc), GFP_NOFS);
    if (!mc) {
        return ERR_PTR(-ENOMEM);
    }
    mutex_init(&mc->mutex);
    strncpy(mc->volid, volid, CFS_UUID_LEN);
    mc->volid[CFS_UUID_LEN] = '\0';
    mc->req_tree = RB_ROOT;
    mc->state = CFS_STATE_OPENING;

    int i = 0, j = 0, ret = 0;
    char *p = volmgr_hosts;
    for (; *p != '\0'; p++) {
        if (*p == ',') {
            mc->volmgr_infos[i++].host[j] = '\0';
            continue;
        } else if (*p == ' ') {
            continue;
        }

        if (i == CFS_RG_COUNT || j == CFS_IP4_LEN_MAX) {
            ret = -EINVAL;
            goto out;
        }
        
        mc->volmgr_infos[i].host[j++] = *p;
    }
    
    for (i = 0; i < CFS_RG_COUNT; i++) {
        int count = 0;
        int len = strlen(mc->volmgr_infos[i].host);
        cfs_parse_hosts(mc->volmgr_infos[i].host, mc->volmgr_infos[i].host+len, &mc->volmgr_infos[i].addr, 1, &count);
        if (ret != 0 || count != 1) {
            ret = -EINVAL;
            goto out;
        }
        cfs_set_addr_port(&mc->volmgr_infos[i].addr, CFS_MSG_PROTOCOL_VOLMGR_PORT);
    }

    if (__get_volmgr_leader(mc) != 0) {
        ret = -EIO;
        goto out;
    }

    if (__get_metanode_leader(mc) != 0) {
        ret = -EIO;
        goto out;
    }

    mc->state = CFS_STATE_WORKING;
    return mc;
    
out:
    meta_client_exit(mc);
    return ERR_PTR(ret);
}


