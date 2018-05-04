/*
 * cfs_pub.h - CFS Public definition
 */

#ifndef CFS_PUB_H
#define CFS_PUB_H

#define CFS_UUID_LEN        (32)
#define CFS_IP4_LEN_MAX     (16) /*255.255.255.255*/
#define CFS_IP4PORT_LEN_MAX (22) /*255.255.255.255:65536*/
#define CFS_FILENAME_MAX    (255)
#define CFS_BLOCKGROUP_MAX  (3)
#define CFS_RG_COUNT        (3)

#define CFS_REQUEST   (0)
#define CFS_RESPONSE  (1)


#define dprintk(fmt, ...)             \
    do {                                \
        pr_debug("CFS: %s: " fmt, __func__, ##__VA_ARGS__);  \
    } while (0)

#define iprintk(fmt, ...)             \
    do {                                \
        pr_err("CFS: %s: " fmt, __func__, ##__VA_ARGS__);  \
    } while (0)

#define eprintk(fmt, ...)             \
    do {                                \
        pr_err("CFS: %s: " fmt, __func__, ##__VA_ARGS__);  \
    } while (0)


#define CFS_STATE_CLOSED  (0)
#define CFS_STATE_OPENING (1)
#define CFS_STATE_WORKING (2)
#define CFS_STATE_CLOSING (3)
#define CFS_STATE_ERROR   (4)

#define CFS_STATE_SET(mutex, state, value) \
do {\
    mutex_lock(&mutex); \
    state = value; \
    mutex_unlock(&mutex); \
} while(0)

extern void *cfs_malloc(size_t size, gfp_t flags);

extern char *cfs_ntop(const struct sockaddr_storage *paddr, char *buf, const size_t buflen);

extern int cfs_pton(const char *str, size_t len, struct sockaddr_storage *ss, char delim, const char **ipend);

extern void cfs_set_addr_port(struct sockaddr_storage *ss, int port);

extern int cfs_get_addr_port(struct sockaddr_storage *ss);

extern int cfs_parse_hosts(const char *begin, const char *end, struct sockaddr_storage *in_addr, int max, int *count);

#endif

