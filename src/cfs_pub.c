#include "cfs_pub.h"

void *cfs_malloc(size_t size, gfp_t flags)
{
    void *ptr = NULL;
	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		ptr = kmalloc(size, flags | __GFP_NOWARN);
	}
    /* kmalloc may failed */
    if (NULL == ptr) {
    	ptr = __vmalloc(size, flags | __GFP_HIGHMEM, PAGE_KERNEL);
    }
    return ptr;
}
EXPORT_SYMBOL(cfs_malloc);

char *cfs_ntop(const struct sockaddr_storage *paddr, char *buf, const size_t buflen)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *)paddr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)paddr;
    
	switch (paddr->ss_family) {
	case AF_INET:
		snprintf(buf, buflen, "%pI4:%hu", &in4->sin_addr, ntohs(in4->sin_port));
		break;

	case AF_INET6:
		snprintf(buf, buflen, "[%pI6c]:%hu", &in6->sin6_addr, ntohs(in6->sin6_port));
		break;

	default:
		snprintf(buf, buflen, "(unknown sockaddr family %hu)", ss->ss_family);
	}

	return buf;
}
EXPORT_SYMBOL(cfs_ntop);

int cfs_pton(const char *str, size_t len, struct sockaddr_storage *ss, char delim, const char **ipend)
{
	struct sockaddr_in *in4 = (struct sockaddr_in *) ss;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) ss;

	memset(ss, 0, sizeof(*ss));

	if (in4_pton(str, len, (u8 *)&in4->sin_addr.s_addr, delim, ipend)) {
		ss->ss_family = AF_INET;
		return 0;
	}

	if (in6_pton(str, len, (u8 *)&in6->sin6_addr.s6_addr, delim, ipend)) {
		ss->ss_family = AF_INET6;
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(cfs_pton);

void cfs_set_addr_port(struct sockaddr_storage *ss, int port)
{
	switch (ss->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)ss)->sin_port = htons(port);
		break;
	case AF_INET6:
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
		break;
	}
}
EXPORT_SYMBOL(cfs_set_addr_port);

int cfs_get_addr_port(struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)ss)->sin_port)
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)ss)->sin6_port)
	}
}
EXPORT_SYMBOL(cfs_get_addr_port);


/*
 * Parse an ip[:port] list into an addr array: ip1[:port1][,ip2[:port2]...]
 */
int cfs_parse_hosts(const char *begin, const char *end, struct sockaddr_storage *in_addr, int max, int *count)
{
	int i, ret = -EINVAL;
	const char *p = begin;
    struct sockaddr_storage *ss = in_addr;
    char addr_buf[MAX_ADDRSTR_LEN];

	dprintk("parse hosts: '%.*s'\n", (int)(end-begin), begin);
    
	for (i = 0; i < max; i++) {
		const char *ipend;
		int port = 0;
		char delim = ',';

        /* ipv6 */
		if (*p == '[') {
			delim = ']';
			p++;
		}

		ret = cfs_pton(p, end - p, ss, delim, &ipend);
		if (ret)
			goto out;
		ret = -EINVAL;

		p = ipend;

        /* ipv6 */
		if (delim == ']') {
			if (*p != ']') {
				dprintk("missing matching ']'\n");
				goto out;
			}
			p++;
		}

		/* port? */
		if (p < end && *p == ':') {
			p++;
			while (p < end && *p >= '0' && *p <= '9') {
				port = (port * 10) + (*p - '0');
				p++;
			}
			if (port > 65535)
				goto out;
		}
        if (port != 0) 
		    cfs_set_addr_port(ss, port);

		dprintk("parse hosts got %s\n", cfs_ntop(ss, addr_buf, sizeof(addr_buf)));

		if (p == end)
			break;
        
		if (*p != ',')
			goto out;
        
		p++;
	}

	if (p != end)
		goto out;

	if (count)
		*count = i + 1;
	return 0;

out:
	eprintk("parse hosts invalid hosts: '%.*s'\n", (int)(end - begin), begin);
	return ret;
}
EXPORT_SYMBOL(cfs_parse_hosts);



