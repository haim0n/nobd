#include <linux/version.h>
#include <asm/types.h>
#include <linux/socket.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/netlink.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/moduleparam.h>

#include <net/sock.h>

#include "include/nobd_nl.h"


#undef pr_fmt
#define pr_fmt(fmt) "nobd_nl: " fmt

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
#define SHUT_RDWR 2
#ifndef CONFIG_ARPD
	#error "CONFIG_ARPD not configured"
#endif /* CONFIG_ARPD */
#endif /* KERNEL_VERSION(2.6.24) */

#define RTMGRP_NEIGH	4
#define RTMGRP_IPV4_ROUTE	0x40
//#endif /* CONFIG_ARPD */

#define nobd_GRP (RTMGRP_IPV4_ROUTE | RTMGRP_NEIGH | RTNLGRP_LINK | RTNLGRP_NEIGH)
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))

static int no_arp = 0;
module_param(no_arp, int, 0644);
MODULE_PARM_DESC(no_arp, "avoid reporting arp events");


struct msgnames_t {
	int id;
	char *msg;
} typenames[] = {
#define MSG(x) { x, #x }
	MSG(RTM_NEWROUTE),
	MSG(RTM_DELROUTE),
	MSG(RTM_GETROUTE),
	MSG(RTM_NEWNEIGH),
	MSG(RTM_DELNEIGH),
	MSG(RTM_NEWLINK),
	MSG(RTM_DELLINK),
#undef MSG
	{0,0}
};

static struct socket *nobd_socket;

static char *nobd_nl_lookup_name(struct msgnames_t *db,int id)
{
	static char name[512];
	struct msgnames_t *msgnamesiter;
	for (msgnamesiter=db;msgnamesiter->msg;++msgnamesiter) {
		if (msgnamesiter->id == id)
			break;
	}
	if (msgnamesiter->msg) {
		return msgnamesiter->msg;
	}
	snprintf(name,sizeof(name),"#%i",id);
	return name;
}

#ifndef NIPQUAD
	#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#if 0
static void
netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}
#endif

static int nobd_nl_ev_route(struct nlmsghdr *nlh, void *buffer)
{
	struct rtmsg *rtm;
	struct rtattr *rta;
	int rtl;
	rtm = (struct rtmsg *)buffer;
	rta = (struct rtattr*)RTM_RTA(rtm);
	rtl = RTM_PAYLOAD(nlh);
	printk("%s: family: %u\n", __func__, rtm->rtm_family);
	/* parse each attr */
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		if (rta->rta_type == RTA_DST) {
			uint32_t dst_addr = *((uint32_t *)RTA_DATA(rta));
			printk("dst " NIPQUAD_FMT "/%u\n", NIPQUAD(dst_addr),
			       rtm->rtm_dst_len);
		}
		if (rta->rta_type == RTA_GATEWAY) {
			uint32_t dst_gw = *((uint32_t *)RTA_DATA(rta));
			printk("gw " NIPQUAD_FMT "\n", NIPQUAD(dst_gw));
		}
		if (rta->rta_type == RTA_OIF) {
			uint32_t oif = *((uint32_t *)RTA_DATA(rta));
			printk("oif_index %u\n", oif);
		}
	}
	if (nlh->nlmsg_type == RTM_NEWROUTE) {
		printk("new route\n");
		/* dpa_rt_rule_add */
	} else {
		/* dpa_rt_rule_del */
		printk("del route\n");
	}

	return 0;
}

/* we handle only bridge if bind/unbind here,
   the rest is done in notification chains */
static int nobd_nl_ev_link(struct nlmsghdr *nlh, void *buffer)
{
	struct ifinfomsg *ifi;
	struct rtattr *rta;
//      struct interface *ifp;
	int rtl;
	int new_if = (nlh->nlmsg_type == RTM_NEWLINK);

	ifi = (struct ifinfomsg *)buffer;
	rta = (struct rtattr*)IFLA_RTA(ifi);
	rtl = IFLA_PAYLOAD(nlh);

	pr_debug("%s: ifi_family: %u\n", __func__, ifi->ifi_family);
	if (ifi->ifi_family != AF_BRIDGE)
		return 0;

	if (new_if) {
		printk("bridge if bind\n");
	} else 
		printk("bridge if unbind\n");
	
	/* parse each attr */
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		if (rta->rta_type == IFLA_IFNAME) {
			printk("name: %s, flags %#x, type %#x\n",(char *)RTA_DATA(rta), 
			       ifi->ifi_flags,
			       ifi->ifi_type);
		}
	}
	printk("\n");
	if (new_if) {
		/* add */
	} else {
		/* del */
	}
	return 0;
}

static int nobd_nl_ev_arp(struct nlmsghdr *nlh, void *buffer)
{
	struct ndmsg *ndm;
	struct rtattr *rta;
	int rtl;
	int new_neigh = 0;

	ndm = (struct ndmsg *)buffer;
	rta = (struct rtattr*)RTM_RTA(ndm);
	rtl = RTM_PAYLOAD(nlh);
	printk("%s: family: %u\n", __func__, ndm->ndm_family);
	/* parse each attr */
	for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
		if (rta->rta_type == NDA_DST) {
			uint32_t dst_addr = *((uint32_t *)RTA_DATA(rta));
			printk("ip " NIPQUAD_FMT "\n", NIPQUAD(dst_addr));
			continue;
		}
		if (rta->rta_type == NDA_LLADDR) {
			#define MAX_BUF_LEN 6
			uint8_t ha[MAX_BUF_LEN];
			uint8_t *data = (uint8_t *)RTA_DATA(rta);
			uint32_t data_len =
				rta->rta_len < MAX_BUF_LEN ? rta->rta_len : MAX_BUF_LEN;
			uint32_t i;

			new_neigh = 1; /* NDA_LLADDR appears only in new entry */
			memcpy(ha, data, data_len);
			for (i = 0; i < data_len; i++) {
				printk("%x:", ha[i]);
			}
			printk("\n");
			continue;
		}
	}
	if (new_neigh) {
		printk("new arp entry\n");
		/* dpa_arp_rule_add */
	} else {
		/* dpa_arp_rule_del */
		printk("del arp entry\n");
	}
	return 0;
}

static void nobd_nl_dump_skb(struct sk_buff *skb) 
{
#ifdef DEBUG
	char tmp[80];
	char *p = skb->data;
	char *t = tmp;
	int i;
	for (i = 0; i < skb->len; i++) {
		t += sprintf(t, "%02x ", *p++ & 0xff);
		if ((i & 0x0f) == 8) {
			printk(KERN_DEBUG "dump: %s\n", tmp);
			t = tmp;
		}
	}
	if (i & 0x07)
		printk(KERN_DEBUG "dump: %s\n", tmp);
#endif
}

/* Receive message from netlink and pass information to relevant function. */
static void nobd_nl_data_ready(struct sock *sk, int bytes)
{
	int status = 0;
	int ret = 0;
	int len;
	void *buf;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	
	pr_debug("%s: got a message %u bytes\n", __func__, bytes);
	while ((skb = skb_recv_datagram(sk, 0, 1, &ret)) == NULL) {
		if (ret == -EAGAIN) {
			printk(KERN_ERR "no data available\n");
			return;
		}
		pr_debug("recvfrom() error %d\n", -ret);
	}

	len = skb->len;
	nobd_nl_dump_skb(skb);
	for (nlh = (struct nlmsghdr *)skb->data; NLMSG_OK(nlh, len);
	    nlh = NLMSG_NEXT(nlh, status)) {
		pr_debug("%s: nlmsg_len %u, nlmsg_type %u\n", __func__,
		       nlh->nlmsg_len, nlh->nlmsg_type);
		/* Finish of reading. */
		if (nlh->nlmsg_type == NLMSG_DONE)
			return;

		/* Error handling. */
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			printk(KERN_ERR "nl message error\n");
			return;
		}
		if (no_arp &&
		    nlh->nlmsg_type != RTM_NEWNEIGH &&
		    nlh->nlmsg_type != RTM_DELNEIGH) {
			pr_debug("nlmsg_type: %i (%s)\n",(nlh->nlmsg_type), 
			       nobd_nl_lookup_name(typenames,nlh->nlmsg_type));
		}
		/* OK we got netlink message. */
		buf = NLMSG_DATA(skb->data);
		switch (nlh->nlmsg_type) {
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			ret = nobd_nl_ev_route(nlh, buf);
			break;
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			if (!no_arp)
				ret = nobd_nl_ev_arp(nlh, buf);
			break;
		case RTM_NEWLINK:
		case RTM_DELLINK:
			ret = nobd_nl_ev_link(nlh, buf);
			break;
		}
	}
	skb_orphan(skb);
	kfree_skb(skb);

	return;
}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
extern struct neigh_table arp_tbl;
void nobd_init_arp_neigh_tbl(struct neigh_table *tbl)
{
	struct neighbour *n;
	u32 hash_val;
	
	read_lock_bh(&tbl->lock);
	hash_val = atomic_read(&tbl->entries);
	while (hash_val--) {
		for (n = tbl->hash_buckets[hash_val & tbl->hash_mask]; n; 
		      n = n->next) {
			neigh_hold(n);
			n->parms->app_probes = 1;
			neigh_release(n);
		}
	}
	read_unlock_bh(&tbl->lock);
}
#endif /* KERNEL_VERSION(2,6,24) */

int nobd_nl_open(void)
{
	struct sock *sock;
	struct sockaddr_nl addr;
	int rc = sock_create_kern(AF_NETLINK,SOCK_RAW, NETLINK_ROUTE, &nobd_socket);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	nobd_init_arp_neigh_tbl(&arp_tbl);
#endif
	if (rc < 0) {
		printk(KERN_ERR "socket_create err %d\n", rc);
		return rc;
	}

	memset((void *)&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = nobd_GRP;
	rc = kernel_bind(nobd_socket, (struct sockaddr *)&addr, sizeof(addr));
	if (rc <0) {
		printk(KERN_ERR "bind err\n");
		return rc;
	}

	/* set the socket up */
	sock = nobd_socket->sk;
	sock->sk_data_ready = nobd_nl_data_ready;
	sock->sk_allocation = GFP_ATOMIC;
	return 0;
}

void nobd_nl_close(void)
{
	nobd_socket->ops->shutdown(nobd_socket, SHUT_RDWR);
	sock_release(nobd_socket);
}
