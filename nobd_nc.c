/*
 *	Kernel Learning Agent
 *
 *      Authors:
 *	Haim Daniel
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <asm/cacheflush.h>
#include <net/netevent.h>
#include <net/neighbour.h>
#include <net/sock.h>
#include <vlan.h>
#include <br_private.h>
#include <linux/if_arp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <linux/version.h>

#include "include/nobd_pppoe_sock.h"
#include "include/nobd_br.h"

#undef pr_fmt
#define pr_fmt(fmt) "nobd_nc: " fmt

static int no_ct;
module_param(no_ct, int, 0644);
MODULE_PARM_DESC(no_ct, "avoid reporting conntrack events");

DEFINE_SPINLOCK(nobd_lock);
#ifdef CONFIG_NF_CONNTRACK_EVENTS

static void (*death_by_timeout_org)(unsigned long);
static atomic_t en_reg_timeout_death = ATOMIC_INIT(1);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,26)
static inline u_int16_t nf_ct_l3num(const struct nf_conn *ct)
{
	return ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
}
static inline u_int8_t nf_ct_protonum(const struct nf_conn *ct)
{
	return ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
}
#endif /* KERNEL_VERSION 2.6.26 */

#ifndef NIPQUAD
	#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

static void nobd_print_conntrack_tuple(struct nf_conn *ct)
{
	const struct nf_conntrack_l3proto *l3proto;
	const struct nf_conntrack_l4proto *l4proto;

	struct nf_conntrack_tuple *tuple = 
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

	l3proto = __nf_ct_l3proto_find(nf_ct_l3num(ct));
	NF_CT_ASSERT(l3proto);
	l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
	NF_CT_ASSERT(l4proto);

	pr_info("[%s]" NIPQUAD_FMT ":%u -> " NIPQUAD_FMT ":%u\n",
		l4proto->name,
		NIPQUAD(tuple->src.u3.ip), ntohs(tuple->src.u.all),
		NIPQUAD(tuple->dst.u3.ip), ntohs(tuple->dst.u.all));
}

/* overrides ct->timeout->function() */
void nobd_death_by_timeout(unsigned long ul_conntrack)
{
	struct nf_conn *ct = (void *)ul_conntrack;

	pr_info("nobd_death_by_timeout:\n");
	nobd_print_conntrack_tuple(ct);
//	mod_timer(&ct->timeout, jiffies + 400 * HZ);
	death_by_timeout_org(ul_conntrack); /* hook the original timeout */
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static void unregister_death_by_timeout(void)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct hlist_nulls_node *n;
	unsigned int bucket = 0;
	struct net *net = &init_net;

	spin_lock_bh(&nf_conntrack_lock);
	/* Go over all tuples in the Linux database */
	for (; bucket < net->ct.htable_size; bucket++) {
		hlist_nulls_for_each_entry(h, n, &net->ct.hash[bucket], hnnode) {
			ct = nf_ct_tuplehash_to_ctrack(h);
			if (death_by_timeout_org)
				ct->timeout.function = death_by_timeout_org;
		}
	}
	spin_unlock_bh(&nf_conntrack_lock);
}
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) */
static void unregister_death_by_timeout(void)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	unsigned int bucket = 0;

	spin_lock_bh(&nf_conntrack_lock);
	/* Go over all tuples in the Linux database */
	for (; bucket < nf_conntrack_htable_size; bucket++) {
		list_for_each_entry(h, &nf_conntrack_hash[bucket], list) {
			ct = nf_ct_tuplehash_to_ctrack(h);
			ct->timeout.function = death_by_timeout_org;
		}
	}
	spin_unlock_bh(&nf_conntrack_lock);
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
static int nobd_nc_ct_event(struct notifier_block *this,
				     unsigned long events, void *item)
{
	struct nf_conn *ct = (struct nf_conn *)item;
#else
static int nobd_nc_ct_event(unsigned int events, struct nf_ct_event *item)
{
	struct nf_conn *ct = item->ct;
#endif /* LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31) */

	struct nf_conn_help *help = nfct_help(ct);
	/* ignore fake conntrack entry */
	if (ct == &nf_conntrack_untracked)
		return 0;

	if (!death_by_timeout_org)
		death_by_timeout_org = ct->timeout.function;

	if (atomic_read(&en_reg_timeout_death))
		ct->timeout.function = &nobd_death_by_timeout;

	if (events & IPCT_DESTROY) {
		pr_info("destroyed ct\n");
	} else  if (events & IPCT_NEW) {
		pr_info("new ct\n");
		if (help && help->helper) {
			struct nf_conntrack_helper *hlp = help->helper;
			struct nf_conntrack_tuple *tup =
				&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

			pr_info("new helper ct\n");
			pr_info("(%s:%d): helper name: %s, proto %u, "
				"port %u\n", __func__, __LINE__,
			       hlp->name, tup->dst.protonum, 
				ntohs(tup->dst.u.all));
		}
	} else if (events & IPCT_RELATED) {
		pr_info("related ct\n");
	} else if (events & IPCT_HELPER) {
		if (help && help->helper) {
			struct nf_conntrack_helper *hlp = help->helper;
			struct nf_conntrack_tuple *tup =
				&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;

			pr_info("new helper ct\n");
			pr_info("(%s:%d): helper name: %s, proto %u, dst_port %u\n", __func__, __LINE__,
			       hlp->name, tup->dst.protonum, ntohs(tup->dst.u.all));
		} else {
			pr_debug("new ct\n");
		}

	} else 
		return 0;

	nobd_print_conntrack_tuple(ct);
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31)
static struct notifier_block nobd_ct_notifier = {
	.notifier_call	= nobd_nc_ct_event,
};
#else
static struct nf_ct_event_notifier nobd_ct_notifier = {
	.fcn = nobd_nc_ct_event
};
#endif /* LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,31) */

#endif /* CONFIG_NF_CONNTRACK_EVENTS */

static int nobd_nc_br_if_event(struct notifier_block *unused, unsigned long event, 
			      void *ptr)
{
	struct net_device *dev = ptr;
	struct net_bridge *br = dev->br_port->br;

	switch (event) {

	case NETDEV_REGISTER:
		pr_info("if %s up at br [%s]\n", dev->name, br->dev->name);
		break;

	case NETDEV_UNREGISTER:
		pr_info("if %s down at br [%s]\n", dev->name, br->dev->name);
		break;
	}
	return NOTIFY_DONE;
}

static int nobd_nc_br_dev_event(struct notifier_block *unused, unsigned long event, 
			      void *ptr)
{
	struct net_device *dev = ptr;
	struct net_bridge *br = netdev_priv(dev);
	int ret = NOTIFY_DONE;

	switch (event) {

	case NETDEV_REGISTER:
		pr_info("br up [%s]\n", dev->name);
		if (nobd_br_reg(br))
			ret = NOTIFY_BAD;
		break;

	case NETDEV_UNREGISTER:
		pr_info("br unreg [%s]\n", dev->name);
		nobd_br_unreg(br);
		break;
	}

	return ret;
}

static int 
nobd_nc_eth_dev_event(struct notifier_block *unused, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = ptr;

	pr_info("(%s:%d) eth dev %s event %lu\n", __func__, __LINE__,
	       dev->name, event);
	switch (event) {
	case NETDEV_REGISTER:
		pr_info("eth dev register %s\n", dev->name);
		break;
	case NETDEV_UNREGISTER:
		pr_info("eth dev unregister %s\n", dev->name);
		break;
	case NETDEV_UP:
		pr_info("eth dev %s up\n", dev->name);
	case NETDEV_DOWN:
		pr_info("eth dev %s down\n", dev->name);
	case NETDEV_CHANGE:
		pr_info("eth dev %s change\n", dev->name);

	}

	return NOTIFY_DONE;
}

static int 
nobd_nc_pppox_dev_event(struct notifier_block *unused, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = ptr;

	pr_info("(%s:%d) pppox dev %s event %lu\n", __func__, __LINE__,
	       dev->name, event);

	switch (event) {
	case NETDEV_REGISTER:
		pr_info("dev register %s\n", dev->name);
		break;
	case NETDEV_UNREGISTER:
		pr_info("dev unregister %s\n", dev->name);
		break;
	case NETDEV_UP:
		pr_info("dev %s up\n", dev->name);
		find_dev_pppoe_socks(dev);
		break;
	case NETDEV_DOWN:
		pr_info("dev %s down\n", dev->name);
		find_dev_pppoe_socks(dev);
		break;
	case NETDEV_GOING_DOWN:
		pr_info("dev %s going down\n", dev->name);
		find_dev_pppoe_socks(dev);
		break;
	}

	return NOTIFY_DONE;
}

static int 
nobd_nc_vlan_dev_event(struct notifier_block *unused, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = ptr;
	struct vlan_dev_info *dev_info = (struct vlan_dev_info *)netdev_priv(dev);

	switch (event) {
	case NETDEV_REGISTER:
		pr_info("vlan register %s vid %u\n", dev->name, dev_info->vlan_id);
		break;
	case NETDEV_UNREGISTER:
		pr_info("vlan unreg %s vid %u\n", dev->name, dev_info->vlan_id);
		break;
	case NETDEV_UP:
		pr_info("vlan %s up vid %u\n", dev->name, dev_info->vlan_id);
		break;
	case NETDEV_DOWN:
		pr_info("vlan %s down vid %u\n", dev->name, dev_info->vlan_id);
		break;
	}

	return NOTIFY_DONE;
}

/* main dispatcher for netdev events */
static int nobd_nc_netdev_event(struct notifier_block *unused, unsigned long event,
			   void *ptr)
{
	struct net_device *dev = ptr;
	
//      pr_debug("dpa_netdev_dev %s event %lu, dev_type: %#x, flags #%x\n",dev->name, event,
//      	dev->type, dev->priv_flags);

	if (dev->priv_flags & IFF_802_1Q_VLAN) {
		return nobd_nc_vlan_dev_event(unused, event, ptr);
	}
	if (dev->priv_flags & IFF_EBRIDGE) {
		return nobd_nc_br_dev_event(unused, event, ptr);
	} else if (dev->br_port) {
		return nobd_nc_br_if_event(unused, event, ptr);
	}
	if (dev->type == ARPHRD_ETHER) {
		return nobd_nc_eth_dev_event(unused, event, ptr);
	}
	if (dev->type == ARPHRD_PPP) {
		return nobd_nc_pppox_dev_event(unused, event, ptr);
	}

	return NOTIFY_DONE;
}

static struct notifier_block nobd_netdev_notifier __read_mostly = {
	.notifier_call = nobd_nc_netdev_event,
};

int nobd_nc_init(void)
{
	int err = 0;

	pr_info("init\n");
	err = nobd_br_fdb_init();
	if (err)
		goto exit;

	err = register_netdevice_notifier(&nobd_netdev_notifier);
	if (err) {
		unregister_netdevice_notifier(&nobd_netdev_notifier);
	}
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	if (!no_ct) {
		pr_info("reg nf_conntrack\n");
		err = nf_conntrack_register_notifier(&nobd_ct_notifier);
		if (err) {
			nf_conntrack_unregister_notifier(&nobd_ct_notifier);
		}
	}
#else
	#warning "CONFIG_NF_CONNTRACK_EVENTS undefined!"
#endif
exit :
	return err;
}

void nobd_nc_exit(void)
{
	pr_info("exit\n");
	unregister_netdevice_notifier(&nobd_netdev_notifier);
#ifdef CONFIG_NF_CONNTRACK_EVENTS
	if (!no_ct) {
		pr_info("unreg nf_ct\n");
		atomic_set(&en_reg_timeout_death, 0);
		nf_conntrack_unregister_notifier(&nobd_ct_notifier);
		unregister_death_by_timeout();
	}
#endif
	nobd_br_fdb_exit();
}
