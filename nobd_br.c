#include <linux/list.h>
#include <linux/timer.h>
#include <br_private.h>
#include "include/nobd_br.h"

#undef pr_fmt
#define pr_fmt(fmt) "nobd_br: " fmt

/* sample rate of Linux br */
#define nobd_FDB_TO (5 *HZ)

DEFINE_SPINLOCK(nobd_fdb_lock);

static struct timer_list nobd_fdb_timer;
static struct list_head nobd_br_list = LIST_HEAD_INIT(nobd_br_list);
struct br_element {
	struct list_head list;
	struct net_bridge *br;
};

#define MAC_ADDR(mac) \
	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
#ifndef MAC_FMT
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

/* taken from br_fbd.c br_fdb_fillbuf() */
static int nobd_br_fdb_read(struct net_bridge *br)
{
	unsigned int i;
	struct hlist_node *h;
	struct net_bridge_fdb_entry *f;

	pr_info("%s\n", __func__);
	rcu_read_lock();
	for (i = 0; i < BR_HASH_SIZE; i++) {
		hlist_for_each_entry_rcu(f, h, &br->hash[i], hlist) {
/*      		if (has_expired(br, f))
				continue;

			if (!f->is_static)
				fe->ageing_timer_value = jiffies_to_clock_t(jiffies - f->ageing_timer);
*/
			pr_info("br %s fdb[%u]: " MAC_FMT ", port:%s, local:%u, "
				"static:%u, timeout:%lu\n",
			       br->dev->name, i, MAC_ADDR(f->addr.addr), f->dst->dev->name,
			       f->is_local, f->is_static,
			       f->is_static ? 0 : 
				(jiffies_to_clock_t(jiffies - f->ageing_timer)));
		}
	}
	rcu_read_unlock();

	return i;
}

int nobd_br_reg(struct net_bridge *br)
{
	struct list_head *p;
	struct br_element *el = NULL;
	int ret = 0;

	pr_info("%s br %s\n", __func__,br->dev->name);
	del_timer(&nobd_fdb_timer);
	spin_lock_bh(&nobd_fdb_lock);
	list_for_each(p, &nobd_br_list) {
		el = list_entry(p, struct br_element, list);
		if (el->br == br)
			goto out;
	}
	el = kmalloc(sizeof(struct br_element), GFP_ATOMIC);
	if (!el) {
		pr_err("insufficient mm for br_element\n");
		ret = -ENOMEM;
		goto out;
	}
	el->br = br;
	INIT_LIST_HEAD(&el->list);
	list_add_tail(&el->list, &nobd_br_list);
out:
	spin_unlock_bh(&nobd_fdb_lock);
	if (!list_empty(&nobd_br_list))
		mod_timer(&nobd_fdb_timer, jiffies + HZ);

	return ret;
}

int nobd_br_unreg(struct net_bridge *br)
{
	struct list_head *p, *tmp;
	struct br_element *el = NULL;

	pr_info("%s br %s\n", __func__,br->dev->name);
	del_timer(&nobd_fdb_timer);
	spin_lock_bh(&nobd_fdb_lock);
	list_for_each_safe(p, tmp, &nobd_br_list) {
		el = list_entry(p, struct br_element, list);
		if (el->br == br) {
			list_del(p);
			el->br = NULL;
			kfree(el);
			break;
		}
	}
	spin_unlock_bh(&nobd_fdb_lock);
	if (!list_empty(&nobd_br_list))
		mod_timer(&nobd_fdb_timer, jiffies + HZ);

	return 0;
}

static void nobd_fdb_timer_expired(unsigned long unused)
{
	struct list_head *p;
	struct br_element *el = NULL;

	spin_lock_bh(&nobd_fdb_lock);
	list_for_each(p, &nobd_br_list) {
		el = list_entry(p, struct br_element, list);
		nobd_br_fdb_read(el->br);
	}
	spin_unlock_bh(&nobd_fdb_lock);

	mod_timer(&nobd_fdb_timer, jiffies + nobd_FDB_TO);
}

int __init nobd_br_fdb_init(void)
{
	pr_info("%s\n", __func__);

	init_timer(&nobd_fdb_timer);
	nobd_fdb_timer.function = &nobd_fdb_timer_expired;
	return 0;
}

void __exit nobd_br_fdb_exit(void)
{
	struct list_head *p, *tmp;
	struct br_element *el = NULL;

	pr_info("%s\n", __func__);

	del_timer(&nobd_fdb_timer);
	spin_lock_bh(&nobd_fdb_lock);
	list_for_each_safe(p, tmp, &nobd_br_list) {
		el = list_entry(p, struct br_element, list);
		list_del(p);
		el->br = NULL;
		kfree(el);
	}
	spin_unlock_bh(&nobd_fdb_lock);
}
