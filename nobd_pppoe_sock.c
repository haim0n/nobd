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
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/if_pppox.h>
#include <net/sock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <linux/fdtable.h>
#endif

#undef pr_fmt
#define pr_fmt(fmt) "nobd_pppoe_sock: " fmt

/* taken from exit.c put_files_struct() */
static void __put_files_struct(struct task_struct *task)
{
	struct files_struct *files = task->files;

	if (files) {
		spin_unlock_bh(&files->file_lock);
	}
	task_unlock(task);
}

/* taken from exit.c get_files_struct()
   NOTE: _don't_ release the task lock, until done with the files struct ! */
static struct files_struct *__get_files_struct(struct task_struct *task)
{
	struct files_struct *files;

	/* we abuse that lock to avoid race of put_files_struct() in exit.c */
	task_lock(task); 
	files = task->files;
//      if (files)
//      	atomic_inc(&files->count);
	if (files) {
		spin_lock_bh(&files->file_lock);
		/* yes we do need it, since we can't update the refcount here
		   due to unexported symbols on put_files() flow */
		if (!atomic_read(&files->count)) {
			files = NULL; 
		}
	}
//      task_unlock(task);

	return files;
}

static struct sock *get_pppox_sock_by_filp(struct file *filp)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct sock *sk;

	if (!S_ISSOCK(inode->i_mode))
		return NULL;

	sk = SOCKET_I(inode)->sk;
	if (sk->sk_family != AF_PPPOX)
		return NULL;

	sock_hold(sk);

	return sk;
}

static void detect_pppox_sock_files(struct files_struct *files, 
				    struct task_struct *tsk /* just for printout */, 
				    struct net_device *dev)
{
	int i, j;
	struct fdtable *fdt;

	j = 0;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	for (;;) {
		unsigned long set;
		i = j * __NFDBITS;
		if (i >= fdt->max_fds)
			break;
		set = fdt->open_fds->fds_bits[j++];
		while (set) {
			if (set & 1) {
				struct file *filep = fdt->fd[i];
				if (filep) {
					struct sock *sk = get_pppox_sock_by_filp(filep);
					if (sk) {
						struct pppox_sock *po;
						lock_sock(sk);
						po = pppox_sk(sk);
						/* HAIM FIXME : need a way to map between pppoe_dev and event_dev  */
//      					if (po->pppoe_dev == dev) {
							printk(KERN_INFO "(%s:%d) found pppoe sock!\n", __func__, __LINE__);
							printk(KERN_INFO "Task %s,pid = %d,state = %ld, "
									 "ch %u, ev_dev %s ev_dev_index %d, "
									 "pppoe_dev %s index %d\n",
							       tsk->comm, tsk->pid, tsk->state, ppp_channel_index(&po->chan),
							       dev->name, dev->ifindex,
							       po->pppoe_dev->name, po->pppoe_ifindex);
//      					}
						release_sock(sk);
						__sock_put(sk);
					}
				}
			}
			i++;
			set >>= 1;
		}
	}
	spin_unlock(&files->file_lock);
}

void find_dev_pppoe_socks(struct net_device *dev)
{
	struct task_struct *tsk;
	struct files_struct *files;

	read_lock_bh(&tasklist_lock);
	for_each_process(tsk) {
		files = __get_files_struct(tsk);
		if (files) {
			detect_pppox_sock_files(files, tsk, dev);
		}
		__put_files_struct(tsk);
	}
	read_unlock_bh(&tasklist_lock);
}
