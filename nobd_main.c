/*
 *	Network OBserving Daemon [NOBD]
 * 
 *      Monitoring of the network stack and notifies for any activities.
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
#include "include/nobd_nl.h"
#include "include/nobd_nc.h"

#undef pr_fmt
#define pr_fmt(fmt) "nobd: " fmt

static int __init nobd_init(void)
{
	int err = 0;

	pr_info("init\n");
	err = nobd_nl_open();
	if (err) {
		printk(KERN_ERR "nl failed\n");
		return err;
	}
	err = nobd_nc_init();
	if (err) {
		printk(KERN_ERR "nc failed\n");
		nobd_nl_close();
		return err;
	}

	return err;
}

static void __exit nobd_exit(void)
{
	pr_info("exit\n");
	nobd_nl_close();
	nobd_nc_exit();
}

module_init(nobd_init)
module_exit(nobd_exit)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Haim Daniel <haimdaniel@gmail.com>");
