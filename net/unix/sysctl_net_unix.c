/*
 * NET4:	Sysctl interface to net af_unix subsystem.
 *
 * Authors:	Mike Shaver.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>

#include <net/af_unix.h>

static ctl_table unix_table[] = {
	{
		.procname	= "max_dgram_qlen",
		.data		= &init_net.unx.sysctl_max_dgram_qlen,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_path unix_path[] = {
	{ .procname = "net", },
	{ .procname = "unix", },
	{ },
};

int __net_init unix_sysctl_register(struct net *net)
{
	net->unx.ctl = register_net_sysctl_table_net_cookie(net, unix_path,
							    unix_table);
	if (net->unx.ctl == NULL)
		return -ENOMEM;

	return 0;
}

void unix_sysctl_unregister(struct net *net)
{
	unregister_sysctl_table(net->unx.ctl);
}
