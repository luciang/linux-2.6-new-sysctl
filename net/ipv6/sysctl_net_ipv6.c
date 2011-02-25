/*
 * sysctl_net_ipv6.c: sysctl interface to net IPV6 subsystem.
 *
 * Changes:
 * YOSHIFUJI Hideaki @USAGI:	added icmp sysctl table.
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/ndisc.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/inet_frag.h>

static struct ctl_table empty[1];

static ctl_table ipv6_static_skeleton[] = {
	{
		.procname	= "neigh",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= empty,
	},
	{ }
};

static ctl_table ipv6_table[] = {
	{
		.procname	= "route",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= ipv6_route_table
	},
	{
		.procname	= "icmp",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= ipv6_icmp_table
	},
	{
		.procname	= "bindv6only",
		.data		= &init_net.ipv6.sysctl.bindv6only,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= netns_proc_dointvec,
	},
	{ }
};

static ctl_table ipv6_rotable[] = {
	{
		.procname	= "mld_max_msf",
		.data		= &sysctl_mld_max_msf,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{ }
};

struct ctl_path net_ipv6_ctl_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv6", },
	{ },
};
EXPORT_SYMBOL_GPL(net_ipv6_ctl_path);

static int __net_init ipv6_sysctl_net_init(struct net *net)
{
	net->ipv6.sysctl.table = register_net_sysctl_table(net,
				   net_ipv6_ctl_path, ipv6_table);
	if (!net->ipv6.sysctl.table)
		return -ENOMEM;

	return 0;
}

static void __net_exit ipv6_sysctl_net_exit(struct net *net)
{
	unregister_net_sysctl_table(net->ipv6.sysctl.table);
}

static struct pernet_operations ipv6_sysctl_net_ops = {
	.init = ipv6_sysctl_net_init,
	.exit = ipv6_sysctl_net_exit,
};

static struct ctl_table_header *ip6_header;

int ipv6_sysctl_register(void)
{
	int err = -ENOMEM;

	ip6_header = register_net_sysctl_rotable(net_ipv6_ctl_path, ipv6_rotable);
	if (ip6_header == NULL)
		goto out;

	err = register_pernet_subsys(&ipv6_sysctl_net_ops);
	if (err)
		goto err_pernet;
out:
	return err;

err_pernet:
	unregister_net_sysctl_table(ip6_header);
	goto out;
}

void ipv6_sysctl_unregister(void)
{
	unregister_net_sysctl_table(ip6_header);
	unregister_pernet_subsys(&ipv6_sysctl_net_ops);
}

static struct ctl_table_header *ip6_base;

int ipv6_static_sysctl_register(void)
{
	ip6_base = register_sysctl_paths(net_ipv6_ctl_path, ipv6_static_skeleton);
	if (ip6_base == NULL)
		return -ENOMEM;
	return 0;
}

void ipv6_static_sysctl_unregister(void)
{
	unregister_net_sysctl_table(ip6_base);
}
