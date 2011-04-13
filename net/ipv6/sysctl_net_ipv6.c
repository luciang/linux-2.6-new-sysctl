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

static ctl_table ipv6_bindv6only_template[] = {
	{
		.procname	= "bindv6only",
		.data		= &init_net.ipv6.sysctl.bindv6only,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
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

static const struct ctl_path net_ipv6_route_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv6", },
	{ .procname = "route", },
	{ },
};

static const struct ctl_path net_ipv6_icmp_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv6", },
	{ .procname = "icmp", },
	{ },
};

static int __net_init ipv6_sysctl_net_init(struct net *net)
{
	struct ctl_table *ipv6_bindv6only_table;
	struct ctl_table *ipv6_route_table;
	struct ctl_table *ipv6_icmp_table;

	ipv6_bindv6only_table = kmemdup(ipv6_bindv6only_template,
					sizeof(ipv6_bindv6only_template), GFP_KERNEL);
	if (!ipv6_bindv6only_table)
		goto fail_alloc_ipv6_bindv6only_table;
	ipv6_bindv6only_table[0].data = &net->ipv6.sysctl.bindv6only;

	ipv6_route_table = ipv6_route_sysctl_init(net);
	if (!ipv6_route_table)
		goto fail_alloc_ipv6_route_table;

	ipv6_icmp_table = ipv6_icmp_sysctl_init(net);
	if (!ipv6_icmp_table)
		goto fail_alloc_ipv6_icmp_table;


	net->ipv6.sysctl.bindv6only_hdr = register_net_sysctl_table(
		net, net_ipv6_ctl_path, ipv6_bindv6only_table);
	if (!net->ipv6.sysctl.bindv6only_hdr)
		goto fail_reg_bindv6only_hdr;

	net->ipv6.sysctl.route6_hdr = register_net_sysctl_table(
		net, net_ipv6_route_path, ipv6_route_table);
	if (!net->ipv6.sysctl.route6_hdr)
		goto fail_reg_route6_hdr;

	net->ipv6.sysctl.icmp6_hdr = register_net_sysctl_table(
		net, net_ipv6_icmp_path, ipv6_icmp_table);
	if (!net->ipv6.sysctl.icmp6_hdr)
		goto fail_reg_icmp6_hdr;

	return 0;

fail_reg_icmp6_hdr:
	unregister_net_sysctl_table(net->ipv6.sysctl.route6_hdr);
fail_reg_route6_hdr:
	unregister_net_sysctl_table(net->ipv6.sysctl.bindv6only_hdr);
fail_reg_bindv6only_hdr:
	kfree(ipv6_icmp_table);
fail_alloc_ipv6_icmp_table:
	kfree(ipv6_route_table);
fail_alloc_ipv6_route_table:
	kfree(ipv6_bindv6only_table);
fail_alloc_ipv6_bindv6only_table:
	return -ENOMEM;
}

static void __net_exit ipv6_sysctl_net_exit(struct net *net)
{
	struct ctl_table *ipv6_bindv6only_table;
	struct ctl_table *ipv6_route_table;
	struct ctl_table *ipv6_icmp_table;

	ipv6_bindv6only_table = net->ipv6.sysctl.bindv6only_hdr->ctl_table_arg;
	ipv6_route_table = net->ipv6.sysctl.route6_hdr->ctl_table_arg;
	ipv6_icmp_table = net->ipv6.sysctl.icmp6_hdr->ctl_table_arg;

	unregister_net_sysctl_table(net->ipv6.sysctl.icmp6_hdr);
	unregister_net_sysctl_table(net->ipv6.sysctl.route6_hdr);
	unregister_net_sysctl_table(net->ipv6.sysctl.bindv6only_hdr);

	kfree(ipv6_icmp_table);
	kfree(ipv6_route_table);
	kfree(ipv6_bindv6only_table);
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

static const struct ctl_path net_ipv6_neigh_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv6", },
	{ .procname = "neigh", },
	{ },
};
static struct ctl_table_header *ip6_base;

int ipv6_static_sysctl_register(void)
{
	ip6_base = register_sysctl_paths(net_ipv6_neigh_path, empty);
	if (ip6_base == NULL)
		return -ENOMEM;
	return 0;
}

void ipv6_static_sysctl_unregister(void)
{
	unregister_net_sysctl_table(ip6_base);
}
