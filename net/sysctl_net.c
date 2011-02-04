/* -*- linux-c -*-
 * sysctl_net.c: sysctl interface to net subsystem.
 *
 * Begun April 1, 1996, Mike Shaver.
 * Added /proc/sys/net directories for each protocol family. [MS]
 *
 * Revision 1.2  1996/05/08  20:24:40  shaver
 * Added bits for NET_BRIDGE and the NET_IPV4_ARP stuff and
 * NET_IPV4_IP_FORWARD.
 *
 *
 */

#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/nsproxy.h>

#include <net/sock.h>

#ifdef CONFIG_INET
#include <net/ip.h>
#endif

#ifdef CONFIG_NET
#include <linux/if_ether.h>
#endif

#ifdef CONFIG_TR
#include <linux/if_tr.h>
#endif

static int is_seen(struct ctl_table_group *group)
{
	return &current->nsproxy->net_ns->netns_ctl_group == group;
}

/* Return standard mode bits for table entry. */
static int net_ctl_permissions(struct ctl_table *table)
{
	/* Allow network administrator to have same access as root. */
	if (capable(CAP_NET_ADMIN)) {
		int mode = (table->mode >> 6) & 7;
		return (mode << 6) | (mode << 3) | mode;
	}
	return table->mode;
}

static const struct ctl_table_group_ops net_sysctl_group_ops = {
	.is_seen = is_seen,
	.permissions = net_ctl_permissions,
};

static int net_ctl_ro_permissions(struct ctl_table *table)
{
	if (net_eq(current->nsproxy->net_ns, &init_net))
		return table->mode;
	else
		return table->mode & ~0222;
}

static const struct ctl_table_group_ops net_sysctl_ro_group_ops = {
	.permissions = net_ctl_ro_permissions,
};
static struct ctl_table_group net_sysctl_ro_group = {
	.has_netns_corresp = 0,
	.ctl_ops = &net_sysctl_ro_group_ops,
};

static int __net_init sysctl_net_init(struct net *net)
{
	int has_netns_corresp = 1;

	sysctl_init_group(&net->netns_ctl_group, &net_sysctl_group_ops,
			  has_netns_corresp);
	return 0;
}

static void __net_exit sysctl_net_exit(struct net *net)
{
	WARN_ON(!list_empty(&net->netns_ctl_group.corresp_list));
}

static struct pernet_operations sysctl_pernet_ops = {
	.init = sysctl_net_init,
	.exit = sysctl_net_exit,
};

static __init int net_sysctl_init(void)
{
	int ret;
	ret = register_pernet_subsys(&sysctl_pernet_ops);
	if (ret)
		goto out;
out:
	return ret;
}
subsys_initcall(net_sysctl_init);

struct ctl_table_header *register_net_sysctl_table(struct net *net,
						   const struct ctl_path *path,
						   struct ctl_table *table)
{
	return __register_sysctl_paths(&net->netns_ctl_group, path, table);
}
EXPORT_SYMBOL_GPL(register_net_sysctl_table);

struct ctl_table_header *register_net_sysctl_rotable(const struct ctl_path *path,
						     struct ctl_table *table)
{
	return __register_sysctl_paths(&net_sysctl_ro_group, path, table);
}
EXPORT_SYMBOL_GPL(register_net_sysctl_rotable);

void unregister_net_sysctl_table(struct ctl_table_header *header)
{
	unregister_sysctl_table(header);
}
EXPORT_SYMBOL_GPL(unregister_net_sysctl_table);
