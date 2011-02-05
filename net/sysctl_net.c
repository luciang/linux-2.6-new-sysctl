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

static struct ctl_table_set *
net_ctl_header_lookup(struct ctl_table_root *root, struct nsproxy *namespaces)
{
	return &namespaces->net_ns->sysctls;
}

static int is_seen(struct ctl_table_set *set)
{
	return &current->nsproxy->net_ns->sysctls == set;
}

/* Return standard mode bits for table entry. */
static int net_ctl_permissions(struct ctl_table_root *root,
			       struct nsproxy *nsproxy,
			       struct ctl_table *table)
{
	/* Allow network administrator to have same access as root. */
	if (capable(CAP_NET_ADMIN)) {
		int mode = (table->mode >> 6) & 7;
		return (mode << 6) | (mode << 3) | mode;
	}
	return table->mode;
}

static struct ctl_table_root net_sysctl_root = {
	.lookup = net_ctl_header_lookup,
	.permissions = net_ctl_permissions,
};

static int net_ctl_ro_header_perms(struct ctl_table_root *root,
		struct nsproxy *namespaces, struct ctl_table *table)
{
	if (net_eq(namespaces->net_ns, &init_net))
		return table->mode;
	else
		return table->mode & ~0222;
}

static struct ctl_table_root net_sysctl_ro_root = {
	.permissions = net_ctl_ro_header_perms,
};

static int __net_init sysctl_net_init(struct net *net)
{
	setup_sysctl_set(&net->sysctls,
			 &net_sysctl_ro_root.default_set,
			 is_seen);
	return 0;
}

static void __net_exit sysctl_net_exit(struct net *net)
{
	WARN_ON(!list_empty(&net->sysctls.list));
}

static struct pernet_operations sysctl_pernet_ops = {
	.init = sysctl_net_init,
	.exit = sysctl_net_exit,
};

static __init int sysctl_init(void)
{
	int ret;
	ret = register_pernet_subsys(&sysctl_pernet_ops);
	if (ret)
		goto out;
	register_sysctl_root(&net_sysctl_root);
	setup_sysctl_set(&net_sysctl_ro_root.default_set, NULL, NULL);
	register_sysctl_root(&net_sysctl_ro_root);
out:
	return ret;
}
subsys_initcall(sysctl_init);

struct ctl_table_header *register_net_sysctl_table_pathdata(struct net *net,
	const struct ctl_path *path, struct ctl_table *table, void *pathdata)
{
	struct nsproxy namespaces;
	namespaces = *current->nsproxy;
	namespaces.net_ns = net;
	return __register_sysctl_paths(&net_sysctl_root, &namespaces,
				       path, table, pathdata);
}
EXPORT_SYMBOL_GPL(register_net_sysctl_table_pathdata);

struct ctl_table_header *register_net_sysctl_table(struct net *net,
	const struct ctl_path *path, struct ctl_table *table)
{
	return register_net_sysctl_table_pathdata(net, path, table, net);
}
EXPORT_SYMBOL_GPL(register_net_sysctl_table);


struct ctl_table_header *register_net_sysctl_rotable(const
		struct ctl_path *path, struct ctl_table *table)
{
	return __register_sysctl_paths(&net_sysctl_ro_root, &init_nsproxy,
				       path, table, NULL);
}
EXPORT_SYMBOL_GPL(register_net_sysctl_rotable);

void unregister_net_sysctl_table(struct ctl_table_header *header)
{
	unregister_sysctl_table(header);
}
EXPORT_SYMBOL_GPL(unregister_net_sysctl_table);




static int net_proc_handler(ctl_table *ctl, int write,
			    void __user *buffer,
			    size_t *lenp, loff_t *ppos,
			    struct file *filp,
			    proc_handler *proc_handler)
{
	/* @ctl is shared between network namespaces, but the data
	 * that must be accessed by @proc_handler depends on the
	 * network namespace.
	 *
	 * This handler must be used only for ctl_tables shared
	 * between netns but for which the 'data' field is an offset
	 * inside the 'struct net' corresponding to the netns.
	 *
	 * The 'struct net*' is stored in the parent ctl_table's extra2.
	 */
	struct inode *parent_inode = filp->f_path.dentry->d_parent->d_inode;
	struct ctl_table *parent_table = PROC_I(parent_inode)->sysctl_entry;
	struct net *net = parent_table->extra2;
	struct ctl_table tmp_ctl = *ctl;

	/* 'data' must have been initialized by something like
	 *        ctl->data = &init_net.field1.field2;
	 * the adjustments bellow evaluate to:
	 *    tmp_ctl->data = &net->field1.field2
	 */
	tmp_ctl.data += (char *)net - (char *)&init_net;

	return proc_handler(&tmp_ctl, write, buffer, lenp, ppos);
}

int net_proc_dointvec(struct ctl_table *table, int write,
		      void __user *buffer, size_t *lenp,
		      loff_t *ppos, struct file *filp)
{
	return net_proc_handler(table, write, buffer, lenp,
				ppos, filp, proc_dointvec);
}

int net_proc_dointvec_jiffies(struct ctl_table *table, int write,
			      void __user *buffer, size_t *lenp,
			      loff_t *ppos, struct file *filp)
{
	return net_proc_handler(table, write, buffer, lenp,
				ppos, filp, proc_dointvec_jiffies);
}


int net_proc_dointvec_ms_jiffies(struct ctl_table *table, int write,
				 void __user *buffer, size_t *lenp,
				 loff_t *ppos, struct file *filp)
{
	return net_proc_handler(table, write, buffer, lenp,
				ppos, filp, proc_dointvec_ms_jiffies);
}
