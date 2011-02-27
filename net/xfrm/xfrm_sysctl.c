#include <linux/sysctl.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/xfrm.h>

static void __net_init __xfrm_sysctl_init(struct net *net)
{
	net->xfrm.sysctl_aevent_etime = XFRM_AE_ETIME;
	net->xfrm.sysctl_aevent_rseqth = XFRM_AE_SEQT_SIZE;
	net->xfrm.sysctl_larval_drop = 1;
	net->xfrm.sysctl_acq_expires = 30;
}

#ifdef CONFIG_SYSCTL
static struct ctl_table xfrm_table[] = {
	{
		.procname	= "xfrm_aevent_etime",
		.data		= &init_net.xfrm.sysctl_aevent_etime,
		.maxlen		= sizeof(u32),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "xfrm_aevent_rseqth",
		.data		= &init_net.xfrm.sysctl_aevent_rseqth,
		.maxlen		= sizeof(u32),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "xfrm_larval_drop",
		.data		= &init_net.xfrm.sysctl_larval_drop,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "xfrm_acq_expires",
		.data		= &init_net.xfrm.sysctl_acq_expires,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{}
};

int __net_init xfrm_sysctl_init(struct net *net)
{
	__xfrm_sysctl_init(net);
	net->xfrm.sysctl_hdr = register_net_sysctl_table_net_cookie(net,
				 net_core_path, xfrm_table);
	if (!net->xfrm.sysctl_hdr)
		return -ENOMEM;
	return 0;
}

void __net_exit xfrm_sysctl_fini(struct net *net)
{
	unregister_net_sysctl_table(net->xfrm.sysctl_hdr);
}
#else
int __net_init xfrm_sysctl_init(struct net *net)
{
	__xfrm_sysctl_init(net);
	return 0;
}
#endif
