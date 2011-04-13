/*
 * sysctl_net_llc.c: sysctl interface to LLC net subsystem.
 *
 * Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/llc.h>

#ifndef CONFIG_SYSCTL
#error This file should not be compiled without CONFIG_SYSCTL defined
#endif

static struct ctl_table llc2_timeout_table[] = {
	{
		.procname	= "ack",
		.data		= &sysctl_llc2_ack_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "busy",
		.data		= &sysctl_llc2_busy_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "p",
		.data		= &sysctl_llc2_p_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "rej",
		.data		= &sysctl_llc2_rej_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{ },
};

static struct ctl_table llc_station_table[] = {
	{
		.procname	= "ack_timeout",
		.data		= &sysctl_llc_station_ack_timeout,
		.maxlen		= sizeof(long),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{ },
};


static const __initdata struct ctl_path llc2_timeout_path[] = {
	{ .procname = "net", },
	{ .procname = "llc", },
	{ .procname = "llc2", },
	{ .procname = "timeout", },
	{ }
};

static const __initdata struct ctl_path llc_station_path[] = {
	{ .procname = "net", },
	{ .procname = "llc", },
	{ .procname = "station", },
	{ }
};

static struct ctl_table_header *llc_station_hdr;
static struct ctl_table_header *llc2_timeout_hdr;

int __init llc_sysctl_init(void)
{
	llc_station_hdr = register_sysctl_paths(llc_station_path, llc_station_table);
	if (!llc_station_hdr)
		return -ENOMEM;

	llc2_timeout_hdr = register_sysctl_paths(llc2_timeout_path, llc2_timeout_table);
	if (!llc2_timeout_hdr) {
		unregister_sysctl_table(llc_station_hdr);
		llc_station_hdr = NULL;
		return -ENOMEM;
	}

	return 0;
}

void llc_sysctl_exit(void)
{
	if (llc2_timeout_hdr) {
		unregister_sysctl_table(llc2_timeout_hdr);
		llc2_timeout_hdr = NULL;
	}
	if (llc_station_hdr) {
		unregister_sysctl_table(llc_station_hdr);
		llc_station_hdr = NULL;
	}
}
