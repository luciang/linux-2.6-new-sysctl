#include <linux/stat.h>
#include <linux/sysctl.h>
#include "../fs/xfs/linux-2.6/xfs_sysctl.h"
#include <linux/sunrpc/debug.h>
#include <linux/string.h>
#include <net/ip_vs.h>


static void sysctl_print_path(struct ctl_table *table,
			      struct ctl_table **parents, int depth)
{
	struct ctl_table *p;
	int i;
	if (table->procname) {
		for (i = 0; i < depth; i++) {
			p = parents[i];
			printk("/%s", p->procname ? p->procname : "");
		}
		printk("/%s", table->procname);
	}
	printk(" ");
}

static struct ctl_table *sysctl_check_lookup(struct nsproxy *namespaces,
	     struct ctl_table *table, struct ctl_table **parents, int depth)
{
	struct ctl_table_header *head;
	struct ctl_table *ref, *test;
	int cur_depth;

	for (head = __sysctl_head_next(namespaces, NULL); head;
	     head = __sysctl_head_next(namespaces, head)) {
		cur_depth = depth;
		ref = head->ctl_table;
repeat:
		test = parents[depth - cur_depth];
		for (; ref->procname; ref++) {
			int match = 0;
			if (cur_depth && !ref->child)
				continue;

			if (test->procname && ref->procname &&
			    (strcmp(test->procname, ref->procname) == 0))
					match++;

			if (match) {
				if (cur_depth != 0) {
					cur_depth--;
					ref = ref->child;
					goto repeat;
				}
				goto out;
			}
		}
	}
	ref = NULL;
out:
	sysctl_head_finish(head);
	return ref;
}

static void set_fail(const char **fail, struct ctl_table *table,
	     const char *str, struct ctl_table **parents, int depth)
{
	if (*fail) {
		printk(KERN_ERR "sysctl table check failed: ");
		sysctl_print_path(table, parents, depth);
		printk(" %s\n", *fail);
		dump_stack();
	}
	*fail = str;
}

static void sysctl_check_leaf(struct nsproxy *namespaces,
			      struct ctl_table *table, const char **fail,
			      struct ctl_table **parents, int depth)
{
	struct ctl_table *ref;

	ref = sysctl_check_lookup(namespaces, table, parents, depth);
	if (ref && (ref != table))
		set_fail(fail, table, "Sysctl already exists", parents, depth);
}



#define SET_FAIL(str) set_fail(&fail, table, str, parents, depth)

static int __sysctl_check_table(struct nsproxy *namespaces,
	struct ctl_table *table, struct ctl_table **parents, int depth)
{
	const char *fail = NULL;
	int error = 0;

	if (depth >= CTL_MAXNAME) {
		SET_FAIL("Sysctl tree too deep");
		return -EINVAL;
	}

	for (; table->procname; table++) {
		fail = NULL;

		if (table->parent) {
			if (!table->parent->procname)
				SET_FAIL("Parent without procname");
		}
		if (table->child) {
			if (table->data)
				SET_FAIL("Directory with data?");
			if (table->maxlen)
				SET_FAIL("Directory with maxlen?");
			if ((table->mode & (S_IRUGO|S_IXUGO)) != table->mode)
				SET_FAIL("Writable sysctl directory");
			if (table->proc_handler)
				SET_FAIL("Directory with proc_handler");
			if (table->extra1)
				SET_FAIL("Directory with extra1");
			if (table->extra2)
				SET_FAIL("Directory with extra2");
		} else {
			if ((table->proc_handler == proc_dostring) ||
			    (table->proc_handler == proc_dointvec) ||
			    (table->proc_handler == proc_dointvec_minmax) ||
			    (table->proc_handler == proc_dointvec_jiffies) ||
			    (table->proc_handler == proc_dointvec_userhz_jiffies) ||
			    (table->proc_handler == proc_dointvec_ms_jiffies) ||
			    (table->proc_handler == proc_doulongvec_minmax) ||
			    (table->proc_handler == proc_doulongvec_ms_jiffies_minmax)) {
				if (!table->data)
					SET_FAIL("No data");
				if (!table->maxlen)
					SET_FAIL("No maxlen");
			}
#ifdef CONFIG_PROC_SYSCTL
			if (!table->proc_handler)
				SET_FAIL("No proc_handler");
#endif
			parents[depth] = table;
			sysctl_check_leaf(namespaces, table, &fail,
					  parents, depth);
		}
		if (table->mode > 0777)
			SET_FAIL("bogus .mode");
		if (fail) {
			SET_FAIL(NULL);
			error = -EINVAL;
		}
		if (table->child) {
			parents[depth] = table;
			error |= __sysctl_check_table(namespaces, table->child,
						      parents, depth + 1);
		}
	}
	return error;
}


int sysctl_check_table(struct nsproxy *namespaces, struct ctl_table *table)
{
	struct ctl_table *parents[CTL_MAXNAME];
	/* Keep track of parents as we go down into the tree:
	 * - the node at depth 'd' will have the parent at parents[d-1].
	 * - the root node (depth=0) has no parent in this array.
	 */
	return __sysctl_check_table(namespaces, table, parents, 0);
}
