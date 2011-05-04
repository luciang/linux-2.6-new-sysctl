#include <linux/sysctl.h>
#include <linux/string.h>

/*
 * @path: the path to the offender
 * @offender is the name of a file or directory that violated some sysctl rules.
 * @str: a message accompanying the error
 */
static void fail(const struct ctl_path *path,
		 const char *offender,
		 const char *str)
{
	printk(KERN_ERR "sysctl sanity check failed: ");

	for (; path->procname; path++)
		printk("/%s", path->procname);

	if (offender)
		printk("/%s", offender);

	printk(": %s\n", str);
}

#define FAIL(str) do { fail(path, t->procname, str); error = -EINVAL;} while (0)

int sysctl_check_table(const struct ctl_path *path,
		       int nr_dirs,
		       struct ctl_table *table)
{
	struct ctl_table *t;
	int error = 0;

	if (nr_dirs > CTL_MAXNAME - 1) {
		fail(path, NULL, "tree too deep");
		error = -EINVAL;
	}

	for(t = table; t->procname; t++) {
		if ((t->proc_handler == proc_dostring) ||
		    (t->proc_handler == proc_dointvec) ||
		    (t->proc_handler == proc_dointvec_minmax) ||
		    (t->proc_handler == proc_dointvec_jiffies) ||
		    (t->proc_handler == proc_dointvec_userhz_jiffies) ||
		    (t->proc_handler == proc_dointvec_ms_jiffies) ||
		    (t->proc_handler == proc_doulongvec_minmax) ||
		    (t->proc_handler == proc_doulongvec_ms_jiffies_minmax)) {
			if (!t->data)
				FAIL("No data");
			if (!t->maxlen)
				FAIL("No maxlen");
		}
#ifdef CONFIG_PROC_SYSCTL
		if (!t->proc_handler)
			FAIL("No proc_handler");
#endif
		if (t->mode > 0777)
			FAIL("bogus .mode");
	}

	if (error)
		dump_stack();

	return error;
}


/*
 * @dir: the directory imediately above the offender
 * @offender is the name of a file or directory that violated some sysctl rules.
 */
static void duplicate_error(struct ctl_table_header *dir,
			    const char *offender)
{
	const char *names[CTL_MAXNAME];
	int i = 0;

	printk(KERN_ERR "sysctl duplicate check failed: ");

	for (; dir->parent; dir = dir->parent)
		/* ctl_dirname can be NULL: netns-correspondent
		 * directories do not have a ctl_dirname. Their only
		 * pourpose is to hold the list of
		 * subdirs/subtables. They hold netns-specific
		 * information for the parent directory. */
		if (dir->ctl_dirname) {
			names[i] = dir->ctl_dirname;
			i++;
		}

	/* Print the names in the normal path order, not reversed */
	for(i--; i >= 0; i--)
		printk("/%s", names[i]);

	printk("/%s \n", offender);
}

/* is there an entry in the table with the same procname? */
static int match(struct ctl_table *table, const char *name)
{
	for ( ; table->procname; table++) {

		if (strcmp(table->procname, name) == 0)
			return 1;
	}
	return 0;
}


/* Called under header->parent write lock.
 *
 * checks whether this header's table introduces items that have the
 * same names as other items at the same level (other files or
 * subdirectories of the current dir). */
int sysctl_check_duplicates(struct ctl_table_header *header)
{
	int has_duplicates = 0;
	struct ctl_table *table = header->ctl_table_arg;
	struct ctl_table_header *dir = header->parent;
	struct ctl_table_header *h;

	list_for_each_entry(h, &dir->ctl_subdirs, ctl_entry) {
		if (IS_ERR(sysctl_use_header(h)))
			continue;

		if (match(table, h->ctl_dirname)) {
			has_duplicates = 1;
			duplicate_error(dir, h->ctl_dirname);
		}

		sysctl_unuse_header(h);
	}

	list_for_each_entry(h, &dir->ctl_tables, ctl_entry) {
		ctl_table *t;

		if (IS_ERR(sysctl_use_header(h)))
			continue;

		for (t = h->ctl_table_arg; t->procname; t++) {
			if (match(table, t->procname)) {
				has_duplicates = 1;
				duplicate_error(dir, t->procname);
			}
		}
		sysctl_unuse_header(h);
	}

	if (has_duplicates)
		dump_stack();

	return has_duplicates;
}
