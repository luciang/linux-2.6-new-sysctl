/*
 * /proc/sys support
 */
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/namei.h>
#include "internal.h"

static const struct dentry_operations proc_sys_dentry_operations;
static const struct file_operations proc_sys_file_operations;
static const struct inode_operations proc_sys_inode_operations;
static const struct file_operations proc_sys_dir_file_operations;
static const struct inode_operations proc_sys_dir_operations;

static struct inode *proc_sys_make_inode(struct super_block *sb,
		struct ctl_table_header *head, struct ctl_table *table)
{
	struct inode *inode;
	struct proc_inode *ei;

	inode = new_inode(sb);
	if (!inode)
		goto out;

	inode->i_ino = get_next_ino();

	sysctl_proc_inode_get(head);
	ei = PROC_I(inode);
	ei->sysctl = head;
	ei->sysctl_entry = table;

	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME;

	/* directories have table==NULL (thus ei->sysctl_entry is NULL too) */
	if (table) {
		inode->i_mode = S_IFREG | table->mode;
		inode->i_op = &proc_sys_inode_operations;
		inode->i_fop = &proc_sys_file_operations;
	} else {
		inode->i_mode = S_IFDIR | S_IRUGO | S_IWUSR;
		inode->i_nlink = 0;
		inode->i_op = &proc_sys_dir_operations;
		inode->i_fop = &proc_sys_dir_file_operations;
	}
out:
	return inode;
}

static struct ctl_table *find_in_table(struct ctl_table *p, struct qstr *name)
{
	int len;
	for ( ; p->procname; p++) {

		len = strlen(p->procname);
		if (len != name->len)
			continue;

		if (memcmp(p->procname, name->name, len) == 0)
			return p;
	}
	return NULL;
}

static struct dentry *proc_sys_lookup(struct inode *dir, struct dentry *dentry,
					struct nameidata *nd)
{
	struct ctl_table_header *head = sysctl_use_header(PROC_I(dir)->sysctl);
	struct qstr *name = &dentry->d_name;
	struct ctl_table_header *h = NULL, *found_head = NULL;
	struct ctl_table *table = NULL;
	struct inode *inode;
	struct dentry *err = ERR_PTR(-ENOENT);


	if (IS_ERR(head))
		return ERR_CAST(head);

retry:
	sysctl_read_lock_head(head);

	/* first check whether a subdirectory has the searched-for name */
	list_for_each_entry_rcu(h, &head->ctl_subdirs, ctl_entry) {
		if (IS_ERR(sysctl_use_header(h)))
			continue;

		if (strcmp(name->name, h->ctl_dirname) == 0) {
			found_head = h;
			goto search_finished;
		}
		sysctl_unuse_header(h);
	}

	/* no subdir with that name, look for the file in the ctl_tables */
	list_for_each_entry_rcu(h, &head->ctl_tables, ctl_entry) {
		if (IS_ERR(sysctl_use_header(h)))
			continue;

		table = find_in_table(h->ctl_table_arg, name);
		if (table) {
			found_head = h;
			goto search_finished;
		}
		sysctl_unuse_header(h);
	}

search_finished:
	sysctl_read_unlock_head(head);

	if (!found_head) {
		struct ctl_table_header *netns_corresp;
		/* the item was not found in the dir's sub-directories
		 * or tables. See if this dir has a netns
		 * correspondent and restart the lookup in there. */
		netns_corresp = sysctl_use_netns_corresp(head);
		if (netns_corresp) {
			sysctl_unuse_header(head);
			head = netns_corresp;
			goto retry;
		}
	}
	if (!found_head)
		goto out;

	err = ERR_PTR(-ENOMEM);
	inode = proc_sys_make_inode(dir->i_sb, found_head, table);
	sysctl_unuse_header(found_head);
	if (!inode)
		goto out;

	err = NULL;
	d_set_d_op(dentry, &proc_sys_dentry_operations);
	d_add(dentry, inode);

out:
	sysctl_unuse_header(head);
	return err;
}

static ssize_t proc_sys_call_handler(struct file *filp, void __user *buf,
		size_t count, loff_t *ppos, int write)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct ctl_table_header *head = sysctl_use_header(PROC_I(inode)->sysctl);
	struct ctl_table *table = PROC_I(inode)->sysctl_entry;
	ssize_t error;
	size_t res;

	if (IS_ERR(head))
		return PTR_ERR(head);

	/*
	 * At this point we know that the sysctl was not unregistered
	 * and won't be until we finish.
	 */
	error = -EPERM;
	if (sysctl_perm(head->ctl_group, table, write ? MAY_WRITE : MAY_READ))
		goto out;

	/* if that can happen at all, it should be -EINVAL, not -EISDIR */
	error = -EINVAL;
	if (!table->proc_handler)
		goto out;

	/* careful: calling conventions are nasty here */
	res = count;
	error = table->proc_handler(table, write, buf, &res, ppos);
	if (!error)
		error = res;
out:
	sysctl_unuse_header(head);

	return error;
}

static ssize_t proc_sys_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	return proc_sys_call_handler(filp, (void __user *)buf, count, ppos, 0);
}

static ssize_t proc_sys_write(struct file *filp, const char __user *buf,
				size_t count, loff_t *ppos)
{
	return proc_sys_call_handler(filp, (void __user *)buf, count, ppos, 1);
}


static int proc_sys_fill_cache(struct file *filp, void *dirent,
				filldir_t filldir,
				struct ctl_table_header *head,
				struct ctl_table *table)
{
	struct dentry *child, *dir = filp->f_path.dentry;
	struct inode *inode;
	struct qstr qname;
	ino_t ino = 0;
	unsigned type = DT_UNKNOWN;

	qname.name = table ? table->procname : head->ctl_dirname;
	qname.len  = strlen(qname.name);
	qname.hash = full_name_hash(qname.name, qname.len);

	child = d_lookup(dir, &qname);
	if (!child) {
		child = d_alloc(dir, &qname);
		if (child) {
			inode = proc_sys_make_inode(dir->d_sb, head, table);
			if (!inode) {
				dput(child);
				return -ENOMEM;
			} else {
				d_set_d_op(child, &proc_sys_dentry_operations);
				d_add(child, inode);
			}
		} else {
			return -ENOMEM;
		}
	}
	inode = child->d_inode;
	ino  = inode->i_ino;
	type = inode->i_mode >> 12;
	dput(child);
	return !!filldir(dirent, qname.name, qname.len, filp->f_pos, ino, type);
}

static int scan(struct ctl_table_header *head,
		unsigned long *pos, struct file *file,
		void *dirent, filldir_t filldir)
{
	struct ctl_table_header *h;
	int res = 0;

	sysctl_read_lock_head(head);

	list_for_each_entry_rcu(h, &head->ctl_subdirs, ctl_entry) {
		if (*pos < file->f_pos) {
			(*pos)++;
			continue;
		}

		if (IS_ERR(sysctl_use_header(h)))
			continue;

		res = proc_sys_fill_cache(file, dirent, filldir, h, NULL);
		sysctl_unuse_header(h);
		if (res)
			goto out;

		file->f_pos = *pos + 1;
		(*pos)++;
	}

	list_for_each_entry_rcu(h, &head->ctl_tables, ctl_entry) {
		ctl_table *t;

		if (IS_ERR(sysctl_use_header(h)))
			continue;

		for (t = h->ctl_table_arg; t->procname; t++, (*pos)++) {
			if (*pos < file->f_pos)
				continue;

			res = proc_sys_fill_cache(file, dirent, filldir, h, t);
			if (res) {
				sysctl_unuse_header(h);
				goto out;
			}
			file->f_pos = *pos + 1;
		}
		sysctl_unuse_header(h);
	}

out:
	sysctl_read_unlock_head(head);
	return res;
}

static int proc_sys_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	struct dentry *dentry = filp->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct ctl_table_header *head = sysctl_use_header(PROC_I(inode)->sysctl);
	unsigned long pos;
	int ret = -EINVAL;

	if (IS_ERR(head))
		return PTR_ERR(head);

	ret = 0;
	/* Avoid a switch here: arm builds fail with missing __cmpdi2 */
	if (filp->f_pos == 0) {
		if (filldir(dirent, ".", 1, filp->f_pos,
				inode->i_ino, DT_DIR) < 0)
			goto out;
		filp->f_pos++;
	}
	if (filp->f_pos == 1) {
		if (filldir(dirent, "..", 2, filp->f_pos,
				parent_ino(dentry), DT_DIR) < 0)
			goto out;
		filp->f_pos++;
	}
	pos = 2;
	ret = scan(head, &pos, filp, dirent, filldir);
	if (!ret) {
		/* the netns-correspondent contains only those
		 * subdirectories that are netns-specific, and not
		 * shared with the @head directory: there is no
		 * possibility to list the same directory twice (once
		 * for @head and once for @netns_corresp). Sibling
		 * tables cannot contain the entries with the same
		 * name, no need to worry about them either. */
		struct ctl_table_header *netns_corresp;
		netns_corresp = sysctl_use_netns_corresp(head);
		if (netns_corresp) {
			ret = scan(netns_corresp, &pos, filp, dirent, filldir);
			sysctl_unuse_header(netns_corresp);
		}
	}
	ret = 1;
out:
	sysctl_unuse_header(head);
	return ret;
}

static int proc_sys_permission(struct inode *inode, int mask,unsigned int flags)
{
	/*
	 * sysctl entries that are not writeable,
	 * are _NOT_ writeable, capabilities or not.
	 */
	struct ctl_table_header *head;
	struct ctl_table *table;
	int error;

	if (flags & IPERM_FLAG_RCU)
		return -ECHILD;

	/* Executable files are not allowed under /proc/sys/ */
	if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))
		return -EACCES;

	head = sysctl_use_header(PROC_I(inode)->sysctl);
	if (IS_ERR(head))
		return PTR_ERR(head);

	table = PROC_I(inode)->sysctl_entry;
	if (!table) /* directory - r-xr-xr-x */
		error = mask & MAY_WRITE ? -EACCES : 0;
	else /* Use the permissions on the sysctl table entry */
		error = sysctl_perm(head->ctl_group, table, mask);

	sysctl_unuse_header(head);
	return error;
}

static int proc_sys_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	if (attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID))
		return -EPERM;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = vmtruncate(inode, attr->ia_size);
		if (error)
			return error;
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

static int proc_sys_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct ctl_table_header *head = sysctl_use_header(PROC_I(inode)->sysctl);
	struct ctl_table *table = PROC_I(inode)->sysctl_entry;

	if (IS_ERR(head))
		return PTR_ERR(head);

	generic_fillattr(inode, stat);
	if (table)
		stat->mode = (stat->mode & S_IFMT) | table->mode;

	sysctl_unuse_header(head);
	return 0;
}

static const struct file_operations proc_sys_file_operations = {
	.read		= proc_sys_read,
	.write		= proc_sys_write,
	.llseek		= default_llseek,
};

static const struct file_operations proc_sys_dir_file_operations = {
	.readdir	= proc_sys_readdir,
	.llseek		= generic_file_llseek,
};

static const struct inode_operations proc_sys_inode_operations = {
	.permission	= proc_sys_permission,
	.setattr	= proc_sys_setattr,
	.getattr	= proc_sys_getattr,
};

static const struct inode_operations proc_sys_dir_operations = {
	.lookup		= proc_sys_lookup,
	.permission	= proc_sys_permission,
	.setattr	= proc_sys_setattr,
	.getattr	= proc_sys_getattr,
};

static int proc_sys_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU)
		return -ECHILD;
	return !PROC_I(dentry->d_inode)->sysctl->unregistering;
}

static int proc_sys_delete(const struct dentry *dentry)
{
	return !!PROC_I(dentry->d_inode)->sysctl->unregistering;
}

static int proc_sys_compare(const struct dentry *parent,
		const struct inode *pinode,
		const struct dentry *dentry, const struct inode *inode,
		unsigned int len, const char *str, const struct qstr *name)
{
	struct ctl_table_header *head;
	/* Although proc doesn't have negative dentries, rcu-walk means
	 * that inode here can be NULL */
	/* AV: can it, indeed? */
	if (!inode)
		return 1;
	if (name->len != len)
		return 1;
	if (memcmp(name->name, str, len))
		return 1;
	head = rcu_dereference(PROC_I(inode)->sysctl);
	return !head || !sysctl_is_seen(head);
}

static const struct dentry_operations proc_sys_dentry_operations = {
	.d_revalidate	= proc_sys_revalidate,
	.d_delete	= proc_sys_delete,
	.d_compare	= proc_sys_compare,
};

int __init proc_sys_init(void)
{
	struct proc_dir_entry *proc_sys_root;

	proc_sys_root = proc_mkdir("sys", NULL);
	proc_sys_root->proc_iops = &proc_sys_dir_operations;
	proc_sys_root->proc_fops = &proc_sys_dir_file_operations;
	proc_sys_root->nlink = 0;
	return 0;
}
