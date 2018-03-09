/*
 * BRIEF DESCRIPTION
 *
 * Inode operations for directories.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#include <linux/fs.h>
#include <linux/pagemap.h>
#include "nova.h"
#include "journal.h"
#include "inode.h"

static ino_t nova_inode_by_name(struct inode *dir, struct qstr *entry,
				 struct nova_dentry **res_entry)
{
	struct super_block *sb = dir->i_sb;
	struct nova_dentry *direntry;

	direntry = nova_find_dentry(sb, NULL, dir,
					entry->name, entry->len);
	if (direntry == NULL)
		return 0;

	*res_entry = direntry;
	return direntry->ino;
}

static struct dentry *nova_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct inode *inode = NULL;
	struct nova_dentry *de;
	ino_t ino;
	timing_t lookup_time;

	NOVA_START_TIMING(lookup_t, lookup_time);
	if (dentry->d_name.len > NOVA_NAME_LEN) {
		nova_dbg("%s: namelen %u exceeds limit\n",
			__func__, dentry->d_name.len);
		return ERR_PTR(-ENAMETOOLONG);
	}

	nova_dbg_verbose("%s: %s\n", __func__, dentry->d_name.name);
	ino = nova_inode_by_name(dir, &dentry->d_name, &de);
	nova_dbg_verbose("%s: ino %lu\n", __func__, ino);
	if (ino) {
		inode = nova_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
				|| inode == ERR_PTR(-EACCES)) {
			nova_err(dir->i_sb,
				  "%s: get inode failed: %lu\n",
				  __func__, (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	NOVA_END_TIMING(lookup_t, lookup_time);
	return d_splice_alias(inode, dentry);
}

struct dentry *nova_get_parent(struct dentry *child)
{
	struct inode *inode;
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct nova_dentry *de = NULL;
	ino_t ino;

	nova_inode_by_name(child->d_inode, &dotdot, &de);
	if (!de)
		return ERR_PTR(-ENOENT);

	/* FIXME: can de->ino be avoided by using the return value of
	 * nova_inode_by_name()?
	 */
	ino = le64_to_cpu(de->ino);

	if (ino)
		inode = nova_iget(child->d_inode->i_sb, ino);
	else
		return ERR_PTR(-ENOENT);

	return d_obtain_alias(inode);
}

const struct inode_operations nova_dir_inode_operations = {
	.lookup		= nova_lookup,
};
