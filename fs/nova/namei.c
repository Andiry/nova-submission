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

static void nova_lite_transaction_for_new_inode(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode *pidir, struct inode *inode,
	struct inode *dir, struct nova_inode_update *update)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int cpu;
	u64 journal_tail;
	timing_t trans_time;

	NOVA_START_TIMING(create_trans_t, trans_time);

	cpu = smp_processor_id();
	spin_lock(&sbi->journal_locks[cpu]);

	// If you change what's required to create a new inode, you need to
	// update this functions so the changes will be roll back on failure.
	journal_tail = nova_create_inode_transaction(sb, inode, dir, cpu, 1, 0);

	nova_update_inode(sb, dir, pidir, update);

	pi->valid = 1;
	nova_persist_inode(pi);
	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	spin_unlock(&sbi->journal_locks[cpu]);

	NOVA_END_TIMING(create_trans_t, trans_time);
}

/* Returns new tail after append */
/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int nova_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	struct nova_inode *pidir, *pi;
	struct nova_inode_update update;
	u64 pi_addr = 0;
	u64 ino, epoch_id;
	timing_t create_time;

	NOVA_START_TIMING(create_t, create_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	epoch_id = nova_get_epoch_id(sb);
	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	update.tail = 0;
	err = nova_add_dentry(dentry, ino, 0, &update, epoch_id);
	if (err)
		goto out_err;

	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);
	inode = nova_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode,
					0, 0, &dentry->d_name, epoch_id);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	pi = nova_get_block(sb, pi_addr);
	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
						&update);
	NOVA_END_TIMING(create_t, create_time);
	return err;
out_err:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(create_t, create_time);
	return err;
}

static int nova_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	u64 pi_addr = 0;
	struct nova_inode *pidir, *pi;
	struct nova_inode_update update;
	u64 ino;
	u64 epoch_id;
	timing_t mknod_time;

	NOVA_START_TIMING(mknod_t, mknod_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	epoch_id = nova_get_epoch_id(sb);
	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

	update.tail = 0;
	err = nova_add_dentry(dentry, ino, 0, &update, epoch_id);
	if (err)
		goto out_err;

	inode = nova_new_vfs_inode(TYPE_MKNOD, dir, pi_addr, ino, mode,
					0, rdev, &dentry->d_name, epoch_id);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	pi = nova_get_block(sb, pi_addr);
	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
						&update);
	NOVA_END_TIMING(mknod_t, mknod_time);
	return err;
out_err:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(mknod_t, mknod_time);
	return err;
}

static void nova_lite_transaction_for_time_and_link(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode *pidir, struct inode *inode,
	struct inode *dir, struct nova_inode_update *update,
	struct nova_inode_update *update_dir, int invalidate, u64 epoch_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 journal_tail;
	int cpu;
	timing_t trans_time;

	NOVA_START_TIMING(link_trans_t, trans_time);

	cpu = smp_processor_id();
	spin_lock(&sbi->journal_locks[cpu]);

	// If you change what's required to create a new inode, you need to
	// update this functions so the changes will be roll back on failure.
	journal_tail = nova_create_inode_transaction(sb, inode, dir, cpu,
						0, invalidate);

	if (invalidate) {
		pi->valid = 0;
		pi->delete_epoch_id = epoch_id;
	}
	nova_update_inode(sb, inode, pi, update);

	nova_update_inode(sb, dir, pidir, update_dir);

	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	spin_unlock(&sbi->journal_locks[cpu]);

	NOVA_END_TIMING(link_trans_t, trans_time);
}

static int nova_link(struct dentry *dest_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dest_dentry->d_inode;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode *pidir;
	struct nova_inode_update update_dir;
	struct nova_inode_update update;
	u64 old_linkc = 0;
	u64 epoch_id;
	int err = -ENOMEM;
	timing_t link_time;

	NOVA_START_TIMING(link_t, link_time);
	if (inode->i_nlink >= NOVA_LINK_MAX) {
		err = -EMLINK;
		goto out;
	}

	pidir = nova_get_inode(sb, dir);
	if (!pidir) {
		err = -EINVAL;
		goto out;
	}

	ihold(inode);
	epoch_id = nova_get_epoch_id(sb);

	nova_dbgv("%s: name %s, dest %s\n", __func__,
			dentry->d_name.name, dest_dentry->d_name.name);
	nova_dbgv("%s: inode %lu, dir %lu\n", __func__,
			inode->i_ino, dir->i_ino);

	update_dir.tail = 0;
	err = nova_add_dentry(dentry, inode->i_ino, 0, &update_dir, epoch_id);
	if (err) {
		iput(inode);
		goto out;
	}

	inode->i_ctime = current_time(inode);
	inc_nlink(inode);

	update.tail = 0;
	err = nova_append_link_change_entry(sb, pi, inode, &update,
						&old_linkc, epoch_id);
	if (err) {
		iput(inode);
		goto out;
	}

	d_instantiate(dentry, inode);
	nova_lite_transaction_for_time_and_link(sb, pi, pidir, inode, dir,
					&update, &update_dir, 0, epoch_id);

	nova_invalidate_link_change_entry(sb, old_linkc);

out:
	NOVA_END_TIMING(link_t, link_time);
	return err;
}

static int nova_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	int retval = -ENOMEM;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode *pidir;
	struct nova_inode_update update_dir;
	struct nova_inode_update update;
	u64 old_linkc = 0;
	u64 epoch_id;
	int invalidate = 0;
	timing_t unlink_time;

	NOVA_START_TIMING(unlink_t, unlink_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out;

	epoch_id = nova_get_epoch_id(sb);
	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %lu, dir %lu\n", __func__,
				inode->i_ino, dir->i_ino);

	update_dir.tail = 0;
	retval = nova_remove_dentry(dentry, 0, &update_dir, epoch_id);
	if (retval)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink == 1)
		invalidate = 1;

	if (inode->i_nlink)
		drop_nlink(inode);

	update.tail = 0;
	retval = nova_append_link_change_entry(sb, pi, inode, &update,
						&old_linkc, epoch_id);
	if (retval)
		goto out;

	nova_lite_transaction_for_time_and_link(sb, pi, pidir, inode, dir,
				&update, &update_dir, invalidate, epoch_id);

	nova_invalidate_link_change_entry(sb, old_linkc);
	nova_invalidate_dentries(sb, &update_dir);

	NOVA_END_TIMING(unlink_t, unlink_time);
	return 0;
out:
	nova_err(sb, "%s return %d\n", __func__, retval);
	NOVA_END_TIMING(unlink_t, unlink_time);
	return retval;
}

static int nova_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct nova_inode *pidir, *pi;
	struct nova_inode_info *si, *sidir;
	struct nova_inode_info_header *sih = NULL;
	struct nova_inode_update update;
	u64 pi_addr = 0;
	u64 ino;
	u64 epoch_id;
	int err = -EMLINK;
	timing_t mkdir_time;

	NOVA_START_TIMING(mkdir_t, mkdir_time);
	if (dir->i_nlink >= NOVA_LINK_MAX)
		goto out;

	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	epoch_id = nova_get_epoch_id(sb);
	nova_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu, link %d\n", __func__,
				ino, dir->i_ino, dir->i_nlink);

	update.tail = 0;
	err = nova_add_dentry(dentry, ino, 1, &update, epoch_id);
	if (err) {
		nova_dbg("failed to add dir entry\n");
		goto out_err;
	}

	inode = nova_new_vfs_inode(TYPE_MKDIR, dir, pi_addr, ino,
					S_IFDIR | mode, sb->s_blocksize,
					0, &dentry->d_name, epoch_id);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_err;
	}

	pi = nova_get_inode(sb, inode);
	err = nova_append_dir_init_entries(sb, pi, inode->i_ino, dir->i_ino,
					epoch_id);
	if (err < 0)
		goto out_err;

	/* Build the dir tree */
	si = NOVA_I(inode);
	sih = &si->header;
	nova_rebuild_dir_inode_tree(sb, pi, pi_addr, sih);

	pidir = nova_get_inode(sb, dir);
	sidir = NOVA_I(dir);
	sih = &si->header;
	dir->i_blocks = sih->i_blocks;
	inc_nlink(dir);
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
					&update);
out:
	NOVA_END_TIMING(mkdir_t, mkdir_time);
	return err;

out_err:
//	clear_nlink(inode);
	nova_err(sb, "%s return %d\n", __func__, err);
	goto out;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static int nova_empty_dir(struct inode *inode)
{
	struct super_block *sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *entry;
	unsigned long pos = 0;
	struct nova_dentry *entries[4];
	int nr_entries;
	int i;

	sb = inode->i_sb;
	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, 4);
	if (nr_entries > 2)
		return 0;

	for (i = 0; i < nr_entries; i++) {
		entry = entries[i];

		if (!is_dir_init_entry(sb, entry))
			return 0;
	}

	return 1;
}

static int nova_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct nova_dentry *de;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode), *pidir;
	struct nova_inode_update update_dir;
	struct nova_inode_update update;
	u64 old_linkc = 0;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	int err = -ENOTEMPTY;
	u64 epoch_id;
	timing_t rmdir_time;

	NOVA_START_TIMING(rmdir_t, rmdir_time);
	if (!inode)
		return -ENOENT;

	nova_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		return -EINVAL;

	if (nova_inode_by_name(dir, &dentry->d_name, &de) == 0)
		return -ENOENT;

	if (!nova_empty_dir(inode))
		return err;

	nova_dbgv("%s: inode %lu, dir %lu, link %d\n", __func__,
				inode->i_ino, dir->i_ino, dir->i_nlink);

	if (inode->i_nlink != 2)
		nova_dbg("empty directory %lu has nlink!=2 (%d), dir %lu",
				inode->i_ino, inode->i_nlink, dir->i_ino);

	epoch_id = nova_get_epoch_id(sb);

	update_dir.tail = 0;
	err = nova_remove_dentry(dentry, -1, &update_dir, epoch_id);
	if (err)
		goto end_rmdir;

	/*inode->i_version++; */
	clear_nlink(inode);
	inode->i_ctime = dir->i_ctime;

	if (dir->i_nlink)
		drop_nlink(dir);

	nova_delete_dir_tree(sb, sih);

	update.tail = 0;
	err = nova_append_link_change_entry(sb, pi, inode, &update,
						&old_linkc, epoch_id);
	if (err)
		goto end_rmdir;

	nova_lite_transaction_for_time_and_link(sb, pi, pidir, inode, dir,
					&update, &update_dir, 1, epoch_id);

	nova_invalidate_link_change_entry(sb, old_linkc);
	nova_invalidate_dentries(sb, &update_dir);

	NOVA_END_TIMING(rmdir_t, rmdir_time);
	return err;

end_rmdir:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(rmdir_t, rmdir_time);
	return err;
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
	.create		= nova_create,
	.lookup		= nova_lookup,
	.link		= nova_link,
	.unlink		= nova_unlink,
	.mkdir		= nova_mkdir,
	.rmdir		= nova_rmdir,
	.mknod		= nova_mknod,
};
