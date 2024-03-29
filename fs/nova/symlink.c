/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include "nova.h"
#include "inode.h"

int nova_block_symlink(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, const char *symname, int len, u64 epoch_id)
{
	struct nova_file_write_item entry_item;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct nova_inode_update update;
	unsigned long name_blocknr = 0;
	int allocated;
	u64 block;
	char *blockp;
	u32 time;
	int ret;

	update.tail = sih->log_tail;

	allocated = nova_new_data_blocks(sb, sih, &name_blocknr, 0, 1,
				 ALLOC_INIT_ZERO, ANY_CPU, ALLOC_FROM_TAIL);
	if (allocated != 1 || name_blocknr == 0) {
		ret = allocated;
		return ret;
	}

	/* First copy name to name block */
	block = nova_get_block_off(sb, name_blocknr, NOVA_BLOCK_TYPE_4K);
	blockp = (char *)nova_get_block(sb, block);

	memcpy_to_pmem_nocache(blockp, symname, len);
	blockp[len] = '\0';

	/* Apply a write entry to the log page */
	time = current_time(inode).tv_sec;
	nova_init_file_write_item(sb, sih, &entry_item, epoch_id, 0, 1,
					name_blocknr, time, len + 1);

	sih_lock(sih);
	ret = nova_append_file_write_entry(sb, pi, inode, &entry_item, &update);
	if (ret) {
		nova_dbg("%s: append file write entry failed %d\n",
					__func__, ret);
		nova_free_data_blocks(sb, sih, name_blocknr, 1);
		return ret;
	}

	nova_update_inode(sb, inode, pi, &update);
	sih->trans_id++;
	sih_unlock(sih);

	return 0;
}

/* FIXME: Temporary workaround */
static int nova_readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);

	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned int) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

static int nova_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct nova_file_write_entry *entry;
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	char *blockp;

	entry = (struct nova_file_write_entry *)nova_get_block(sb,
							sih->log_head);

	blockp = (char *)nova_get_block(sb, BLOCK_OFF(entry->block));

	return nova_readlink_copy(buffer, buflen, blockp);
}

static const char *nova_get_link(struct dentry *dentry, struct inode *inode,
	struct delayed_call *done)
{
	struct nova_file_write_entry *entry;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	char *blockp;

	entry = (struct nova_file_write_entry *)nova_get_block(sb,
							sih->log_head);

	blockp = (char *)nova_get_block(sb, BLOCK_OFF(entry->block));

	return blockp;
}

const struct inode_operations nova_symlink_inode_operations = {
	.readlink	= nova_readlink,
	.get_link	= nova_get_link,
	.setattr	= nova_notify_change,
};
