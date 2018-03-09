/*
 * BRIEF DESCRIPTION
 *
 * DAX file operations.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/buffer_head.h>
#include <linux/cpufeature.h>
#include <asm/pgtable.h>
#include <linux/version.h>
#include "nova.h"
#include "inode.h"


static int nova_reassign_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 begin_tail, u64 end_tail)
{
	void *addr;
	struct nova_file_write_entry *entry;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	while (curr_p && curr_p != end_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
				__func__, sih->ino);
			return -EINVAL;
		}

		addr = (void *) nova_get_block(sb, curr_p);
		entry = (struct nova_file_write_entry *) addr;

		if (nova_get_entry_type(entry) != FILE_WRITE) {
			nova_dbg("%s: entry type is not write? %d\n",
				__func__, nova_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}

		nova_assign_write_entry(sb, sih, entry, true);
		curr_p += entry_size;
	}

	return 0;
}

int nova_commit_writes_to_log(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct list_head *head, unsigned long new_blocks,
	int free)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_item *entry_item, *temp;
	struct nova_inode_update update;
	unsigned int data_bits;
	u64 begin_tail = 0;
	int ret = 0;

	if (list_empty(head))
		return 0;

	update.tail = 0;

	list_for_each_entry(entry_item, head, list) {
		ret = nova_append_file_write_entry(sb, pi, inode,
					entry_item, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n", __func__);
			return -ENOSPC;
		}

		if (begin_tail == 0)
			begin_tail = update.curr_entry;
	}

	/* Update file tree */
	ret = nova_reassign_file_tree(sb, sih, begin_tail, update.tail);
	if (ret < 0) {
		/* FIXME: Need to rebuild the tree */
		return ret;
	}

	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (new_blocks << (data_bits - sb->s_blocksize_bits));

	inode->i_blocks = sih->i_blocks;

	nova_update_inode(sb, inode, pi, &update);
	NOVA_STATS_ADD(inplace_new_blocks, 1);

	sih->trans_id++;

	if (free) {
		list_for_each_entry_safe(entry_item, temp, head, list)
			nova_free_file_write_item(entry_item);
	}

	return ret;
}
