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


static inline int nova_copy_partial_block(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long index,
	size_t offset, size_t length, void *kmem)
{
	void *ptr;
	int rc = 0;
	unsigned long nvmm;

	nvmm = get_nvmm(sb, sih, entry, index);
	ptr = nova_get_block(sb, (nvmm << PAGE_SHIFT));

	if (ptr != NULL) {
		if (support_clwb)
			rc = memcpy_mcsafe(kmem + offset, ptr + offset,
						length);
		else
			memcpy_to_pmem_nocache(kmem + offset, ptr + offset,
						length);
	}

	/* TODO: If rc < 0, go to MCE data recovery. */
	return rc;
}

static inline int nova_handle_partial_block(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long index,
	size_t offset, size_t length, void *kmem)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (entry == NULL) {
		/* Fill zero */
		if (support_clwb)
			memset(kmem + offset, 0, length);
		else
			memcpy_to_pmem_nocache(kmem + offset,
					sbi->zeroed_page, length);
	} else {
		nova_copy_partial_block(sb, sih, entry, index,
					offset, length, kmem);

	}
	if (support_clwb)
		nova_flush_buffer(kmem + offset, length, 0);
	return 0;
}

/*
 * Fill the new start/end block from original blocks.
 * Do nothing if fully covered; copy if original blocks present;
 * Fill zero otherwise.
 */
int nova_handle_head_tail_blocks(struct super_block *sb,
	struct inode *inode, loff_t pos, size_t count, void *kmem)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	size_t offset, eblk_offset;
	unsigned long start_blk, end_blk, num_blocks;
	struct nova_file_write_entry *entry;
	timing_t partial_time;
	int ret = 0;

	NOVA_START_TIMING(partial_block_t, partial_time);
	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (nova_inode_blk_size(sih) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	nova_dbg_verbose("%s: %lu blocks\n", __func__, num_blocks);
	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway
	 */
	nova_dbg_verbose("%s: start offset %lu start blk %lu %p\n", __func__,
				offset, start_blk, kmem);
	if (offset != 0) {
		entry = nova_get_write_entry(sb, sih, start_blk);
		ret = nova_handle_partial_block(sb, sih, entry,
						start_blk, 0, offset, kmem);
		if (ret < 0)
			return ret;
	}

	kmem = (void *)((char *)kmem +
			((num_blocks - 1) << sb->s_blocksize_bits));
	eblk_offset = (pos + count) & (nova_inode_blk_size(sih) - 1);
	nova_dbg_verbose("%s: end offset %lu, end blk %lu %p\n", __func__,
				eblk_offset, end_blk, kmem);
	if (eblk_offset != 0) {
		entry = nova_get_write_entry(sb, sih, end_blk);

		ret = nova_handle_partial_block(sb, sih, entry, end_blk,
						eblk_offset,
						sb->s_blocksize - eblk_offset,
						kmem);
		if (ret < 0)
			return ret;
	}
	NOVA_END_TIMING(partial_block_t, partial_time);

	return ret;
}

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

int nova_cleanup_incomplete_write(struct super_block *sb,
	struct nova_inode_info_header *sih, struct list_head *head, int free)
{
	struct nova_file_write_item *entry_item, *temp;
	struct nova_file_write_entry *entry;
	unsigned long blocknr;

	list_for_each_entry_safe(entry_item, temp, head, list) {
		entry = &entry_item->entry;
		blocknr = nova_get_blocknr(sb, entry->block, sih->i_blk_type);
		nova_free_data_blocks(sb, sih, blocknr, entry->num_pages);

		if (free)
			nova_free_file_write_item(entry_item);
	}

	return 0;
}

void nova_init_file_write_item(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_item *item,
	u64 epoch_id, u64 pgoff, int num_pages, u64 blocknr, u32 time,
	u64 file_size)
{
	struct nova_file_write_entry *entry = &item->entry;

	INIT_LIST_HEAD(&item->list);
	memset(entry, 0, sizeof(struct nova_file_write_entry));
	entry->entry_type = FILE_WRITE;
	entry->reassigned = 0;
	entry->epoch_id = epoch_id;
	entry->trans_id = sih->trans_id;
	entry->pgoff = cpu_to_le64(pgoff);
	entry->num_pages = cpu_to_le32(num_pages);
	entry->invalid_pages = 0;
	entry->block = cpu_to_le64(nova_get_block_off(sb, blocknr,
							sih->i_blk_type));
	entry->mtime = cpu_to_le32(time);

	entry->size = file_size;
}
