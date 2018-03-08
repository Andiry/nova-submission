/*
 * BRIEF DESCRIPTION
 *
 * Log methods
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

#include "nova.h"
#include "inode.h"
#include "log.h"

/* Coalesce log pages to a singly linked list */
static int nova_coalesce_log_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long first_blocknr,
	unsigned long num_pages)
{
	unsigned long next_blocknr;
	u64 curr_block, next_page;
	struct nova_inode_log_page *curr_page;
	int i;

	if (prev_blocknr) {
		/* Link prev block and newly allocated head block */
		curr_block = nova_get_block_off(sb, prev_blocknr,
						NOVA_BLOCK_TYPE_4K);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		next_page = nova_get_block_off(sb, first_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
	}

	next_blocknr = first_blocknr + 1;
	curr_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);
	curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
	for (i = 0; i < num_pages - 1; i++) {
		next_page = nova_get_block_off(sb, next_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_set_page_num_entries(sb, curr_page, 0, 0);
		nova_set_page_invalid_entries(sb, curr_page, 0, 0);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
		curr_page++;
		next_blocknr++;
	}

	/* Last page */
	nova_set_page_num_entries(sb, curr_page, 0, 0);
	nova_set_page_invalid_entries(sb, curr_page, 0, 0);
	nova_set_next_page_address(sb, curr_page, 0, 1);
	return 0;
}

/* Log block resides in NVMM */
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block, int cpuid, enum nova_alloc_direction from_tail)
{
	unsigned long new_inode_blocknr;
	unsigned long first_blocknr;
	unsigned long prev_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = nova_new_log_blocks(sb, sih, &new_inode_blocknr,
			num_pages, ALLOC_NO_INIT, cpuid, from_tail);

	if (allocated <= 0) {
		nova_err(sb, "ERROR: no inode log page available: %d %d\n",
			num_pages, allocated);
		return allocated;
	}
	ret_pages += allocated;
	num_pages -= allocated;
	nova_dbg_verbose("Pi %lu: Alloc %d log blocks @ 0x%lx\n",
			sih->ino, allocated, new_inode_blocknr);

	/* Coalesce the pages */
	nova_coalesce_log_pages(sb, 0, new_inode_blocknr, allocated);
	first_blocknr = new_inode_blocknr;
	prev_blocknr = new_inode_blocknr + allocated - 1;

	/* Allocate remaining pages */
	while (num_pages) {
		allocated = nova_new_log_blocks(sb, sih,
					&new_inode_blocknr, num_pages,
					ALLOC_NO_INIT, cpuid, from_tail);

		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
					allocated, new_inode_blocknr);
		if (allocated <= 0) {
			nova_dbg("%s: no inode log page available: %lu %d\n",
				__func__, num_pages, allocated);
			/* Return whatever we have */
			break;
		}
		ret_pages += allocated;
		num_pages -= allocated;
		nova_coalesce_log_pages(sb, prev_blocknr, new_inode_blocknr,
						allocated);
		prev_blocknr = new_inode_blocknr + allocated - 1;
	}

	*new_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);

	return ret_pages;
}

static int nova_initialize_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	int log_id)
{
	u64 new_block;
	int allocated;

	allocated = nova_allocate_inode_log_pages(sb, sih,
					1, &new_block, ANY_CPU,
					log_id == MAIN_LOG ? 0 : 1);
	if (allocated != 1) {
		nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
		return -ENOSPC;
	}

	pi->log_tail = new_block;
	nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
	pi->log_head = new_block;
	sih->log_head = sih->log_tail = new_block;
	sih->log_pages = 1;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	return 0;
}

/*
 * Extend the log.  If the log is less than EXTEND_THRESHOLD pages, double its
 * allocated size.  Otherwise, increase by EXTEND_THRESHOLD. Then, do GC.
 */
static u64 nova_extend_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	u64 new_block = 0;
	int allocated;
	unsigned long num_pages;
	int ret;

	nova_dbgv("%s: inode %lu, curr 0x%llx\n", __func__, sih->ino, curr_p);

	if (curr_p == 0) {
		ret = nova_initialize_inode_log(sb, pi, sih, MAIN_LOG);
		if (ret)
			return 0;

		return sih->log_head;
	}

	num_pages = sih->log_pages >= EXTEND_THRESHOLD ?
				EXTEND_THRESHOLD : sih->log_pages;

	allocated = nova_allocate_inode_log_pages(sb, sih,
					num_pages, &new_block, ANY_CPU, 0);
	nova_dbg_verbose("Link block %llu to block %llu\n",
					curr_p >> PAGE_SHIFT,
					new_block >> PAGE_SHIFT);
	if (allocated <= 0) {
		nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
		nova_dbg("curr_p 0x%llx, %lu pages\n", curr_p,
					sih->log_pages);
		return 0;
	}

	/* Perform GC */
	return new_block;
}

/* For thorough GC, simply append one more page */
static u64 nova_append_one_log_page(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	struct nova_inode_log_page *curr_page;
	u64 new_block;
	u64 curr_block;
	int allocated;

	allocated = nova_allocate_inode_log_pages(sb, sih, 1, &new_block,
							ANY_CPU, 0);
	if (allocated != 1) {
		nova_err(sb, "%s: ERROR: no inode log page available\n",
				__func__);
		return 0;
	}

	if (curr_p == 0) {
		curr_p = new_block;
	} else {
		/* Link prev block and newly allocated head block */
		curr_block = BLOCK_OFF(curr_p);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		nova_set_next_page_address(sb, curr_page, new_block, 1);
	}

	return curr_p;
}

/* Get the append location. Extent the log if needed. */
u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended)
{
	u64 curr_p;

	if (tail)
		curr_p = tail;
	else
		curr_p = sih->log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		if (is_last_entry(curr_p, size)) {
			nova_set_next_page_flag(sb, curr_p);
		}

		/* Alternate log should not go here */
		if (log_id != MAIN_LOG)
			return 0;

		if (thorough_gc == 0) {
			curr_p = nova_extend_inode_log(sb, pi, sih, curr_p);
		} else {
			curr_p = nova_append_one_log_page(sb, sih, curr_p);
			/* For thorough GC */
			*extended = 1;
		}

		if (curr_p == 0)
			return 0;
	}

	if (is_last_entry(curr_p, size)) {
		nova_set_next_page_flag(sb, curr_p);
		curr_p = next_log_page(sb, curr_p);
	}

	return curr_p;
}

int nova_free_contiguous_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 head)
{
	unsigned long blocknr, start_blocknr = 0;
	u64 curr_block = head;
	u8 btype = sih->i_blk_type;
	int num_free = 0;
	int freed = 0;

	while (curr_block > 0) {
		if (ENTRY_LOC(curr_block)) {
			nova_dbg("%s: ERROR: invalid block %llu\n",
					__func__, curr_block);
			break;
		}

		blocknr = nova_get_blocknr(sb, le64_to_cpu(curr_block),
				    btype);
		nova_dbg_verbose("%s: free page %llu\n", __func__, curr_block);
		curr_block = next_log_page(sb, curr_block);

		if (start_blocknr == 0) {
			start_blocknr = blocknr;
			num_free = 1;
		} else {
			if (blocknr == start_blocknr + num_free) {
				num_free++;
			} else {
				/* A new start */
				nova_free_log_blocks(sb, sih, start_blocknr,
							num_free);
				freed += num_free;
				start_blocknr = blocknr;
				num_free = 1;
			}
		}
	}
	if (start_blocknr) {
		nova_free_log_blocks(sb, sih, start_blocknr, num_free);
		freed += num_free;
	}

	return freed;
}

int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih)
{
	int freed = 0;
	timing_t free_time;

	if (sih->log_head == 0 || sih->log_tail == 0)
		return 0;

	NOVA_START_TIMING(free_inode_log_t, free_time);

	/* The inode is invalid now, no need to fence */
	if (pi) {
		pi->log_head = pi->log_tail = 0;
		nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	}

	freed = nova_free_contiguous_log_blocks(sb, sih, sih->log_head);

	NOVA_END_TIMING(free_inode_log_t, free_time);
	return 0;
}
