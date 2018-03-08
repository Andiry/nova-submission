/*
 * NOVA Recovery routines.
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
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include "nova.h"
#include "super.h"
#include "inode.h"

void nova_init_header(struct super_block *sb,
	struct nova_inode_info_header *sih, u16 i_mode)
{
	sih->log_pages = 0;
	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->valid_entries = 0;
	sih->num_entries = 0;
	sih->last_setattr = 0;
	sih->last_link_change = 0;
	sih->last_dentry = 0;
	sih->trans_id = 0;
	sih->log_head = 0;
	sih->log_tail = 0;
	sih->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	init_rwsem(&sih->i_sem);
}

static u64 nova_append_range_node_entry(struct super_block *sb,
	struct nova_range_node *curr, u64 tail, unsigned long cpuid)
{
	u64 curr_p;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	struct nova_range_node_lowhigh *entry;

	curr_p = tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		nova_dbg("%s: inode log reaches end?\n", __func__);
		goto out;
	}

	if (is_last_entry(curr_p, size))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct nova_range_node_lowhigh *)nova_get_block(sb, curr_p);
	entry->range_low = cpu_to_le64(curr->range_low);
	if (cpuid)
		entry->range_low |= cpu_to_le64(cpuid << 56);
	entry->range_high = cpu_to_le64(curr->range_high);
	nova_dbgv("append entry block low 0x%lx, high 0x%lx\n",
			curr->range_low, curr->range_high);

	nova_flush_buffer(entry, sizeof(struct nova_range_node_lowhigh), 0);
out:
	return curr_p;
}

static u64 nova_save_range_nodes_to_log(struct super_block *sb,
	struct rb_root *tree, u64 temp_tail, unsigned long cpuid)
{
	struct nova_range_node *curr;
	struct rb_node *temp;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_entry = 0;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		curr_entry = nova_append_range_node_entry(sb, curr,
						temp_tail, cpuid);
		temp_tail = curr_entry + size;
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		nova_free_range_node(curr);
	}

	return temp_tail;
}

static u64 nova_save_free_list_blocknodes(struct super_block *sb, int cpu,
	u64 temp_tail)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	temp_tail = nova_save_range_nodes_to_log(sb,
				&free_list->block_free_tree, temp_tail, 0);
	return temp_tail;
}

void nova_save_inode_list_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_inode_info_header sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long num_blocks;
	unsigned long num_nodes = 0;
	struct inode_map *inode_map;
	unsigned long i;
	u64 temp_tail;
	u64 new_block;
	int allocated;

	sih.ino = NOVA_INODELIST_INO;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	sih.i_blocks = 0;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		num_nodes += inode_map->num_range_node_inode;
	}

	num_blocks = num_nodes / RANGENODE_PER_PAGE;
	if (num_nodes % RANGENODE_PER_PAGE)
		num_blocks++;

	allocated = nova_allocate_inode_log_pages(sb, &sih, num_blocks,
						&new_block, ANY_CPU, 0);
	if (allocated != num_blocks) {
		nova_dbg("Error saving inode list: %d\n", allocated);
		return;
	}

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		temp_tail = nova_save_range_nodes_to_log(sb,
				&inode_map->inode_inuse_tree, temp_tail, i);
	}

	pi->log_head = new_block;
	nova_update_tail(pi, temp_tail);
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	nova_dbg("%s: %lu inode nodes, pi head 0x%llx, tail 0x%llx\n",
		__func__, num_nodes, pi->log_head, pi->log_tail);
}

void nova_save_blocknode_mappings_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_inode_info_header sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long num_blocknode = 0;
	unsigned long num_pages;
	int allocated;
	u64 new_block = 0;
	u64 temp_tail;
	int i;

	sih.ino = NOVA_BLOCKNODE_INO;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	/* Allocate log pages before save blocknode mappings */
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		num_blocknode += free_list->num_blocknode;
		nova_dbgv("%s: free list %d: %lu nodes\n", __func__,
				i, free_list->num_blocknode);
	}

	num_pages = num_blocknode / RANGENODE_PER_PAGE;
	if (num_blocknode % RANGENODE_PER_PAGE)
		num_pages++;

	allocated = nova_allocate_inode_log_pages(sb, &sih, num_pages,
						&new_block, ANY_CPU, 0);
	if (allocated != num_pages) {
		nova_dbg("Error saving blocknode mappings: %d\n", allocated);
		return;
	}

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++)
		temp_tail = nova_save_free_list_blocknodes(sb, i, temp_tail);

	/* Finally update log head and tail */
	pi->log_head = new_block;
	nova_update_tail(pi, temp_tail);
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	nova_dbg("%s: %lu blocknodes, %lu log pages, pi head 0x%llx, tail 0x%llx\n",
		  __func__, num_blocknode, num_pages,
		  pi->log_head, pi->log_tail);
}

