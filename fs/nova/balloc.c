/*
 * NOVA persistent memory management
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
#include "nova.h"
#include "inode.h"

int nova_alloc_block_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = kcalloc(sbi->cpus, sizeof(struct free_list),
				  GFP_KERNEL);

	if (!sbi->free_lists)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		free_list->block_free_tree = RB_ROOT;
		spin_lock_init(&free_list->s_lock);
		free_list->index = i;
	}

	return 0;
}

void nova_delete_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	/* Each tree is freed in save_blocknode_mappings */
	kfree(sbi->free_lists);
	sbi->free_lists = NULL;
}

// Initialize a free list.  Each CPU gets an equal share of the block space to
// manage.
static void nova_init_free_list(struct super_block *sb,
	struct free_list *free_list, int index)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long per_list_blocks;

	per_list_blocks = sbi->num_blocks / sbi->cpus;

	free_list->block_start = per_list_blocks * index;
	free_list->block_end = free_list->block_start +
					per_list_blocks - 1;
	if (index == 0)
		free_list->block_start += sbi->head_reserved_blocks;
	if (index == sbi->cpus - 1)
		free_list->block_end -= sbi->tail_reserved_blocks;
}

inline struct nova_range_node *nova_alloc_blocknode(struct super_block *sb)
{
	return nova_alloc_range_node(sb);
}

inline void nova_free_blocknode(struct super_block *sb,
	struct nova_range_node *node)
{
	nova_free_range_node(node);
}

void nova_init_blockmap(struct super_block *sb, int recovery)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct rb_root *tree;
	struct nova_range_node *blknode;
	struct free_list *free_list;
	int i;
	int ret;

	/* Divide the block range among per-CPU free lists */
	sbi->per_list_blocks = sbi->num_blocks / sbi->cpus;
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		nova_init_free_list(sb, free_list, i);

		/* For recovery, update these fields later */
		if (recovery == 0) {
			free_list->num_free_blocks = free_list->block_end -
						free_list->block_start + 1;

			blknode = nova_alloc_blocknode(sb);
			if (blknode == NULL)
				return;
			blknode->range_low = free_list->block_start;
			blknode->range_high = free_list->block_end;
			ret = nova_insert_blocktree(sbi, tree, blknode);
			if (ret) {
				nova_err(sb, "%s failed\n", __func__);
				nova_free_blocknode(sb, blknode);
				return;
			}
			free_list->first_node = blknode;
			free_list->last_node = blknode;
			free_list->num_blocknode = 1;
		}

		nova_dbgv("%s: free list %d: block start %lu, end %lu, %lu free blocks\n",
			  __func__, i,
			  free_list->block_start,
			  free_list->block_end,
			  free_list->num_free_blocks);
	}
}

static inline int nova_rbtree_compare_rangenode(struct nova_range_node *curr,
	unsigned long range_low)
{
	if (range_low < curr->range_low)
		return -1;
	if (range_low > curr->range_high)
		return 1;

	return 0;
}

int nova_find_range_node(struct nova_sb_info *sbi,
	struct rb_root *tree, unsigned long range_low,
	struct nova_range_node **ret_node)
{
	struct nova_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		compVal = nova_rbtree_compare_rangenode(curr, range_low);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}


int nova_insert_range_node(struct rb_root *tree,
	struct nova_range_node *new_node)
{
	struct nova_range_node *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct nova_range_node, node);
		compVal = nova_rbtree_compare_rangenode(curr,
					new_node->range_low);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			nova_dbg("%s: entry %lu - %lu already exists: %lu - %lu\n",
				 __func__, new_node->range_low,
				new_node->range_high, curr->range_low,
				curr->range_high);
			return -EINVAL;
		}
	}

	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	return 0;
}

inline int nova_insert_blocktree(struct nova_sb_info *sbi,
	struct rb_root *tree, struct nova_range_node *new_node)
{
	int ret;

	ret = nova_insert_range_node(tree, new_node);
	if (ret)
		nova_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

/* We do not take locks so it's inaccurate */
unsigned long nova_count_free_blocks(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		num_free_blocks += free_list->num_free_blocks;
	}

	return num_free_blocks;
}


