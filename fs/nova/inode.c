/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
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
#include <linux/aio.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "nova.h"
#include "inode.h"

unsigned int blk_type_to_shift[NOVA_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[NOVA_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

int nova_init_inode_inuse_list(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *range_node;
	struct inode_map *inode_map;
	unsigned long range_high;
	int i;
	int ret;

	sbi->s_inodes_used_count = NOVA_NORMAL_INODE_START;

	range_high = NOVA_NORMAL_INODE_START / sbi->cpus;
	if (NOVA_NORMAL_INODE_START % sbi->cpus)
		range_high++;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		range_node = nova_alloc_inode_node(sb);
		if (range_node == NULL)
			/* FIXME: free allocated memories */
			return -ENOMEM;

		range_node->range_low = 0;
		range_node->range_high = range_high;
		ret = nova_insert_inodetree(sbi, range_node, i);
		if (ret) {
			nova_err(sb, "%s failed\n", __func__);
			nova_free_inode_node(sb, range_node);
			return ret;
		}
		inode_map->num_range_node_inode = 1;
		inode_map->first_inode_range = range_node;
	}

	return 0;
}

static int nova_alloc_inode_table(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_table *inode_table;
	unsigned long blocknr;
	u64 block;
	int allocated;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		inode_table = nova_get_inode_table(sb, i);
		if (!inode_table)
			return -EINVAL;

		allocated = nova_new_log_blocks(sb, sih, &blocknr, 1,
				ALLOC_INIT_ZERO, i, ALLOC_FROM_HEAD);

		nova_dbgv("%s: allocate log @ 0x%lx\n", __func__,
							blocknr);
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_2M);
		inode_table->log_head = block;
		nova_flush_buffer(inode_table, CACHELINE_SIZE, 0);
	}

	return 0;
}

int nova_init_inode_table(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODETABLE_INO);
	struct nova_inode_info_header sih;
	int ret = 0;

	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;
	pi->nova_ino = NOVA_INODETABLE_INO;

	pi->i_blk_type = NOVA_BLOCK_TYPE_2M;

	sih.ino = NOVA_INODETABLE_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_2M;

	ret = nova_alloc_inode_table(sb, &sih);

	PERSISTENT_BARRIER();
	return ret;
}

void nova_set_inode_flags(struct inode *inode, struct nova_inode *pi,
	unsigned int flags)
{
	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;
}

/* copy persistent state to struct inode */
static int nova_read_inode(struct super_block *sb, struct inode *inode,
	u64 pi_addr)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode *pi, fake_pi;
	struct nova_inode_info_header *sih = &si->header;
	int ret = -EIO;
	unsigned long ino;

	ret = nova_get_reference(sb, pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%llx failed\n",
				__func__, pi_addr);
		goto bad_inode;
	}

	inode->i_mode = sih->i_mode;
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
//	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	nova_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = inode->i_ino;

	/* check if the inode is active. */
	if (inode->i_mode == 0 || pi->deleted == 1) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = sih->i_blocks;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		break;
	case S_IFDIR:
		break;
	case S_IFLNK:
		break;
	default:
		init_special_inode(inode, inode->i_mode,
				   le32_to_cpu(pi->dev.rdev));
		break;
	}

	/* Update size and time after rebuild the tree */
	inode->i_size = le64_to_cpu(sih->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

/*
 * Get the address in PMEM of an inode by inode number.  Allocate additional
 * block to store additional inodes if necessary.
 */
int nova_get_inode_address(struct super_block *sb, u64 ino,
	u64 *pi_addr, int extendable)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header sih;
	struct inode_table *inode_table;
	unsigned int data_bits;
	unsigned int num_inodes_bits;
	u64 curr;
	unsigned int superpage_count;
	u64 internal_ino;
	int cpuid;
	int extended = 0;
	unsigned int index;
	unsigned int i = 0;
	unsigned long blocknr;
	unsigned long curr_addr;
	int allocated;

	if (ino < NOVA_NORMAL_INODE_START) {
		*pi_addr = nova_get_reserved_inode_addr(sb, ino);
		return 0;
	}

	sih.ino = NOVA_INODETABLE_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_2M;
	data_bits = blk_type_to_shift[sih.i_blk_type];
	num_inodes_bits = data_bits - NOVA_INODE_BITS;

	cpuid = ino % sbi->cpus;
	internal_ino = ino / sbi->cpus;

	inode_table = nova_get_inode_table(sb, cpuid);
	superpage_count = internal_ino >> num_inodes_bits;
	index = internal_ino & ((1 << num_inodes_bits) - 1);

	curr = inode_table->log_head;
	if (curr == 0)
		return -EINVAL;

	for (i = 0; i < superpage_count; i++) {
		if (curr == 0)
			return -EINVAL;

		curr_addr = (unsigned long)nova_get_block(sb, curr);
		/* Next page pointer in the last 8 bytes of the superpage */
		curr_addr += nova_inode_blk_size(&sih) - 8;
		curr = *(u64 *)(curr_addr);

		if (curr == 0) {
			if (extendable == 0)
				return -EINVAL;

			extended = 1;

			allocated = nova_new_log_blocks(sb, &sih, &blocknr,
				1, ALLOC_INIT_ZERO, cpuid, ALLOC_FROM_HEAD);

			if (allocated != 1)
				return allocated;

			curr = nova_get_block_off(sb, blocknr,
						NOVA_BLOCK_TYPE_2M);
			*(u64 *)(curr_addr) = curr;
			nova_flush_buffer((void *)curr_addr,
						NOVA_INODE_SIZE, 1);
		}
	}

	*pi_addr = curr + index * NOVA_INODE_SIZE;

	return 0;
}

struct inode *nova_iget(struct super_block *sb, unsigned long ino)
{
	struct nova_inode_info *si;
	struct inode *inode;
	u64 pi_addr;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	si = NOVA_I(inode);

	nova_dbgv("%s: inode %lu\n", __func__, ino);

	err = nova_get_inode_address(sb, ino, &pi_addr, 0);
	if (err) {
		nova_dbg("%s: get inode %lu address failed %d\n",
			 __func__, ino, err);
		goto fail;
	}

	if (pi_addr == 0) {
		nova_dbg("%s: failed to get pi_addr for inode %lu\n",
			 __func__, ino);
		err = -EACCES;
		goto fail;
	}

	err = nova_rebuild_inode(sb, si, ino, pi_addr, 1);
	if (err) {
		nova_dbg("%s: failed to rebuild inode %lu\n", __func__, ino);
		goto fail;
	}

	err = nova_read_inode(sb, inode, pi_addr);
	if (unlikely(err)) {
		nova_dbg("%s: failed to read inode %lu\n", __func__, ino);
		goto fail;

	}

	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

inline int nova_insert_inodetree(struct nova_sb_info *sbi,
	struct nova_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = nova_insert_range_node(tree, new_node);
	if (ret)
		nova_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

static inline int nova_search_inodetree(struct nova_sb_info *sbi,
	unsigned long ino, struct nova_range_node **ret_node)
{
	struct rb_root *tree;
	unsigned long internal_ino;
	int cpu;

	cpu = ino % sbi->cpus;
	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	internal_ino = ino / sbi->cpus;
	return nova_find_range_node(sbi, tree, internal_ino, ret_node);
}

int nova_alloc_unused_inode(struct super_block *sb, int cpuid,
	unsigned long *ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *i, *next_i;
	struct rb_node *temp, *next;
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	inode_map = &sbi->inode_maps[cpuid];
	i = inode_map->first_inode_range;
	NOVA_ASSERT(i);

	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = MAX_INODE;
	} else {
		next_i = container_of(next, struct nova_range_node, node);
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		/* Fill the gap completely */
		i->range_high = next_i->range_high;
		rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
		nova_free_inode_node(sb, next_i);
		inode_map->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		/* Aligns to left */
		i->range_high = new_ino;
	} else {
		nova_dbg("%s: ERROR: new ino %lu, next low %lu\n", __func__,
			new_ino, next_range_low);
		return -ENOSPC;
	}

	*ino = new_ino * sbi->cpus + cpuid;
	sbi->s_inodes_used_count++;
	inode_map->allocated++;

	nova_dbg_verbose("Alloc ino %lu\n", *ino);
	return 0;
}

int nova_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *i = NULL;
	struct nova_range_node *curr_node;
	int found = 0;
	int cpuid = ino % sbi->cpus;
	unsigned long internal_ino = ino / sbi->cpus;
	int ret = 0;

	nova_dbg_verbose("Free inuse ino: %lu\n", ino);
	inode_map = &sbi->inode_maps[cpuid];

	mutex_lock(&inode_map->inode_table_mutex);
	found = nova_search_inodetree(sbi, ino, &i);
	if (!found) {
		nova_dbg("%s ERROR: ino %lu not found\n", __func__, ino);
		mutex_unlock(&inode_map->inode_table_mutex);
		return -EINVAL;
	}

	if ((internal_ino == i->range_low) && (internal_ino == i->range_high)) {
		/* fits entire node */
		rb_erase(&i->node, &inode_map->inode_inuse_tree);
		nova_free_inode_node(sb, i);
		inode_map->num_range_node_inode--;
		goto block_found;
	}
	if ((internal_ino == i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns left */
		i->range_low = internal_ino + 1;
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino == i->range_high)) {
		/* Aligns right */
		i->range_high = internal_ino - 1;
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns somewhere in the middle */
		curr_node = nova_alloc_inode_node(sb);
		NOVA_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block */
			goto block_found;
		}
		curr_node->range_low = internal_ino + 1;
		curr_node->range_high = i->range_high;

		i->range_high = internal_ino - 1;

		ret = nova_insert_inodetree(sbi, curr_node, cpuid);
		if (ret) {
			nova_free_inode_node(sb, curr_node);
			goto err;
		}
		inode_map->num_range_node_inode++;
		goto block_found;
	}

err:
	nova_error_mng(sb, "Unable to free inode %lu\n", ino);
	nova_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->range_low, i->range_high);
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;

block_found:
	sbi->s_inodes_used_count--;
	inode_map->freed++;
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}

