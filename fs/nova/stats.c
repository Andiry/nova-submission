/*
 * NOVA File System statistics
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
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

#include "nova.h"

const char *Timingstring[TIMING_NUM] = {
	/* Init */
	"================ Initialization ================",
	"init",
	"mount",
	"ioremap",
	"new_init",
	"recovery",

	/* Namei operations */
	"============= Directory operations =============",
	"create",
	"lookup",
	"link",
	"unlink",
	"symlink",
	"mkdir",
	"rmdir",
	"mknod",
	"rename",
	"readdir",
	"add_dentry",
	"remove_dentry",
	"setattr",
	"setsize",

	/* I/O operations */
	"================ I/O operations ================",
	"dax_read",
	"cow_write",
	"inplace_write",
	"copy_to_nvmm",
	"dax_get_block",
	"read_iter",
	"write_iter",

	/* Memory operations */
	"============== Memory operations ===============",
	"memcpy_read_nvmm",
	"memcpy_write_nvmm",
	"memcpy_write_back_to_nvmm",
	"handle_partial_block",

	/* Memory management */
	"============== Memory management ===============",
	"alloc_blocks",
	"new_data_blocks",
	"new_log_blocks",
	"free_blocks",
	"free_data_blocks",
	"free_log_blocks",

	/* Transaction */
	"================= Transaction ==================",
	"transaction_new_inode",
	"transaction_link_change",
	"update_tail",

	/* Logging */
	"============= Logging operations ===============",
	"append_dir_entry",
	"append_file_entry",
	"append_link_change",
	"append_setattr",
	"inplace_update_entry",

	/* Tree */
	"=============== Tree operations ================",
	"checking_entry",
	"assign_blocks",

	/* GC */
	"============= Garbage collection ===============",
	"log_fast_gc",
	"log_thorough_gc",
	"check_invalid_log",

	/* Others */
	"================ Miscellaneous =================",
	"find_cache_page",
	"fsync",
	"write_pages",
	"fallocate",
	"direct_IO",
	"free_old_entry",
	"delete_file_tree",
	"delete_dir_tree",
	"new_vfs_inode",
	"new_nova_inode",
	"free_inode",
	"free_inode_log",
	"evict_inode",

	/* Mmap */
	"=============== MMap operations ================",
	"mmap_page_fault",
	"mmap_pmd_fault",
	"mmap_pfn_mkwrite",

	/* Rebuild */
	"=================== Rebuild ====================",
	"rebuild_dir",
	"rebuild_file",
};

u64 Timingstats[TIMING_NUM];
DEFINE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
u64 Countstats[TIMING_NUM];
DEFINE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);
u64 IOstats[STATS_NUM];
DEFINE_PER_CPU(u64[STATS_NUM], IOstats_percpu);

static void nova_print_alloc_stats(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long alloc_log_count = 0;
	unsigned long alloc_log_pages = 0;
	unsigned long alloc_data_count = 0;
	unsigned long alloc_data_pages = 0;
	unsigned long free_log_count = 0;
	unsigned long freed_log_pages = 0;
	unsigned long free_data_count = 0;
	unsigned long freed_data_pages = 0;
	int i;

	nova_info("=========== NOVA allocation stats ===========\n");
	nova_info("Alloc %llu, alloc steps %llu, average %llu\n",
		Countstats[new_data_blocks_t], IOstats[alloc_steps],
		Countstats[new_data_blocks_t] ?
			IOstats[alloc_steps] / Countstats[new_data_blocks_t]
			: 0);
	nova_info("Free %llu\n", Countstats[free_data_t]);
	nova_info("Fast GC %llu, check pages %llu, free pages %llu, average %llu\n",
		Countstats[fast_gc_t], IOstats[fast_checked_pages],
		IOstats[fast_gc_pages], Countstats[fast_gc_t] ?
			IOstats[fast_gc_pages] / Countstats[fast_gc_t] : 0);
	nova_info("Thorough GC %llu, checked pages %llu, free pages %llu, average %llu\n",
		Countstats[thorough_gc_t],
		IOstats[thorough_checked_pages], IOstats[thorough_gc_pages],
		Countstats[thorough_gc_t] ?
			IOstats[thorough_gc_pages] / Countstats[thorough_gc_t]
			: 0);

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		alloc_log_count += free_list->alloc_log_count;
		alloc_log_pages += free_list->alloc_log_pages;
		alloc_data_count += free_list->alloc_data_count;
		alloc_data_pages += free_list->alloc_data_pages;
		free_log_count += free_list->free_log_count;
		freed_log_pages += free_list->freed_log_pages;
		free_data_count += free_list->free_data_count;
		freed_data_pages += free_list->freed_data_pages;
	}

	nova_info("alloc log count %lu, allocated log pages %lu, "
		"alloc data count %lu, allocated data pages %lu, "
		"free log count %lu, freed log pages %lu, "
		"free data count %lu, freed data pages %lu\n",
		alloc_log_count, alloc_log_pages,
		alloc_data_count, alloc_data_pages,
		free_log_count, freed_log_pages,
		free_data_count, freed_data_pages);
}

static void nova_print_IO_stats(struct super_block *sb)
{
	nova_info("=========== NOVA I/O stats ===========\n");
	nova_info("Read %llu, bytes %llu, average %llu\n",
		Countstats[dax_read_t], IOstats[read_bytes],
		Countstats[dax_read_t] ?
			IOstats[read_bytes] / Countstats[dax_read_t] : 0);
	nova_info("COW write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[cow_write_t], IOstats[cow_write_bytes],
		Countstats[cow_write_t] ?
			IOstats[cow_write_bytes] / Countstats[cow_write_t] : 0,
		IOstats[cow_write_breaks], Countstats[cow_write_t] ?
			IOstats[cow_write_breaks] / Countstats[cow_write_t]
			: 0);
	nova_info("Inplace write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[inplace_write_t], IOstats[inplace_write_bytes],
		Countstats[inplace_write_t] ?
			IOstats[inplace_write_bytes] /
			Countstats[inplace_write_t] : 0,
		IOstats[inplace_write_breaks], Countstats[inplace_write_t] ?
			IOstats[inplace_write_breaks] /
			Countstats[inplace_write_t] : 0);
}

void nova_get_timing_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < TIMING_NUM; i++) {
		Timingstats[i] = 0;
		Countstats[i] = 0;
		for_each_possible_cpu(cpu) {
			Timingstats[i] += per_cpu(Timingstats_percpu[i], cpu);
			Countstats[i] += per_cpu(Countstats_percpu[i], cpu);
		}
	}
}

void nova_get_IO_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			IOstats[i] += per_cpu(IOstats_percpu[i], cpu);
	}
}

void nova_print_timing_stats(struct super_block *sb)
{
	int i;

	nova_get_timing_stats();
	nova_get_IO_stats();

	nova_info("=========== NOVA kernel timing stats ============\n");
	for (i = 0; i < TIMING_NUM; i++) {
		/* Title */
		if (Timingstring[i][0] == '=') {
			nova_info("\n%s\n\n", Timingstring[i]);
			continue;
		}

		if (measure_timing || Timingstats[i]) {
			nova_info("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			nova_info("%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	nova_info("\n");
	nova_print_alloc_stats(sb);
	nova_print_IO_stats(sb);
}

static void nova_clear_timing_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
		for_each_possible_cpu(cpu) {
			per_cpu(Timingstats_percpu[i], cpu) = 0;
			per_cpu(Countstats_percpu[i], cpu) = 0;
		}
	}
}

static void nova_clear_IO_stats(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	int cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			per_cpu(IOstats_percpu[i], cpu) = 0;
	}

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		free_list->alloc_log_count = 0;
		free_list->alloc_log_pages = 0;
		free_list->alloc_data_count = 0;
		free_list->alloc_data_pages = 0;
		free_list->free_log_count = 0;
		free_list->freed_log_pages = 0;
		free_list->free_data_count = 0;
		free_list->freed_data_pages = 0;
	}
}

void nova_clear_stats(struct super_block *sb)
{
	nova_clear_timing_stats();
	nova_clear_IO_stats(sb);
}

void nova_print_inode(struct nova_inode *pi)
{
	nova_dbg("%s: NOVA inode %llu\n", __func__, pi->nova_ino);
	nova_dbg("valid %u, deleted %u, blk type %u, flags %u\n",
		pi->valid, pi->deleted, pi->i_blk_type, pi->i_flags);
	nova_dbg("size %llu, ctime %u, mtime %u, atime %u\n",
		pi->i_size, pi->i_ctime, pi->i_mtime, pi->i_atime);
	nova_dbg("mode %u, links %u, xattr 0x%llx\n",
		pi->i_mode, pi->i_links_count, pi->i_xattr);
	nova_dbg("uid %u, gid %u, gen %u, create time %u\n",
		pi->i_uid, pi->i_gid, pi->i_generation, pi->i_create_time);
	nova_dbg("head 0x%llx, tail 0x%llx\n",
		pi->log_head, pi->log_tail);
	nova_dbg("create epoch id %llu, delete epoch id %llu\n",
		pi->create_epoch_id, pi->delete_epoch_id);
}

void nova_print_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;

	nova_dbg("======== NOVA per-CPU free list allocation stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		nova_dbg("Free list %d: block start %lu, block end %lu, "
			"num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		nova_dbg("Free list %d: alloc log count %lu, "
			"allocated log pages %lu, alloc data count %lu, "
			"allocated data pages %lu, free log count %lu, "
			"freed log pages %lu, free data count %lu, "
			"freed data pages %lu\n",
			i,
			free_list->alloc_log_count,
			free_list->alloc_log_pages,
			free_list->alloc_data_count,
			free_list->alloc_data_pages,
			free_list->free_log_count,
			free_list->freed_log_pages,
			free_list->free_data_count,
			free_list->freed_data_pages);
	}
}
