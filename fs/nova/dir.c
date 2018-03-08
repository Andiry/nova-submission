/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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
#include "inode.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

struct nova_dentry *nova_find_dentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *direntry;
	unsigned long hash;

	hash = BKDRHash(name, name_len);
	direntry = radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

int nova_insert_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dentry *direntry)
{
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);
	nova_dbgv("%s: insert %s hash %lu\n", __func__, name, hash);

	/* FIXME: hash collision ignored here */
	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret)
		nova_dbg("%s ERROR %d: %s\n", __func__, ret, name);

	return ret;
}

static int nova_check_dentry_match(struct super_block *sb,
	struct nova_dentry *dentry, const char *name, int namelen)
{
	if (dentry->name_len != namelen)
		return -EINVAL;

	return strncmp(dentry->name, name, namelen);
}

int nova_remove_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen,
	int replay, struct nova_dentry **create_dentry)
{
	struct nova_dentry *entry;
	unsigned long hash;

	hash = BKDRHash(name, namelen);
	entry = radix_tree_delete(&sih->tree, hash);

	if (replay == 0) {
		if (!entry) {
			nova_dbg("%s ERROR: %s, length %d, hash %lu\n",
					__func__, name, namelen, hash);
			return -EINVAL;
		}

		if (entry->ino == 0 || entry->invalid ||
		    nova_check_dentry_match(sb, entry, name, namelen)) {
			nova_dbg("%s dentry not match: %s, length %d, hash %lu\n",
				 __func__, name, namelen, hash);
			/* for debug information, still allow access to nvmm */
			nova_dbg("dentry: type %d, inode %llu, name %s, namelen %u, rec len %u\n",
				 entry->entry_type, le64_to_cpu(entry->ino),
				 entry->name, entry->name_len,
				 le16_to_cpu(entry->de_len));
			return -EINVAL;
		}

		if (create_dentry)
			*create_dentry = entry;
	}

	return 0;
}

void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_dentry *direntry;
	unsigned long pos = 0;
	struct nova_dentry *entries[FREE_BATCH];
	timing_t delete_time;
	int nr_entries;
	int i;
	void *ret;

	NOVA_START_TIMING(delete_dir_tree_t, delete_time);

	nova_dbgv("%s: delete dir %lu\n", __func__, sih->ino);
	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			direntry = entries[i];

			pos = BKDRHash(direntry->name, direntry->name_len);
			ret = radix_tree_delete(&sih->tree, pos);
			if (!ret || ret != direntry) {
				nova_err(sb, "dentry: type %d, inode %llu, "
					"name %s, namelen %u, rec len %u\n",
					direntry->entry_type,
					le64_to_cpu(direntry->ino),
					direntry->name, direntry->name_len,
					le16_to_cpu(direntry->de_len));
				if (!ret)
					nova_dbg("ret is NULL\n");
			}
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

	NOVA_END_TIMING(delete_dir_tree_t, delete_time);
}

/* ========================= Entry operations ============================= */

static unsigned int nova_init_dentry(struct super_block *sb,
	struct nova_dentry *de_entry, u64 self_ino, u64 parent_ino,
	u64 epoch_id)
{
	void *start = de_entry;
	struct nova_inode_log_page *curr_page = start;
	unsigned int length;
	unsigned short de_len;

	de_len = NOVA_DIR_LOG_REC_LEN(1);
	memset(de_entry, 0, de_len);
	de_entry->entry_type = DIR_LOG;
	de_entry->epoch_id = epoch_id;
	de_entry->trans_id = 0;
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->name_len = 1;
	de_entry->de_len = cpu_to_le16(de_len);
	de_entry->mtime = timespec_trunc(current_kernel_time(),
					 sb->s_time_gran).tv_sec;

	de_entry->links_count = 1;
	strncpy(de_entry->name, ".\0", 2);
	nova_persist_entry(de_entry);

	length = de_len;

	de_entry = (struct nova_dentry *)((char *)de_entry + length);
	de_len = NOVA_DIR_LOG_REC_LEN(2);
	memset(de_entry, 0, de_len);
	de_entry->entry_type = DIR_LOG;
	de_entry->epoch_id = epoch_id;
	de_entry->trans_id = 0;
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->name_len = 2;
	de_entry->de_len = cpu_to_le16(de_len);
	de_entry->mtime = timespec_trunc(current_kernel_time(),
					 sb->s_time_gran).tv_sec;

	de_entry->links_count = 2;
	strncpy(de_entry->name, "..\0", 3);
	nova_persist_entry(de_entry);
	length += de_len;

	nova_set_page_num_entries(sb, curr_page, 2, 1);

	nova_flush_buffer(start, length, 0);
	return length;
}

/* Append . and .. entries */
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino, u64 epoch_id)
{
	struct nova_inode_info_header sih;
	int allocated;
	u64 new_block;
	unsigned int length;
	struct nova_dentry *de_entry;

	sih.ino = self_ino;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	allocated = nova_allocate_inode_log_pages(sb, &sih, 1, &new_block,
							ANY_CPU, 0);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return -ENOMEM;
	}

	pi->log_tail = pi->log_head = new_block;

	de_entry = (struct nova_dentry *)nova_get_block(sb, new_block);

	length = nova_init_dentry(sb, de_entry, self_ino, parent_ino, epoch_id);

	nova_update_tail(pi, new_block + length);

	return 0;
}
