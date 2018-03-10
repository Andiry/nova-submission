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

static u64 nova_find_next_dentry_addr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 pos)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry *entries[1];
	int nr_entries;
	u64 addr = 0;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, 1);
	if (nr_entries == 1) {
		entry = entries[0];
		addr = nova_get_addr_off(sbi, entry);
	}

	return addr;
}

static int nova_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pidir;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *child_pi;
	struct nova_inode *prev_child_pi = NULL;
	struct nova_dentry *entry = NULL;
	struct nova_dentry *prev_entry = NULL;
	unsigned short de_len;
	u64 pi_addr;
	unsigned long pos = 0;
	ino_t ino;
	void *addr;
	u64 curr_p;
	u8 type;
	int ret = 0;
	timing_t readdir_time;

	NOVA_START_TIMING(readdir_t, readdir_time);
	pidir = nova_get_inode(sb, inode);
	nova_dbgv("%s: ino %llu, size %llu, pos 0x%llx\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (sih->log_head == 0) {
		nova_err(sb, "Dir %lu log is NULL!\n", inode->i_ino);
		ret = -ENOSPC;
		goto out;
	}

	pos = ctx->pos;

	if (pos == 0)
		curr_p = sih->log_head;
	else if (pos == READDIR_END)
		goto out;
	else {
		curr_p = nova_find_next_dentry_addr(sb, sih, pos);
		if (curr_p == 0)
			goto out;
	}

	while (curr_p != sih->log_tail) {
		if (goto_next_page(sb, curr_p))
			curr_p = next_log_page(sb, curr_p);


		if (curr_p == 0) {
			nova_err(sb, "Dir %lu log is NULL!\n", inode->i_ino);
			ret = -EINVAL;
			goto out;
		}

		addr = (void *)nova_get_block(sb, curr_p);
		type = nova_get_entry_type(addr);
		switch (type) {
		case SET_ATTR:
			curr_p += sizeof(struct nova_setattr_logentry);
			continue;
		case LINK_CHANGE:
			curr_p += sizeof(struct nova_link_change_entry);
			continue;
		case DIR_LOG:
			break;
		default:
			nova_err(sb, "%s: unknown type %d, 0x%llx\n",
				 __func__, type, curr_p);
			ret = -EINVAL;
			goto out;
		}

		entry = (struct nova_dentry *)nova_get_block(sb, curr_p);
		nova_dbgv("curr_p: 0x%llx, type %d, ino %llu, name %s, namelen %u, rec len %u\n",
			  curr_p, entry->entry_type, le64_to_cpu(entry->ino),
			  entry->name, entry->name_len,
			  le16_to_cpu(entry->de_len));

		de_len = le16_to_cpu(entry->de_len);
		if (entry->ino > 0 && entry->invalid == 0
					&& entry->reassigned == 0) {
			ino = __le64_to_cpu(entry->ino);
			pos = BKDRHash(entry->name, entry->name_len);

			ret = nova_get_inode_address(sb, ino,
						     &pi_addr, 0);
			if (ret) {
				nova_dbg("%s: get child inode %lu address failed %d\n",
					 __func__, ino, ret);
				ctx->pos = READDIR_END;
				goto out;
			}

			child_pi = nova_get_block(sb, pi_addr);
			nova_dbgv("ctx: ino %llu, name %s, name_len %u, de_len %u\n",
				(u64)ino, entry->name, entry->name_len,
				entry->de_len);
			if (prev_entry && !dir_emit(ctx, prev_entry->name,
				prev_entry->name_len, ino,
				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
				nova_dbgv("Here: pos %llu\n", ctx->pos);
				ret = 0;
				goto out;
			}
			prev_entry = entry;

			prev_child_pi = child_pi;
		}
		ctx->pos = pos;
		curr_p += de_len;
	}

	if (prev_entry && !dir_emit(ctx, prev_entry->name,
			prev_entry->name_len, ino,
			IF2DT(le16_to_cpu(prev_child_pi->i_mode))))
		return 0;

	ctx->pos = READDIR_END;
	ret = 0;
out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	nova_dbgv("%s return\n", __func__);
	return ret;
}

const struct file_operations nova_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= nova_readdir,
	.fsync		= noop_fsync,
};
