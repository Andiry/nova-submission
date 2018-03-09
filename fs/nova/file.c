/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
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

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "nova.h"
#include "inode.h"

static loff_t nova_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	sih_lock_shared(sih);
	switch (origin) {
	case SEEK_DATA:
		retval = nova_find_region(inode, &offset, 0);
		if (retval) {
			sih_unlock_shared(sih);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = nova_find_region(inode, &offset, 1);
		if (retval) {
			sih_unlock_shared(sih);
			return retval;
		}
		break;
	}

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		sih_unlock_shared(sih);
		return -ENXIO;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	sih_unlock_shared(sih);
	return offset;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync()
 */
static int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct address_space *mapping = file->f_mapping;
	unsigned long start_pgoff, end_pgoff;
	int ret = 0;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);

	if (datasync)
		NOVA_STATS_ADD(fdatasync, 1);

	/* No need to flush if the file is not mmaped */
	if (!mapping_mapped(mapping))
		goto persist;

	start_pgoff = start >> PAGE_SHIFT;
	end_pgoff = (end + 1) >> PAGE_SHIFT;
	nova_dbgv("%s: msync pgoff range %lu to %lu\n",
			__func__, start_pgoff, end_pgoff);

	ret = generic_file_fsync(file, start, end, datasync);

persist:
	PERSISTENT_BARRIER();
	NOVA_END_TIMING(fsync_t, fsync_time);

	return ret;
}

/* This callback is called when a file is closed */
static int nova_flush(struct file *file, fl_owner_t id)
{
	PERSISTENT_BARRIER();
	return 0;
}

static int nova_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}

static ssize_t
do_dax_mapping_read(struct file *filp, char __user *buf,
	size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	if (!access_ok(VERIFY_WRITE, buf, len)) {
		error = -EFAULT;
		goto out;
	}

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu, size %lld\n",
		__func__, inode->i_ino,	pos, len, isize);

	if (len > isize - pos)
		len = isize - pos;

	if (len <= 0)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;
	do {
		unsigned long nr, left;
		unsigned long nvmm;
		void *dax_mem = NULL;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset)
				goto out;
		}

		entry = nova_get_write_entry(sb, sih, index);
		if (unlikely(entry == NULL)) {
			nova_dbgv("Required extent not found: pgoff %lu, inode size %lld\n",
				index, isize);
			nr = PAGE_SIZE;
			zero = 1;
			goto memcpy;
		}

		/* Find contiguous blocks */
		if (index < entry->pgoff ||
			index - entry->pgoff >= entry->num_pages) {
			nova_err(sb, "%s ERROR: %lu, entry pgoff %llu, num %u, blocknr %llu\n",
				__func__, index, entry->pgoff,
				entry->num_pages, entry->block >> PAGE_SHIFT);
			return -EINVAL;
		}
		if (entry->reassigned == 0) {
			nr = (entry->num_pages - (index - entry->pgoff))
				* PAGE_SIZE;
		} else {
			nr = PAGE_SIZE;
		}

		nvmm = get_nvmm(sb, sih, entry, index);
		dax_mem = nova_get_block(sb, (nvmm << PAGE_SHIFT));

memcpy:
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		NOVA_START_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (!zero)
			left = __copy_to_user(buf + copied,
						dax_mem + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		NOVA_END_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (left) {
			nova_dbg("%s ERROR!: bytes %lu, left %lu\n",
				__func__, nr, left);
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	NOVA_STATS_ADD(read_bytes, copied);

	nova_dbgv("%s returned %zu\n", __func__, copied);
	return copied ? copied : error;
}

/*
 * Wrappers. We need to use the read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * lock.
 */
static ssize_t nova_dax_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	ssize_t res;
	timing_t dax_read_time;

	NOVA_START_TIMING(dax_read_t, dax_read_time);
	inode_lock_shared(inode);
	sih_lock_shared(sih);
	res = do_dax_mapping_read(filp, buf, len, ppos);
	sih_unlock_shared(sih);
	inode_unlock_shared(inode);
	NOVA_END_TIMING(dax_read_t, dax_read_time);
	return res;
}


const struct file_operations nova_dax_file_operations = {
	.llseek		= nova_llseek,
	.read		= nova_dax_file_read,
	.open		= nova_open,
	.fsync		= nova_fsync,
	.flush		= nova_flush,
};

const struct inode_operations nova_file_inode_operations = {
	.setattr	= nova_notify_change,
	.getattr	= nova_getattr,
	.get_acl	= NULL,
};
