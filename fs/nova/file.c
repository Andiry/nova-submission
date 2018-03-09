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


const struct file_operations nova_dax_file_operations = {
	.llseek		= nova_llseek,
	.open		= nova_open,
	.fsync		= nova_fsync,
	.flush		= nova_flush,
};

const struct inode_operations nova_file_inode_operations = {
	.setattr	= nova_notify_change,
	.getattr	= nova_getattr,
	.get_acl	= NULL,
};
