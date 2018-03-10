/*
 * NOVA journaling facility.
 *
 * This file contains journaling code to guarantee the atomicity of directory
 * operations that span multiple inodes (unlink, rename, etc).
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
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

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "nova.h"
#include "journal.h"

/**************************** Lite journal ******************************/

static inline void
nova_print_lite_transaction(struct nova_lite_journal_entry *entry)
{
	nova_dbg("Entry %p: Type %llu, data1 0x%llx, data2 0x%llx\n, checksum %u\n",
			entry, entry->type,
			entry->data1, entry->data2, entry->csum);
}

static inline int nova_update_journal_entry_csum(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = nova_crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry)
			 - sizeof(__le32)));

	entry->csum = cpu_to_le32(crc);
	nova_flush_buffer(entry, sizeof(struct nova_lite_journal_entry), 0);
	return 0;
}

static inline int nova_check_entry_integrity(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = nova_crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry)
			 - sizeof(__le32)));

	if (entry->csum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}

// Get the next journal entry.  Journal entries are stored in a circular
// buffer.  They live a 1-page circular buffer.
//
// TODO: Add check to ensure that the journal doesn't grow too large.
static inline u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct nova_lite_journal_entry);

	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

// Walk the journal for one CPU, and verify the checksum on each entry.
static int nova_check_journal_entries(struct super_block *sb,
	struct journal_ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;
	int ret;

	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
									temp);
		ret = nova_check_entry_integrity(sb, entry);
		if (ret) {
			nova_dbg("Entry %p checksum failure\n", entry);
			nova_print_lite_transaction(entry);
			return ret;
		}
		temp = next_lite_journal(temp);
	}

	return 0;
}
