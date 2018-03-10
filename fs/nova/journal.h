#ifndef __JOURNAL_H
#define __JOURNAL_H

#include <linux/types.h>
#include <linux/fs.h>
#include "nova.h"
#include "super.h"


/* ======================= Lite journal ========================= */

#define NOVA_MAX_JOURNAL_LENGTH 128

#define	JOURNAL_INODE	1
#define	JOURNAL_ENTRY	2

/* Lightweight journal entry */
struct nova_lite_journal_entry {
	__le64 type;       // JOURNAL_INODE or JOURNAL_ENTRY
	__le64 data1;
	__le64 data2;
	__le32 padding;
	__le32 csum;
} __attribute((__packed__));

/* Head and tail pointers into a circular queue of journal entries.  There's
 * one of these per CPU.
 */
struct journal_ptr_pair {
	__le64 journal_head;
	__le64 journal_tail;
};

static inline
struct journal_ptr_pair *nova_get_journal_pointers(struct super_block *sb,
	int cpu)
{
	return (struct journal_ptr_pair *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K * JOURNAL_START) + cpu * CACHELINE_SIZE);
}


#endif
