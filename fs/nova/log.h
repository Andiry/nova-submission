#ifndef __LOG_H
#define __LOG_H

#include "balloc.h"
#include "inode.h"

/* ======================= Log entry ========================= */
/* Inode entry in the log */

#define	MAIN_LOG	0
#define	ALTER_LOG	1

#define	PAGE_OFFSET_MASK	4095
#define	BLOCK_OFF(p)	((p) & ~PAGE_OFFSET_MASK)

#define	ENTRY_LOC(p)	((p) & PAGE_OFFSET_MASK)

#define	LOG_BLOCK_TAIL	4064
#define	PAGE_TAIL(p)	(BLOCK_OFF(p) + LOG_BLOCK_TAIL)

/*
 * Log page state and pointers to next page and the replica page
 */
struct nova_inode_page_tail {
	__le32	invalid_entries;
	__le32	num_entries;
	__le64	epoch_id;	/* For snapshot list page */
	__le64	padding;
	__le64	next_page;
} __attribute((__packed__));

/* Fit in PAGE_SIZE */
struct	nova_inode_log_page {
	char padding[LOG_BLOCK_TAIL];
	struct nova_inode_page_tail page_tail;
} __attribute((__packed__));

#define	EXTEND_THRESHOLD	256

enum nova_entry_type {
	FILE_WRITE = 1,
	DIR_LOG,
	SET_ATTR,
	LINK_CHANGE,
	NEXT_PAGE,
};

static inline u8 nova_get_entry_type(void *p)
{
	u8 type;
	int rc;

	rc = memcpy_mcsafe(&type, p, sizeof(u8));
	if (rc)
		return rc;

	return type;
}

static inline void nova_set_entry_type(void *p, enum nova_entry_type type)
{
	*(u8 *)p = type;
}

static inline u64 next_log_page(struct super_block *sb, u64 curr)
{
	struct nova_inode_log_page *curr_page;
	u64 next = 0;
	int rc;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	rc = memcpy_mcsafe(&next, &curr_page->page_tail.next_page,
				sizeof(u64));
	if (rc)
		return rc;

	return next;
}

static inline void nova_set_next_page_flag(struct super_block *sb, u64 curr_p)
{
	void *p;

	if (ENTRY_LOC(curr_p) >= LOG_BLOCK_TAIL)
		return;

	p = nova_get_block(sb, curr_p);
	nova_set_entry_type(p, NEXT_PAGE);
	nova_flush_buffer(p, CACHELINE_SIZE, 1);
}

static inline void nova_set_next_page_address(struct super_block *sb,
	struct nova_inode_log_page *curr_page, u64 next_page, int fence)
{
	curr_page->page_tail.next_page = next_page;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
	if (fence)
		PERSISTENT_BARRIER();
}

static inline void nova_set_page_num_entries(struct super_block *sb,
	struct nova_inode_log_page *curr_page, int num, int flush)
{
	curr_page->page_tail.num_entries = num;
	if (flush)
		nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_set_page_invalid_entries(struct super_block *sb,
	struct nova_inode_log_page *curr_page, int num, int flush)
{
	curr_page->page_tail.invalid_entries = num;
	if (flush)
		nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_inc_page_num_entries(struct super_block *sb,
	u64 curr)
{
	struct nova_inode_log_page *curr_page;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);

	curr_page->page_tail.num_entries++;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_inc_page_invalid_entries(struct super_block *sb,
	u64 curr)
{
	struct nova_inode_log_page *curr_page;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);

	curr_page->page_tail.invalid_entries++;
	if (curr_page->page_tail.invalid_entries >
			curr_page->page_tail.num_entries) {
		nova_dbg("Page 0x%llx has %u entries, %u invalid\n",
				curr,
				curr_page->page_tail.num_entries,
				curr_page->page_tail.invalid_entries);
	}

	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline bool is_last_entry(u64 curr_p, size_t size)
{
	unsigned int entry_end;

	entry_end = ENTRY_LOC(curr_p) + size;

	return entry_end > LOG_BLOCK_TAIL;
}

static inline bool goto_next_page(struct super_block *sb, u64 curr_p)
{
	void *addr;
	u8 type;
	int rc;

	/* Each kind of entry takes at least 32 bytes */
	if (ENTRY_LOC(curr_p) + 32 > LOG_BLOCK_TAIL)
		return true;

	addr = nova_get_block(sb, curr_p);
	rc = memcpy_mcsafe(&type, addr, sizeof(u8));

	if (rc < 0)
		return true;

	if (type == NEXT_PAGE)
		return true;

	return false;
}


int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block, int cpuid, enum nova_alloc_direction from_tail);
u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended);
int nova_free_contiguous_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 head);
int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih);

#endif
