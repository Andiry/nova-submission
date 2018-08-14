/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
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
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/exportfs.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/dax.h>
#include "nova.h"
#include "super.h"

int measure_timing;
int support_clwb;

module_param(measure_timing, int, 0444);
MODULE_PARM_DESC(measure_timing, "Timing measurement");

module_param(nova_dbgmask, int, 0444);
MODULE_PARM_DESC(nova_dbgmask, "Control debugging output");

static struct super_operations nova_sops;

static struct kmem_cache *nova_inode_cachep;
static struct kmem_cache *nova_range_node_cachep;


/* FIXME: should the following variable be one per NOVA instance? */
unsigned int nova_dbgmask;

void nova_error_mng(struct super_block *sb, const char *fmt, ...)
{
	va_list args;

	printk(KERN_CRIT "nova error: ");
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	if (test_opt(sb, ERRORS_PANIC))
		panic("nova: panic from previous error\n");
	if (test_opt(sb, ERRORS_RO)) {
		printk(KERN_CRIT "nova err: remounting filesystem read-only");
		sb->s_flags |= MS_RDONLY;
	}
}

static void nova_set_blocksize(struct super_block *sb, unsigned long size)
{
	int bits;

	/*
	 * We've already validated the user input and the value here must be
	 * between NOVA_MAX_BLOCK_SIZE and NOVA_MIN_BLOCK_SIZE
	 * and it must be a power of 2.
	 */
	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

static int nova_get_nvmm_info(struct super_block *sb,
	struct nova_sb_info *sbi)
{
	void *virt_addr = NULL;
	pfn_t __pfn_t;
	long size;
	struct dax_device *dax_dev;
	int ret;

	ret = bdev_dax_supported(sb, PAGE_SIZE);
	nova_dbg_verbose("%s: dax_supported = %d; bdev->super=0x%p",
			 __func__, ret, sb->s_bdev->bd_super);
	if (ret) {
		nova_err(sb, "device does not support DAX\n");
		return ret;
	}

	sbi->s_bdev = sb->s_bdev;

	dax_dev = fs_dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
	if (!dax_dev) {
		nova_err(sb, "Couldn't retrieve DAX device.\n");
		return -EINVAL;
	}
	sbi->s_dax_dev = dax_dev;

	size = dax_direct_access(sbi->s_dax_dev, 0, LONG_MAX/PAGE_SIZE,
				 &virt_addr, &__pfn_t) * PAGE_SIZE;
	if (size <= 0) {
		nova_err(sb, "direct_access failed\n");
		return -EINVAL;
	}

	sbi->virt_addr = virt_addr;

	if (!sbi->virt_addr) {
		nova_err(sb, "ioremap of the nova image failed(1)\n");
		return -EINVAL;
	}

	sbi->phys_addr = pfn_t_to_pfn(__pfn_t) << PAGE_SHIFT;
	sbi->initsize = size;
	sbi->replica_reserved_inodes_addr = virt_addr + size -
			(sbi->tail_reserved_blocks << PAGE_SHIFT);
	sbi->replica_sb_addr = virt_addr + size - PAGE_SIZE;

	nova_dbg("%s: dev %s, phys_addr 0x%llx, virt_addr %p, size %ld\n",
		__func__, sbi->s_bdev->bd_disk->disk_name,
		sbi->phys_addr, sbi->virt_addr, sbi->initsize);

	return 0;
}

static loff_t nova_max_size(int bits)
{
	loff_t res;

	res = (1ULL << 63) - 1;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	nova_dbg_verbose("max file size %llu bytes\n", res);
	return res;
}

enum {
	Opt_bpi, Opt_init, Opt_mode, Opt_uid,
	Opt_gid, Opt_dax,
	Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_dbgmask, Opt_err
};

static const match_table_t tokens = {
	{ Opt_bpi,	     "bpi=%u"		  },
	{ Opt_init,	     "init"		  },
	{ Opt_mode,	     "mode=%o"		  },
	{ Opt_uid,	     "uid=%u"		  },
	{ Opt_gid,	     "gid=%u"		  },
	{ Opt_dax,	     "dax"		  },
	{ Opt_err_cont,	     "errors=continue"	  },
	{ Opt_err_panic,     "errors=panic"	  },
	{ Opt_err_ro,	     "errors=remount-ro"  },
	{ Opt_dbgmask,	     "dbgmask=%u"	  },
	{ Opt_err,	     NULL		  },
};

static int nova_parse_options(char *options, struct nova_sb_info *sbi,
			       bool remount)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	kuid_t uid;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_bpi:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (remount && sbi->bpi)
				goto bad_opt;
			sbi->bpi = option;
			break;
		case Opt_uid:
			if (match_int(&args[0], &option))
				goto bad_val;
			uid = make_kuid(current_user_ns(), option);
			if (remount && !uid_eq(sbi->uid, uid))
				goto bad_opt;
			sbi->uid = uid;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				goto bad_val;
			sbi->mode = option & 01777U;
			break;
		case Opt_init:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_err_panic:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			set_opt(sbi->s_mount_opt, ERRORS_PANIC);
			break;
		case Opt_err_ro:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_RO);
			break;
		case Opt_err_cont:
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_CONT);
			break;
		case Opt_dax:
			set_opt(sbi->s_mount_opt, DAX);
			break;
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad_val;
			nova_dbgmask = option;
			break;
		default: {
			goto bad_opt;
		}
		}
	}

	return 0;

bad_val:
	nova_info("Bad value '%s' for mount option '%s'\n", args[0].from,
	       p);
	return -EINVAL;
bad_opt:
	nova_info("Bad mount option: \"%s\"\n", p);
	return -EINVAL;
}


/* Make sure we have enough space */
static bool nova_check_size(struct super_block *sb, unsigned long size)
{
	unsigned long minimum_size;

	/* space required for super block and root directory.*/
	minimum_size = (HEAD_RESERVED_BLOCKS + TAIL_RESERVED_BLOCKS + 1)
			  << sb->s_blocksize_bits;

	if (size < minimum_size)
		return false;

	return true;
}

static inline int nova_check_super_checksum(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u32 crc = 0;

	// Check CRC but skip c_sum, which is the 4 bytes at the beginning
	crc = nova_crc32c(~0, (__u8 *)sbi->nova_sb + sizeof(__le32),
			sizeof(struct nova_super_block) - sizeof(__le32));

	if (sbi->nova_sb->s_sum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}

static inline void nova_sync_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = nova_get_super(sb);
	struct nova_super_block *super_redund;

	super_redund = nova_get_redund_super(sb);

	memcpy_to_pmem_nocache((void *)super, (void *)sbi->nova_sb,
		sizeof(struct nova_super_block));
	PERSISTENT_BARRIER();

	memcpy_to_pmem_nocache((void *)super_redund, (void *)sbi->nova_sb,
		sizeof(struct nova_super_block));
	PERSISTENT_BARRIER();
}

/* Update checksum for the DRAM copy */
static inline void nova_update_super_crc(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u32 crc = 0;

	sbi->nova_sb->s_wtime = cpu_to_le32(get_seconds());
	sbi->nova_sb->s_sum = 0;
	crc = nova_crc32c(~0, (__u8 *)sbi->nova_sb + sizeof(__le32),
			sizeof(struct nova_super_block) - sizeof(__le32));
	sbi->nova_sb->s_sum = cpu_to_le32(crc);
}


static inline void nova_update_mount_time(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 mnt_write_time;

	mnt_write_time = (get_seconds() & 0xFFFFFFFF);
	mnt_write_time = mnt_write_time | (mnt_write_time << 32);

	sbi->nova_sb->s_mtime = cpu_to_le64(mnt_write_time);
	nova_update_super_crc(sb);

	nova_sync_super(sb);
}

static struct nova_inode *nova_init(struct super_block *sb,
				      unsigned long size)
{
	unsigned long blocksize;
	struct nova_inode *root_i, *pi;
	struct nova_super_block *super;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	timing_t init_time;

	NOVA_START_TIMING(new_init_t, init_time);

	nova_info("creating an empty nova of size %lu\n", size);
	sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);

	nova_dbgv("nova: Default block size set to 4K\n");
	sbi->blocksize = blocksize = NOVA_DEF_BLOCK_SIZE_4K;
	nova_set_blocksize(sb, sbi->blocksize);

	if (!nova_check_size(sb, size)) {
		nova_warn("Specified NOVA size too small 0x%lx.\n", size);
		NOVA_END_TIMING(new_init_t, init_time);
		return ERR_PTR(-EINVAL);
	}

	nova_dbgv("max file name len %d\n", (unsigned int)NOVA_NAME_LEN);

	super = nova_get_super(sb);

	/* clear out super-block and inode table */
	memset_nt(super, 0, sbi->head_reserved_blocks * sbi->blocksize);

	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->nova_ino = NOVA_BLOCKNODE_INO;
	nova_flush_buffer(pi, CACHELINE_SIZE, 1);

	nova_init_blockmap(sb, 0);

	sbi->nova_sb->s_size = cpu_to_le64(size);
	sbi->nova_sb->s_blocksize = cpu_to_le32(blocksize);
	sbi->nova_sb->s_magic = cpu_to_le32(NOVA_SUPER_MAGIC);
	sbi->nova_sb->s_epoch_id = 0;
	nova_update_super_crc(sb);

	nova_sync_super(sb);

	root_i = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);
	nova_dbgv("%s: Allocate root inode @ 0x%p\n", __func__, root_i);

	root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_blk_type = NOVA_BLOCK_TYPE_4K;
	root_i->i_flags = 0;
	root_i->i_size = cpu_to_le64(sb->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->nova_ino = cpu_to_le64(NOVA_ROOT_INO);
	root_i->valid = 1;

	nova_flush_buffer(root_i, sizeof(*root_i), false);

	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	nova_info("NOVA initialization finish\n");
	NOVA_END_TIMING(new_init_t, init_time);
	return root_i;
}

static inline void set_default_opts(struct nova_sb_info *sbi)
{
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);
	set_opt(sbi->s_mount_opt, ERRORS_CONT);
	sbi->head_reserved_blocks = HEAD_RESERVED_BLOCKS;
	sbi->tail_reserved_blocks = TAIL_RESERVED_BLOCKS;
	sbi->cpus = num_online_cpus();
}

static void nova_root_check(struct super_block *sb, struct nova_inode *root_pi)
{
	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
		nova_warn("root is not a directory!\n");
}

/* Check super block magic and checksum */
static int nova_check_super(struct super_block *sb,
	struct nova_super_block *ps)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int rc;

	rc = memcpy_mcsafe(sbi->nova_sb, ps,
				sizeof(struct nova_super_block));

	if (rc < 0)
		return rc;

	if (le32_to_cpu(sbi->nova_sb->s_magic) != NOVA_SUPER_MAGIC)
		return -EIO;

	if (nova_check_super_checksum(sb))
		return -EIO;

	return 0;
}

static int nova_check_integrity(struct super_block *sb)
{
	struct nova_super_block *super = nova_get_super(sb);
	struct nova_super_block *super_redund;
	int rc;

	super_redund = nova_get_redund_super(sb);

	/* Do sanity checks on the superblock */
	rc = nova_check_super(sb, super);
	if (rc < 0) {
		rc = nova_check_super(sb, super_redund);
		if (rc < 0) {
			nova_err(sb, "Can't find a valid nova partition\n");
			return rc;
		} else {
			nova_warn("Error in super block: try to repair it with the other copy\n");
			memcpy_to_pmem_nocache((void *)super, (void *)super_redund,
					sizeof(struct nova_super_block));
			PERSISTENT_BARRIER();
		}
	}

	return 0;
}

static int nova_fill_super(struct super_block *sb, void *data, int silent)
{
	struct nova_sb_info *sbi = NULL;
	struct nova_inode *root_pi;
	struct inode *root_i = NULL;
	unsigned long blocksize;
	u32 random = 0;
	int retval = -EINVAL;
	timing_t mount_time;

	NOVA_START_TIMING(mount_t, mount_time);

	BUILD_BUG_ON(sizeof(struct nova_super_block) > NOVA_SB_SIZE);

	sbi = kzalloc(sizeof(struct nova_sb_info), GFP_KERNEL);
	if (!sbi) {
		NOVA_END_TIMING(mount_t, mount_time);
		return -ENOMEM;
	}

	sbi->nova_sb = kzalloc(sizeof(struct nova_super_block), GFP_KERNEL);
	if (!sbi->nova_sb) {
		kfree(sbi);
		NOVA_END_TIMING(mount_t, mount_time);
		return -ENOMEM;
	}

	sb->s_fs_info = sbi;
	sbi->sb = sb;

	set_default_opts(sbi);

	/* Currently the log page supports 64 journal pointer pairs */
	if (sbi->cpus > MAX_CPUS) {
		nova_err(sb, "NOVA needs more log pointer pages to support more than "
			  __stringify(MAX_CPUS) " cpus.\n");
		goto out;
	}

	retval = nova_get_nvmm_info(sb, sbi);
	if (retval) {
		nova_err(sb, "%s: Failed to get nvmm info.",
			 __func__);
		goto out;
	}

	nova_dbg("measure timing %d\n", measure_timing);

	get_random_bytes(&random, sizeof(u32));
	atomic_set(&sbi->next_generation, random);

	/* Init with default values */
	sbi->mode = (0755);
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);

	mutex_init(&sbi->s_lock);

	sbi->zeroed_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sbi->zeroed_page) {
		retval = -ENOMEM;
		nova_dbg("%s: sbi->zeroed_page failed.",
			 __func__);
		goto out;
	}

	retval = nova_parse_options(data, sbi, 0);
	if (retval) {
		nova_err(sb, "%s: Failed to parse nova command line options.",
			 __func__);
		goto out;
	}

	if (nova_alloc_block_free_lists(sb)) {
		retval = -ENOMEM;
		nova_err(sb, "%s: Failed to allocate block free lists.",
			 __func__);
		goto out;
	}

	/* Init a new nova instance */
	if (sbi->s_mount_opt & NOVA_MOUNT_FORMAT) {
		root_pi = nova_init(sb, sbi->initsize);
		if (IS_ERR(root_pi)) {
			nova_err(sb, "%s: root_pi error.",
				 __func__);

			goto out;
		}
		goto setup_sb;
	}

	if (nova_check_integrity(sb) < 0) {
		retval = -EINVAL;
		nova_dbg("Memory contains invalid nova %x:%x\n",
			le32_to_cpu(sbi->nova_sb->s_magic), NOVA_SUPER_MAGIC);
		goto out;
	}

	blocksize = le32_to_cpu(sbi->nova_sb->s_blocksize);
	nova_set_blocksize(sb, blocksize);

	nova_dbg_verbose("blocksize %lu\n", blocksize);

	/* Read the root inode */
	root_pi = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

	/* Check that the root inode is in a sane state */
	nova_root_check(sb, root_pi);

	/* Set it all up.. */
setup_sb:
	sb->s_magic = le32_to_cpu(sbi->nova_sb->s_magic);
	sb->s_op = &nova_sops;
	sb->s_maxbytes = nova_max_size(sb->s_blocksize_bits);
	sb->s_time_gran = 1000000000; // 1 second.
	sb->s_xattr = NULL;
	sb->s_flags |= MS_NOSEC;

	root_i = nova_iget(sb, NOVA_ROOT_INO);
	if (IS_ERR(root_i)) {
		retval = PTR_ERR(root_i);
		nova_err(sb, "%s: failed to get root inode",
			 __func__);

		goto out;
	}

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		nova_err(sb, "get nova root inode failed\n");
		retval = -ENOMEM;
		goto out;
	}

	if (!(sb->s_flags & MS_RDONLY))
		nova_update_mount_time(sb);

	retval = 0;
	NOVA_END_TIMING(mount_t, mount_time);
	return retval;

out:
	kfree(sbi->zeroed_page);
	sbi->zeroed_page = NULL;

	nova_delete_free_lists(sb);

	kfree(sbi->nova_sb);
	kfree(sbi);
	nova_dbg("%s failed: return %d\n", __func__, retval);
	NOVA_END_TIMING(mount_t, mount_time);
	return retval;
}

static int nova_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct super_block *sb = d->d_sb;
	struct nova_sb_info *sbi = (struct nova_sb_info *)sb->s_fs_info;

	buf->f_type = NOVA_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;

	buf->f_blocks = sbi->num_blocks;
	buf->f_bfree = buf->f_bavail = nova_count_free_blocks(sb);
	buf->f_files = LONG_MAX;
	buf->f_ffree = LONG_MAX - sbi->s_inodes_used_count;
	buf->f_namelen = NOVA_NAME_LEN;
	nova_dbg_verbose("nova_stats: total 4k free blocks 0x%llx\n",
		buf->f_bfree);
	return 0;
}

static int nova_show_options(struct seq_file *seq, struct dentry *root)
{
	struct nova_sb_info *sbi = NOVA_SB(root->d_sb);

	if (sbi->mode != (0777 | S_ISVTX))
		seq_printf(seq, ",mode=%03o", sbi->mode);
	if (uid_valid(sbi->uid))
		seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));
	if (gid_valid(sbi->gid))
		seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));
	if (test_opt(root->d_sb, ERRORS_RO))
		seq_puts(seq, ",errors=remount-ro");
	if (test_opt(root->d_sb, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
	if (test_opt(root->d_sb, DAX))
		seq_puts(seq, ",dax");

	return 0;
}

static int nova_remount(struct super_block *sb, int *mntflags, char *data)
{
	unsigned long old_sb_flags;
	unsigned long old_mount_opt;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret = -EINVAL;

	/* Store the old options */
	mutex_lock(&sbi->s_lock);
	old_sb_flags = sb->s_flags;
	old_mount_opt = sbi->s_mount_opt;

	if (nova_parse_options(data, sbi, 1))
		goto restore_opt;

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		      ((sbi->s_mount_opt & NOVA_MOUNT_POSIX_ACL) ?
		       MS_POSIXACL : 0);

	if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY))
		nova_update_mount_time(sb);

	mutex_unlock(&sbi->s_lock);
	ret = 0;
	return ret;

restore_opt:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_mount_opt;
	mutex_unlock(&sbi->s_lock);
	return ret;
}

static void nova_put_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->virt_addr) {
		/* Save everything before blocknode mapping! */
		nova_save_blocknode_mappings_to_log(sb);
		sbi->virt_addr = NULL;
	}

	nova_delete_free_lists(sb);

	kfree(sbi->zeroed_page);
	nova_dbgmask = 0;

	kfree(sbi->nova_sb);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

inline void nova_free_range_node(struct nova_range_node *node)
{
	kmem_cache_free(nova_range_node_cachep, node);
}

inline struct nova_range_node *nova_alloc_range_node(struct super_block *sb)
{
	struct nova_range_node *p;

	p = (struct nova_range_node *)
		kmem_cache_zalloc(nova_range_node_cachep, GFP_NOFS);
	return p;
}

static struct inode *nova_alloc_inode(struct super_block *sb)
{
	struct nova_inode_info *vi;

	vi = kmem_cache_alloc(nova_inode_cachep, GFP_NOFS);
	if (!vi)
		return NULL;

	return &vi->vfs_inode;
}

static void nova_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct nova_inode_info *vi = NOVA_I(inode);

	nova_dbg_verbose("%s: ino %lu\n", __func__, inode->i_ino);
	kmem_cache_free(nova_inode_cachep, vi);
}

static void nova_destroy_inode(struct inode *inode)
{
	nova_dbgv("%s: %lu\n", __func__, inode->i_ino);
	call_rcu(&inode->i_rcu, nova_i_callback);
}

static void init_once(void *foo)
{
	struct nova_inode_info *vi = foo;

	inode_init_once(&vi->vfs_inode);
}

static int __init init_rangenode_cache(void)
{
	nova_range_node_cachep = kmem_cache_create("nova_range_node_cache",
					sizeof(struct nova_range_node),
					0, (SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD), NULL);
	if (nova_range_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static int __init init_inodecache(void)
{
	nova_inode_cachep = kmem_cache_create("nova_inode_cache",
					       sizeof(struct nova_inode_info),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), init_once);
	if (nova_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before
	 * we destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(nova_inode_cachep);
}

static void destroy_rangenode_cache(void)
{
	kmem_cache_destroy(nova_range_node_cachep);
}


/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations nova_sops = {
	.alloc_inode	= nova_alloc_inode,
	.destroy_inode	= nova_destroy_inode,
	.put_super	= nova_put_super,
	.statfs		= nova_statfs,
	.remount_fs	= nova_remount,
	.show_options	= nova_show_options,
};

static struct dentry *nova_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, nova_fill_super);
}

static struct file_system_type nova_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "NOVA",
	.mount		= nova_mount,
	.kill_sb	= kill_block_super,
};

static int __init init_nova_fs(void)
{
	int rc = 0;
	timing_t init_time;

	NOVA_START_TIMING(init_t, init_time);

	nova_dbg("%s: %d cpus online\n", __func__, num_online_cpus());
	if (arch_has_clwb())
		support_clwb = 1;

	nova_info("Arch new instructions support: CLWB %s\n",
			support_clwb ? "YES" : "NO");

	rc = init_rangenode_cache();
	if (rc)
		goto out;

	rc = init_inodecache();
	if (rc)
		goto out1;

	rc = register_filesystem(&nova_fs_type);
	if (rc)
		goto out2;

out:
	NOVA_END_TIMING(init_t, init_time);
	return rc;

out2:
	destroy_inodecache();

out1:
	destroy_rangenode_cache();
	goto out;
}

static void __exit exit_nova_fs(void)
{
	unregister_filesystem(&nova_fs_type);
	destroy_inodecache();
	destroy_rangenode_cache();
}

MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("NOVA: NOn-Volatile memory Accelerated File System");
MODULE_LICENSE("GPL");

module_init(init_nova_fs)
module_exit(exit_nova_fs)
