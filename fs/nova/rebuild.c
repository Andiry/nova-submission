/*
 * BRIEF DESCRIPTION
 *
 * Inode rebuild methods.
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

#include "nova.h"
#include "inode.h"

/* initialize nova inode header and other DRAM data structures */
int nova_rebuild_inode(struct super_block *sb, struct nova_inode_info *si,
	u64 ino, u64 pi_addr, int rebuild_dir)
{
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pi;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	// We need this valid in case we need to evict the inode.

	nova_init_header(sb, sih, __le16_to_cpu(pi->i_mode));
	sih->pi_addr = pi_addr;

	if (pi->deleted == 1) {
		nova_dbgv("%s: inode %llu has been deleted.\n", __func__, ino);
		return -ESTALE;
	}

	nova_dbgv("%s: inode %llu, addr 0x%llx, valid %d, head 0x%llx, tail 0x%llx\n",
			__func__, ino, pi_addr, pi->valid,
			pi->log_head, pi->log_tail);

	sih->ino = ino;

	/* Traverse the log */
	return 0;
}

