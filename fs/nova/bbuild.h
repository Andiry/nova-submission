#ifndef __BBUILD_H
#define __BBUILD_H

void nova_init_header(struct super_block *sb,
	struct nova_inode_info_header *sih, u16 i_mode);
void nova_save_inode_list_to_log(struct super_block *sb);
void nova_save_blocknode_mappings_to_log(struct super_block *sb);

#endif
