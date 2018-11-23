// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
//static size_t teste(struct kiocb *iocb, struct iov_iter *from);
/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= &teste, //void *function = &teste; (*function)();
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read 	= generic_file_splice_read,
};

static ssize_t teste(struct kiocb *iocb, struct iov_iter *from){
	ssize_t ret;
	ssize_t bytes = from->count;
	char addr[100];
	int i;

	pr_info("file: count %i", (int)bytes);
	//ret = copy_to_iter((void *)addr, bytes, from);
	//pr_info("file: valor addr %s",addr);
	//for (i = 0; i < 100; i++)
	//{

	// 	pr_info("file: addr %c", addr[i]);
		
	// }
	pr_info("file: ret %i", (int) ret);
	pr_info("file: teste %s", (char *)(from->iov->iov_base));
	pr_info("file: key %s", getKey());
	//generic_file_write_iter(iocb,from);		
	
	return generic_file_write_iter(iocb,from);
}

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;
	pr_info("file:minix_setattr");
	error = setattr_prepare(dentry, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		minix_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};
