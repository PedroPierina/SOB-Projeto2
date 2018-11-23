// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"
#include <linux/crypto.h>
//static size_t teste(struct kiocb *iocb, struct iov_iter *from);
/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= &read_modified,
	.write_iter	= &write_modified, 
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read 	= generic_file_splice_read,
};

static ssize_t write_modified(struct kiocb *iocb, struct iov_iter *from){

	char *addrDados = (char *)(from->iov->iov_base);

	pr_info("file: teste %s", addrDados);
	pr_info("file: key %s", getKey());

	encryptDados(&addrDados);
	
	return generic_file_write_iter(iocb,from);
}

static ssize_t read_modified(struct kiocb *iocb, struct iov_iter *from){

	char *addrDados = (char *)(from->iov->iov_base);
	
	return generic_file_read_iter(iocb,from);
}

static void encryptDados(char **addrDados){
	char *addrKey, block[CIPHER_BLOCK_SIZE];
	int numBlocos, byteslastblock, i, j;
	struct crypto_cipher *tfm;

	// Get Cipher Key
	addrKey = getKey();

	// Number or blocks and number of lastblock and number of bytes in last block
	numBlocos = strlen(addrDados)/CIPHER_BLOCK_SIZE;
	byteslastblock = strlen(addrDados)%CIPHER_BLOCK_SIZE;
	if(byteslastblock) numBlocos++;

	// Alloc crypto
	tfm = crypto_alloc_cipher("ecb-aes-aesni", 0, CIPHER_BLOCK_SIZE);
	crypto_cipher_setkey(tfm, addrKey, CIPHER_BLOCK_SIZE);

	// Encrypting
	for(i = 0; i < numBlocos; i++){
		// if(byteslastblock && i == numBlocos - 1){
		// 	for(j = byteslastblock; j < CIPHER_BLOCK_SIZE; j++){
		// 		addrDados[i*CIPHER_BLOCK_SIZE + j] = 0;
		// 	}
		// }
		crypto_cipher_encrypt_one(tfm, block, *addrDados);
		pr_info("Block %i: %s", block);
		memcpy(*addrDados, block, CIPHER_BLOCK_SIZE);
		*addrDados += CIPHER_BLOCK_SIZE;
	}
	
	// Free crypto
	crypto_free_cipher(tfm);

}
static void decryptDados(char *addrDados){
	char *addrKey;
	addrKey = getKey();

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
