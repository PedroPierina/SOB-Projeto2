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
#include <linux/delay.h>

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

static struct info_files arquivos;


ssize_t write_modified(struct kiocb *iocb, struct iov_iter *from){
	arquivos.id = 0;
	if(arquivos.id == 0){
		arquivos.sizeFileDecrypted = from->count;
	}
	encryptDados(from, arquivos.id);
	
	return generic_file_write_iter(iocb,from);
}

ssize_t read_modified(struct kiocb *iocb, struct iov_iter *iter){
	int delay;

	for(delay = 0; delay < 10000; delay++){
		if(strlen((char*)iter->iov->iov_base) > 0) break;
	}
	if(delay == 10000){
		pr_info("Chegou porra nenhuma");
	}
	else{
		pr_info("Dados antes de entrar no decrypt %s", (char*)iter->iov->iov_base);		
		decryptDados(iter, 0);
	}
	return generic_file_read_iter(iocb,iter);
}

void encryptDados(struct iov_iter *from, int id){
	char *addrKey;
	struct info_files *fileInfo = &arquivos;
	char *interator;
	char **addrDados = (char**)&(from->iov->iov_base);
	char *stringEncriptada;
	int numBlocos, byteslastblock, i;
	struct crypto_cipher *tfm;
	
	interator = *addrDados;
	// Get Cipher Key
	addrKey = getKey();

	// Number or blocks and number of lastblock and number of bytes in last block
	if((*fileInfo).id != id){
		pr_info("Arquivo Errado");
	}
	numBlocos = (*fileInfo).sizeFileDecrypted/CIPHER_BLOCK_SIZE;
	byteslastblock = (*fileInfo).sizeFileDecrypted%CIPHER_BLOCK_SIZE;
	if(byteslastblock) numBlocos++;
	(*fileInfo).sizeFileEncrypted = numBlocos * CIPHER_BLOCK_SIZE;
	pr_info("Numeros Calculados: numblocos: %d, byteslastblock: %d", numBlocos, byteslastblock);

	// Alloc memory for the result
	stringEncriptada = kmalloc(CIPHER_BLOCK_SIZE * numBlocos, GFP_KERNEL);
	memset(stringEncriptada, 0, CIPHER_BLOCK_SIZE * numBlocos);
	pr_info("StringEncryptada deve ser vazia: %s", stringEncriptada);

	// Alloc crypto
	tfm = crypto_alloc_cipher("aes", 0, CIPHER_BLOCK_SIZE);
	crypto_cipher_setkey(tfm, addrKey, CIPHER_BLOCK_SIZE);
	pr_info("Cripto Alocado");

	pr_info("Dados decifrados write: %s", *addrDados);
	// Encrypting
	for(i = 0; i < numBlocos; i++){
		
		crypto_cipher_encrypt_one(tfm, stringEncriptada + (CIPHER_BLOCK_SIZE * i), interator);
		
		interator = interator + CIPHER_BLOCK_SIZE;
	}
	// Copy result to data
	pr_info("Before memcpy: %s", *addrDados);
	memcpy(*addrDados, stringEncriptada, (*fileInfo).sizeFileEncrypted);
	pr_info("Dados cifrados write: %s", *addrDados);
	
	// Free crypto and stringEncriptada
	crypto_free_cipher(tfm);
	kfree(stringEncriptada);

}

void decryptDados(struct iov_iter *iter, int id){
	char *addrKey;
	char *interator;
	struct info_files *fileInfo = &arquivos;
	char **addrDados = (char**)&(iter->iov->iov_base);
	char *stringDecriptada;
	int numBlocos, i;
	struct crypto_cipher *tfm;

	// Delay to recive data
	udelay(5000);

	
	// Get Cipher Key
	addrKey = getKey();

	// Number or blocks and number of lastblock and number of bytes in last block
	if((*fileInfo).id != id){
		pr_info("Arquivo Errado");
	}
	numBlocos = (*fileInfo).sizeFileEncrypted/CIPHER_BLOCK_SIZE;
	pr_info("size in decrypt: %zd e num blocos %d", (*fileInfo).sizeFileEncrypted, numBlocos);
	// Alloc memory for the result
	stringDecriptada = kmalloc(CIPHER_BLOCK_SIZE * numBlocos, GFP_KERNEL);
	memset(stringDecriptada, 0, CIPHER_BLOCK_SIZE * numBlocos);
	pr_info("StringEncryptada deve ser vazia: %s", stringDecriptada);

	// Alloc crypto
	tfm = crypto_alloc_cipher("aes", 0, CIPHER_BLOCK_SIZE);
	crypto_cipher_setkey(tfm, addrKey, CIPHER_BLOCK_SIZE);
	pr_info("Cripto Alocado");

	pr_info("Dados cifrados read: %s", *addrDados);

	// Decrypting
	interator = *addrDados;
	for(i = 0; i < numBlocos; i++){

		crypto_cipher_decrypt_one(tfm, stringDecriptada + (CIPHER_BLOCK_SIZE * i), interator);

		interator = interator + CIPHER_BLOCK_SIZE;
		
	}
	// Copy result to data
	pr_info("Before memcpy: %s", stringDecriptada);
	memcpy(*addrDados, stringDecriptada,  (*fileInfo).sizeFileDecrypted);
	
	pr_info("Dados decifrados read: %s", *addrDados);
	
	// Free crypto and stringDecriptada
	crypto_free_cipher(tfm);
	kfree(stringDecriptada);

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
