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

struct skcipher_def sk;

const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= &read_modified,
	.write_iter	= &write_modified, 
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read 	= generic_file_splice_read,
};

ssize_t write_modified(struct kiocb *iocb, struct iov_iter *from){

	char **dadosFinais = (char **)&(from->iov->iov_base);
	pr_info("file: write %s", *dadosFinais);

	cryptoDados(dadosFinais,1, (size_t *)&(from->iov->iov_len));
	
	pr_info("write_modified: Resultado Cifrado resultCrypto %s", *dadosFinais);
	pr_info("write_modified: Resultado Cifrado from->iov->iov_base %s", (char *)(from->iov->iov_base));

	return generic_file_write_iter(iocb,from);
}

ssize_t read_modified(struct kiocb *iocb, struct iov_iter *from){

	char **dadosFinais = (char **)&(from->iov->iov_base);
	ssize_t ret;
	pr_info("1-file: read %s", *dadosFinais);

	ret = generic_file_read_iter(iocb,from);
	cryptoDados(dadosFinais,0, (size_t *)&(from->iov->iov_len));

	pr_info("9-read_modified: Resultado Decifrado resultCrypto %s", *dadosFinais);
	pr_info("11-read_modified: Resultado Decifrado from->iov->iov_base %s", (char *)(from->iov->iov_base));
	
	return ret;
}

void cryptoDados(char **addrDados, int opcao, size_t *sizeiov){

	char *addrKey;
	char *stringAux;
	int   nBlocos;
	int size;
	
	sk.tfm = NULL;
	sk.req = NULL;
	sk.scratchpad = NULL;
	sk.ciphertext = NULL;
	sk.ivdata = NULL;
	
	
		
	size = strlen(*addrDados);
	/*------------------------Key-----------------------------*/
	// Get Cipher Key

	addrKey = getKey();
	
	pr_info("2-cryptoDados:1 key %s", getKey());

	/*--------------------------------------------------------*/

	/*------------------------Trata-Dados-----------------------------*/

	pr_info("3-cryptoDados: Tamanho msg %d", size);

	nBlocos = size/CIPHER_BLOCK_SIZE;
	if(size%CIPHER_BLOCK_SIZE)nBlocos++;
	*sizeiov = nBlocos * CIPHER_BLOCK_SIZE;
	stringAux = (char*)kmalloc((nBlocos + 1) * CIPHER_BLOCK_SIZE, GFP_KERNEL);
	memset(stringAux, 0, (nBlocos + 1) * CIPHER_BLOCK_SIZE);
	memcpy(stringAux, *addrDados, size);

	pr_info("4-cryptoDados: nBlocos %d", nBlocos);
	pr_info("5-cryptoDados: opcao %i",opcao);

	test_skcipher_encrypt_decrypt(stringAux, addrKey, &sk, nBlocos,opcao);
	/*----------------------------------------------------------------*/
	/*------------------------Trata-Dados-Cifrados--------------------*/

	pr_info("8-cryptoDados: Resultado Crypto textInCipher %s", stringAux);
	test_skcipher_finish(&sk);
	/*----------------------------------------------------------------*/
	memcpy(*addrDados, stringAux, nBlocos * CIPHER_BLOCK_SIZE);
	kfree(stringAux);
	return;
}


int test_skcipher_encrypt_decrypt(char *plaintext, char *password,struct skcipher_def *sk,int nBlocos,int opcao)
{
	int ret = (int)(-EFAULT);
	int j;
	unsigned char key[SYMMETRIC_KEY_LENGTH + 1];
	char *bloco;
	
	pr_info("test_skcipher_encrypt_decrypt: opcao %i",opcao);

	if (!sk->tfm)
	{
		sk->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
		if (IS_ERR(sk->tfm))
		{
			pr_info("could not allocate skcipher handle\n");
			return PTR_ERR(sk->tfm);
		}
	}
	if (!sk->req)
	{
		sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL);
		if (!sk->req)
		{
			pr_info("could not allocate skcipher request\n");
			ret = -ENOMEM;
			goto out;
		}
	}

	skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
								  test_skcipher_callback,
								  &sk->result);
	/* clear the key */

	memset((void *)key, '\0', SYMMETRIC_KEY_LENGTH);

	memcpy((char *)key,password, SYMMETRIC_KEY_LENGTH);

	/* AES 128 with given symmetric key */
	if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH))
	{
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	
	if (!sk->ivdata)
	{
		/* see https://en.wikipedia.org/wiki/Initialization_vector */
		sk->ivdata = vmalloc(CIPHER_BLOCK_SIZE);
		if (!sk->ivdata)
		{
			pr_info("could not allocate ivdata\n");
			goto out;
		}
		get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE);
	}

	if (!sk->scratchpad)
	{
		/* The text to be encrypted */
		sk->scratchpad = vmalloc(CIPHER_BLOCK_SIZE);
		if (!sk->scratchpad)
		{
			pr_info("could not allocate scratchpad\n");
			goto out;
		}
	}
	pr_info("6-test_skcipher_encrypt_decrypt: Plaintext %s\n", plaintext);
	pr_info("7-test_skcipher_encrypt_decrypt: nBlocos %i", nBlocos);

	for(j=0;j<nBlocos;j++){
		memcpy(sk->scratchpad,plaintext+CIPHER_BLOCK_SIZE*j,CIPHER_BLOCK_SIZE);
		
		sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE);
		skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg,
								CIPHER_BLOCK_SIZE, sk->ivdata);
		
		init_completion(&sk->result.completion);
		/* encrypt data */

		if(opcao == 1)
			ret = crypto_skcipher_encrypt(sk->req);
		if(opcao == 0)
			ret = crypto_skcipher_decrypt(sk->req);
	
		ret = test_skcipher_result(sk, ret);

		if(ret)
			return ret;

		
    	bloco = sg_virt(&(sk->sg));
		
		memcpy(plaintext+CIPHER_BLOCK_SIZE*j,bloco,CIPHER_BLOCK_SIZE);
		
	}

out: 
	return ret;
}

void test_skcipher_callback(struct crypto_async_request *req, int error)
{
	struct tcrypt_result *result = req->data;
	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	pr_info("Encryption finished successfully result\n");
}

int test_skcipher_result(struct skcipher_def *sk, int rc)
{
	switch (rc)
	{
	case 0:
		break;
	case -EINPROGRESS:

	case -EBUSY:
		rc = wait_for_completion_interruptible(
			&sk->result.completion);
		if (!rc && !sk->result.err)
		{
			reinit_completion(&sk->result.completion);
			break;
		}
	default:
		pr_info("skcipher encrypt returned with %d result %d\n",
				rc, sk->result.err);
		break;
	}

	init_completion(&sk->result.completion);
	return rc;
}

void test_skcipher_finish(struct skcipher_def *sk)
{
	if (sk->tfm)
		crypto_free_skcipher(sk->tfm);
	if (sk->req)
		skcipher_request_free(sk->req);
	if (sk->ivdata)
		vfree(sk->ivdata);
	if (sk->scratchpad)
		vfree(sk->scratchpad);
	if (sk->ciphertext)
		vfree(sk->ciphertext);
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
