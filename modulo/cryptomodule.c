#include "cryptomodule.h"

// Necessary Scructs for crypto API
struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

// Global Variables 
char *keyHex;



module_param(keyHex, charp, 0);
MODULE_PARM_DESC(keyHex, "A character string in HEX");

/*
	Funcao: stringParaHexadecimal
	Funcao para transformar a representacao de dados
	hexadecimal em string para os valores originais.
	Ex.:
		"41" -> 'A'
*/
static void stringParaHexadecimal(size_t const size, char *stringHex, char *stringNorm)
{
	int i, j;

	// Loop transformando toda letra para seu valor em hexadecimal
	// A -> 1010

	for (i = 0; i < size; i++)
	{	
		if ((int)stringHex[i] >= 48 && (int)stringHex[i] <= 57)
			stringHex[i] -= (char)48;
		else if ((int)stringHex[i] >= 97 && (int)stringHex[i] <= 102)
			stringHex[i] -= (char)87;
		else if ((int)stringHex[i] >= 65 && (int)stringHex[i] <= 70)
			stringHex[i] -= (char)55;
		else
			pr_info("ERROR: String em Hexa contem valor desconhecido -> %i", i);
	}

	// Concatenação em um unico byte
	// 00001010, 00000011 -> 10100011
	j = 0;
	for (i = 0; i < size / 2; i++)
	{	
		if(size%2 == 1 && i == size-1){
			stringNorm[i] = (stringHex[j] << 4) + 0b00000000;
			size_of_hex_msg++;
		}
		else{
			stringNorm[i] = (stringHex[j] << 4) + stringHex[j + 1];
		}
		j += 2;
	}
}
//========================================================================================

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                     int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
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

/* Initialize and trigger cipher operation */
static int test_skcipher(void)
{
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    char *scratchpad = NULL;
    char *ivdata = NULL;
    unsigned char key[32];
    int ret = -EFAULT;

    skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

    /* AES 256 with random key */
    get_random_bytes(&key, 32); // Mudar para receber key dada pelo usuario
	
    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16);

    /* Input data will be random */
    scratchpad = kmalloc(16, GFP_KERNEL);
    if (!scratchpad) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    get_random_bytes(scratchpad, 16);

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, scratchpad, 16);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);

    /* encrypt data */
    ret = test_skcipher_encdec(&sk, 1);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    if (scratchpad)
        kfree(scratchpad);
    return ret;
}

//====================================================================================
/* Função que será chamada quando o modulo é instalado */
static int __init cryptomodule_init(void)
{
	return SUCCESS;
}

/* Função que será chamada quando o modulo é removido  */
static void __exit cryptomodule_exit(void)
{
}

/* Registra quais funções devem ser chamadas para cada "evento"  */
module_init(cryptomodule_init);
module_exit(cryptomodule_exit);

/* Informações sobre o módulo  */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Grupo SOB");
MODULE_DESCRIPTION("Write/Read encrypted files in Minix File System.");
