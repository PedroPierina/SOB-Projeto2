/*
 *   Definições das operações de manipulação de arquivos que serão
 * usadas para acessar o nó criado em /dev
 *
 *   Definitions for the file hander operations whose will be used
 * to access the node created inside /dev
 *
 */
/*-------------------------------Bibliotecas---------------------------------------*/
#include <linux/kernel.h>         //Necessario para para fazer a build do module e função printk
#include <linux/init.h>           //Necessario para usar macro das funções init_module e cleanup_module...
#include <linux/module.h>         //Necessario para todo modulo de kernel
#include <linux/fs.h>             //para usar file_operations
#include <linux/uaccess.h>	      //Para acessar a memoria do usuario.
#include <linux/errno.h>          //biblioteca para exibir os erros
#include <linux/miscdevice.h>     //Permite o uso de um misc device(declaração de um driver novo)
#include <linux/slab.h>           //Permite o uso do kmalloc e do kfree
#include <linux/crypto.h>         //biblioteca para encriptar
#include <linux/device.h>         //controle de um dispositivo
#include <linux/cdev.h>		        //Dispositivo do tipo de caracteres, usado para gravar-lo no sistema e identificar o dispositivo.
#include <linux/irq.h>		        //Interrupção a qual a notificação se aplica.
#include <asm/uaccess.h>	        //Acesso do usuario (ativando/desativando) macros.
#include <asm/irq.h>		          //
#include <asm/io.h>		            //Genérico IO read/write. Executa acesso Native-Endian.
#include <linux/poll.h>		        //wait for some event on a file descriptor.

#include <crypto/internal/skcipher.h>
#include <crypto/internal/hash.h> 

/*-------------------------------Defines---------------------------------------*/
#define DEVICE_NAME "cryptomodule"
#define DISK_SIZE 4096
#define BUF_LEN 130
#define SUCCESS 0
#define TAMMAX 100

#define SYMMETRIC_KEY_LENGTH 16
#define CIPHER_BLOCK_SIZE 16

#define SHA256_LENGTH (256/8) 

/*-------------------------------Headers---------------------------------------*/
static ssize_t device_read(struct file *, char *, size_t, loff_t *);

static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int device_open(struct inode *, struct file *);

static int device_release(struct inode *, struct file *);
