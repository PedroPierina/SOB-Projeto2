#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)

static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

void stringtoHex(char *str);
void getString(char *str);
void writeModule(char *str, int fd);
void readModule(int fd);

void stringtoHex(char *str){
    char strAux[strlen(str)*2];
    int size = strlen(str);

    int i;
    for(i = 0; i < size; i++){
        sprintf(&strAux[i*2], "%02hhX", str[i]);
    }
    str[i*2] = '\0';
	
    strcpy(str, strAux);
	printf("String em hexa = %s \n", str);
}

int main(){
 int fd, opcao;
    char stringToSend[BUFFER_LENGTH];
    char stringModulo[BUFFER_LENGTH];

    /*---------------------Open-file--------------------*/
    printf("Iniciando o modulo...\n");
    fd = open("/dev/cryptomodule", O_RDWR); // Abrir o arquivo com permissao para escrita e leitura
    if (fd < 0)
    {
        perror("Erro ao iniciar o modulo...");
        return errno;
    }

    // Menu
    printf("Menu:\n");
    printf("1- Cifrar String\n");
    printf("2- Cifrar Valores Hexadecimais\n");
    printf("3- Decifrar\n");
    printf("4- Calcular Hash\n");    
    printf("0- Sair\n");
    scanf("%d", &opcao);

    // Get string
    switch(opcao){
        case 1:
            getchar();
            printf("Digite a String para Encriptar:\n");
            scanf("%[^\n]%*c", stringToSend); // String que sera envida para o modulo
            stringtoHex(stringToSend);
            printf("%s\n", stringToSend);
            stringModulo[0] = 'c';
            stringModulo[1] = ' '; 
            strcat(stringModulo, stringToSend);//indica ao modulo que eh string
            printf("String para Encriptar: %s\n",stringModulo);
            break;
        case 2:
            getchar();
            printf("Digitar valor Hexadecimal:\n");
            scanf("%[^\n]%*c", stringToSend); // String que sera envida para o modulo
            stringModulo[0] = 'c';
            stringModulo[1] = ' '; 
            strcat(stringModulo, stringToSend);
            printf("Hexadecimal para Encriptar: %s\n",stringModulo);
            break;
        case 3://Perguntar para oque serve.
            getchar();
            printf("Digitar valor Hexadecimal:\n");
            scanf("%[^\n]%*c", stringToSend); // String que sera envida para o modulo
            stringModulo[0] = 'd';
            stringModulo[1] = ' '; 
            strcat(stringModulo, stringToSend);
            printf("Hexadecimal para Decifrar: %s\n",stringModulo);
            break;
        case 4://Perguntar para oque serve.
            getchar();
            printf("Digite a String para calcular o Hash:\n");
            scanf("%[^\n]%*c", stringToSend); // String que sera envida para o modulo
            stringtoHex(stringToSend);
            printf("%s\n", stringToSend);
            stringModulo[0] = 'h';
            stringModulo[1] = ' '; 
            strcat(stringModulo, stringToSend);//indica ao modulo que eh string
            printf("String para Encriptar: %s\n",stringModulo);
            break;
        case 0:
            return 0;
            break;
    }

    // Send String
    writeModule(stringModulo, fd);
    // Read Answer
    readModule(fd);

    printf("Finalizando o modulo...\n");
    
    if (close(fd))// Fechar o arquivo com permissao para escrita e leitura
    {
        perror("Erro ao fechar aquivo o modulo...");
        return errno;
    }
    return 0;
}

void getString(char *str){
    scanf("%s",str);
}

void writeModule(char *str, int fd){
    int ret;
    printf("Escrevendo a mensagem [%s] no modulo .\n", str);
    ret = write(fd, str, strlen(str)); // envio da string para o modulo
    if (ret < 0)
    {
        perror("Erro no envio da string.");
        printf("Erro no: %ls", &errno);
        return;
    }
    printf("Aperte ENTER para ler a resposta..\n");
    getchar();
}

void readModule(int fd){
    int ret;
    printf("Lendo do modulo...\n");
    ret = read(fd, receive, BUFFER_LENGTH); // Leitura do buffer
    if (ret < 0)
    {
        perror("Erro na leitura da mensagem.");
        printf("Erro no: %ls", &errno);
        return;
    }
    printf("Mensagem recebida: [%s]\n", receive);
    printf("Aperte ENTER para sair..\n");
    getchar();
}