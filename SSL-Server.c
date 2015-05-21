//SSL-Server.c
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/aes.h>
#include <openssl/rand.h>

#define FAIL    -1

char buf[1024];
char UsedSessions[100][2];
int SessionCount=0;
char sessionNum ='0';


//AES 256 encryption of data on cloud
static void hex_print(const void* pv, size_t len)
{
	 const unsigned char * p = (const unsigned char*)pv;
	 
	 if (NULL == pv)
    	 printf("NULL");
	 
	 else{
    	 size_t i = 0;
     	 for (; i<len;++i)
              printf("%c", *p++);
 	 }
	 printf("\n");
}

//This function contains the AES Encyption and Decryption logic used
void AESEncryptData(const char* filename,int choice)
{

  int keylength=256;    /* generate a key with a given length */

  //Key used for Encryption and Decryption
  unsigned char aes_key[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0x6E,0xF8,0x07,0x11,0x25,0x32,0x47,0x57,0x66,0x74,0x88,0x90,0x2A,0x3B,0xCE,0x4D,0xEE,0xFA};
	   /* unsigned char aes_key[keylength/8];
	    memset(aes_key, 0, keylength/8);
	    if (!RAND_bytes(aes_key, keylength/8))
	        exit(-1);*/


   size_t inputslength = sizeof(buf);  /* generate input with a given length */
   unsigned char aes_input[inputslength];
   memcpy(aes_input, buf, inputslength);

  /* init vector */
   unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
   memset(iv_enc,0x00,AES_BLOCK_SIZE);
   memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
 
  // buffers for encryption and decryption
   const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
   unsigned char enc_out[encslength];
   unsigned char dec_out[inputslength];
   memset(enc_out, 0, sizeof(enc_out));
   memset(dec_out, 0, sizeof(dec_out));
 
  //Path where the encrypted file will be Stored
   char filepath[90]="/Users/prashanth/Desktop/try-1/ProejectTry-2/cloud/";
   strcat(filepath, filename);

   AES_KEY enc_key, dec_key;
   
   //Upload Scenario
   if(choice ==1){
   
   		AES_set_encrypt_key(aes_key, keylength, &enc_key);
	    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
	    printf("encrypted message of File: \n");

	    hex_print(enc_out, sizeof(enc_out));
	    printf("\n\nPath where file is stored at server :%s\n",filepath);

	    FILE *restFp = fopen(filepath, "wb");

	    if(restFp == NULL)
	    	printf("Sorry, file cannot be created\n");
	    else{
	    	fwrite(enc_out,sizeof(unsigned char), sizeof(enc_out),restFp);
	    	fclose(restFp);
	    	printf("\nFile created at server\n");

	    }
	    /*
	    AES_set_decrypt_key(aes_key, keylength, &dec_key);
	    AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);
	    printf("decrypt:\t");
	    */		    	    				  
	    // hex_print(dec_out, sizeof(dec_out));
	}
	 
	//Download Scenario    
	else{
	    
	    FILE *restFp = fopen(filepath, "rb");
	    if(restFp == NULL)
	    	printf("Sorry, file cannot be found\n");
	    else{
	    	//printf("%lu",sizeof(buf));
	    	fread(buf,sizeof(unsigned char), sizeof(buf),restFp);
	    	inputslength = sizeof(buf);
	    	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	    	memcpy(enc_out, buf,inputslength);
	    	printf("\n\n Decrypting File...\n");
	    	hex_print(enc_out, sizeof(enc_out));
			AES_set_decrypt_key(aes_key, keylength, &dec_key);
			AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);
			//printf("decrypted Message:\t");
		    //  hex_print(dec_out, sizeof(dec_out));
			//buf =0;
			sprintf(buf,"%s",dec_out);
			//printf("After utting to bugf---%s",buf);
			 fclose(restFp);
	    }

	//printf("decrypt:\t");
	//hex_print(dec_out, sizeof(dec_out));
	}
}


//Open a port for Listening
int OpenListener(int port)
{   
	int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 ){
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

//Checking if the program is being run as root
int isRoot()
{
    if (getuid() != 0){
        return 0;
    }
    else{
        return 1;
    }

}

SSL_CTX* InitServerCTX(void)
{   
	SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
	       ERR_print_errors_fp(stderr);

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	       ERR_print_errors_fp(stderr);


	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) ){
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


void ShowCerts(SSL* ssl)
{  
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL ){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
   
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   
	
    char reply[1024], file[56];
    int sd, bytes, fileint;
    int itr=0;
    SSL_CTX_set_verify(SSL_get_SSL_CTX(ssl), SSL_VERIFY_PEER, NULL);

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else{
        ShowCerts(ssl);        /* get any certificates */
        
        //Handling Data replay attack using rand session variable
		srand(time(NULL));
        int sessionNum = rand()%100;
        char ack[10];
        sprintf(ack,"%d",sessionNum);

        int attack=0;

        fileint = SSL_read(ssl,file, sizeof(file));
        
        if(strcmp(file, "DOWNLOAD")==0){
        	SSL_write(ssl,ack, 10);
        	printf("Command received: %s\n\n",file);
        	//Verify token and filename
        	char verifyFile[50];
        	SSL_read(ssl,verifyFile, sizeof(verifyFile) );
        	printf("filename: %s\n\n",verifyFile);
        	char * session=strtok(verifyFile,"-");
        	char * filename = strtok(NULL,"-");
        	
        	//Checking for session number to see if it is a replay attack 
        	for(itr=0; itr<25;itr++)
        	{
        		if(strcmp(UsedSessions[itr], session)==0)
        		{			attack =1;
        			break;
        		}

        	}
        	if(attack ==1)
        		SSL_write(ssl,"REPLAY ATTACK",15);
        	else{
        		AESEncryptData(filename,2);

        		printf("Client msg: \"%s\"\n", filename);
        		sprintf(reply, "%s", buf);   /* construct reply */
        		SSL_write(ssl, reply, strlen(reply)); /* send reply */
        		memset(buf,0,sizeof(buf));
        		sprintf(UsedSessions[SessionCount],"%d",sessionNum);
        		//printf("\nfdgddg: %s",UsedSessions[SessionCount++]);
        	}

        }
        
        //UPLOAD Scenario
        else{
        	SSL_write(ssl,"Uploading File", 10);
        	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        	        if ( bytes > 0 ){
        	            buf[bytes] = 0;
        	            AESEncryptData(file,1);
        	            //printf(": \"%s\"\n", buf);
        	            printf("File received ... Encrypted\n");
        	            sprintf(reply, "%s", buf);   /* construct reply */
        	            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        	            memset(buf,0,sizeof(buf));
        	        }
        	        else
        	            ERR_print_errors_fp(stderr);
        }

	}
	
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int main(int count, char *strings[])
{   
	SSL_CTX *ctx;
    int server;
    char *portnum;

    if(!isRoot()){
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    
    if ( count != 2 ){
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    
    SSL_library_init();
	portnum = strings[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert1.pem", "mycert1.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    
    while (1)
    {   struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        //added for user verification data replay

        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}

