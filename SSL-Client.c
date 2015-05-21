//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
//#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
#define BUF_SIZE 1000


int OpenConnection(const char *hostname, int port)
{   
	int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL ){
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   
	SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


void ShowCerts(SSL* ssl)
{   
	X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    
    if ( cert != NULL ){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

//This function represents the HMAC-SHA1 logic used to check the message integrity
void calHmac( unsigned char * filecontents, char * filename,int choice){
	
	 // The secret key for hashing
    const char keyNew[] = "b89eaac7e61417341b710b727768294d0e6a277b";

    // Be careful of the length of string with the choosen hash engine. SHA1 needed 20 characters.
    // Change the length accordingly with your choosen hash engine.
    unsigned char* result;
    unsigned int len = 40;
    int size;

    result = (unsigned char*)malloc(sizeof(unsigned char) * len);
    memset(result,0,sizeof(unsigned char) * len);

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    // Using sha1 hash engine here.
    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
    HMAC_Init_ex(&ctx, keyNew, strlen(keyNew), EVP_sha256(), NULL);
    HMAC_Update(&ctx, (unsigned char*)filecontents, sizeof(filecontents)+1);
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);

    //Path where HMAC is stored
    char filepath[90]="/Users/prashanth/Desktop/try-1/ProejectTry-2/Hmac/";

    strcat(filepath, "Hmac-");
    strcat(filepath,filename);
    FILE *restFp=0;
        
    //writing hmac contents to new file for checking integrity(upload Scenario)
    if (choice ==1){
		restFp = fopen(filepath, "w");
    	if(restFp == NULL)
    		printf("Sorry, file cannot be created\n");
	    else{
        printf("\n hmac contents:%s,%d,, \n",result,len);
     	fwrite(result,sizeof(unsigned char), len,restFp);
     	fclose(restFp);
     	}
    }
    //checking the integrity of the file downloaded(download Scenario)
    else{
     	restFp = fopen(filepath, "r");
 		if(restFp == NULL)
 			printf("Sorry, file cannot be created\n");
 		else{
			unsigned char hmac_buf[100];
			size = fread(hmac_buf,sizeof(unsigned char),size ,restFp);
			hmac_buf[size]='\0';
			//printf("file contents:%s",filecontents);
			printf("\n hmac contents:%s\n%s\n\t\n",hmac_buf,result);
			//printf("readvalue:\t%d",size);
			fclose(restFp);
			if(strcmp(hmac_buf,result)==0){
				printf("Message Integirty CHeck : Passed\n\n");
			}
			else
				printf("Message Integirty CHeck : Failed\n\n");
     	}
     }

	printf("HMAC digest: ");

	for (int i = 0; i != len; i++)
        printf("%02x", (unsigned int)result[i]);

    printf("\n");
	free(result);

}

int main(int count, char *strings[])
{   
	SSL_CTX *ctx;
    int server;
    int choice=0;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;
    char filename[20] ;

    if ( count != 3 ){
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else{

        printf("Connected with %s encryption\n\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        printf("\n\n");
        printf("Welcome to Cloud Storage System :\n Enter 1 - FILE UPLOAD\n 2 - FILE DOWNLOAD \n ");
     	scanf("%d",&choice);

        if(choice ==1){
			printf("Enter the file name you want to upload :");
			scanf("    %s",filename);
			FILE *fp = fopen(filename,"r");
			if(fp==NULL){
				printf("File open error\n\n");
				SSL_free(ssl);
				 close(server);         /* close socket */
				 SSL_CTX_free(ctx);
				return 1;
			}

			SSL_write(ssl,filename,sizeof(filename));
			char ack[10];
			SSL_read(ssl,ack,sizeof(ack));
       	    printf("File name ACK received: %s\n\n",ack);
       	     /* Read data from file and send it. First read file in chunks of BUF_SIZE bytes */
            unsigned char buff[BUF_SIZE]={0};
            int nread = fread(buff,1,BUF_SIZE,fp);
            printf("Bytes read %d \n", nread);

            /* If read was success, send data. */
            if(nread > 0){
				printf("Sending File contents to server Side \n");
				SSL_write(ssl, buff, nread);  /* send file contents to server */
        		calHmac(buff,filename,choice);
            }
			
			// SSL_write(ssl, msg, strlen(msg));
 			bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
 			buf[bytes] = 0;
            printf("\nReceived: File Created at Server \n" );
        }
            
        else if(choice ==2){
            printf("Enter the file name you want to download :");
            scanf("    %s",filename);
            SSL_write(ssl,"DOWNLOAD",sizeof(filename));
            char ack[30];
            int replay=0;
            SSL_read(ssl,ack,sizeof(ack));
            printf("File name ACK received: %s\n\n",ack);
            strcat(ack,"-");
            strcat(ack,filename);
            printf("Do you want to try Replay Attack? If yes, enter 1:");
            scanf("%d",&replay);
            
            if(replay ==1){
            	printf("Enter the data to replay :");
            	scanf("%s",ack);
            	SSL_write(ssl,ack,sizeof(ack));
            }
            else{
           	SSL_write(ssl,ack,sizeof(ack));
            }
            
            unsigned char fileContent[256];
  			SSL_read(ssl,fileContent,sizeof(fileContent));
            printf("File Contents received: %s\n\n",fileContent);
            calHmac(fileContent,filename,choice);
            
            //path where downloaded files are stored
            char filepath[90]="/Users/prashanth/Desktop/try-1/ProejectTry-2/Download/";
            	            strcat(filepath,filename);
            	            FILE *DownloadFp=0;

            	            //writing Downloaded file contents to a new location
            	            DownloadFp = fopen(filepath, "w");
            	            if(DownloadFp == NULL)
            	                printf("Sorry, file cannot be created\n");
            	            else{
            	                fwrite(fileContent,sizeof(unsigned char), sizeof(fileContent),DownloadFp);
            	                printf("\n Path of Downloaded file:%s \n",filepath);
            	                fclose(DownloadFp);
            	                } // Directory al

        }
        
        else{
        	printf("Invalid Choice\n");
        	exit(0);
        }
        
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
