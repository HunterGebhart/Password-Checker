/*include libraries and definitions for some variables to be visible*/
#define h_addr h_addr_list[0]
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>  // Include for gethostbyname()
#include <unistd.h>
#include "sha256_lib.h"
#include "time.h"

int     clientSocket;    /* socket descriptor                   */ 
int     port;            /* protocol port number                */  

int main(int argc, char *argv[])
{ 
  struct  sockaddr_in sad; /* structure to hold an IP address     */
  struct  hostent  *ptrh;  /* pointer to a host table entry       */
  char    *host;           /* pointer to host name                */
  struct timespec begin, end;
  
  /*Check if correct number of arguments*/
  if (argc != 3) {
    fprintf(stderr,"Usage: %s server-name port-number\n",argv[0]);
    exit(1);
  }
  
  /* Extract host-name from command-line argument */
  host = argv[1];         /* if host argument specified   */
  
  /* Extract port number  from command-line argument */
  port = atoi(argv[2]);   /* convert to binary            */
  
  /*An int to read menu option and a buffer to read keyboard input*/
  int option;
  char buffer[1000];

  /*Do while loop for the menu*/
  do{

    /* Create a socket. */
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
      fprintf(stderr, "socket creation failed\n");
      exit(1);
    }
    printf("Socket created\n");

    /* Connect the socket to the specified server. */

    memset((char *)&sad,0,sizeof(sad)); /* clear sockaddr structure */
    sad.sin_family = AF_INET;           /* set family to Internet     */
    sad.sin_port = htons((uint16_t)port);
    ptrh = gethostbyname(host); /* Convert host name to equivalent IP address and copy to sad. */
    if ( ((char *)ptrh) == NULL ) {
      fprintf(stderr,"invalid host: %s\n", host);
      exit(1);
    }
    memcpy(&sad.sin_addr, ptrh->h_addr, ptrh->h_length);
    
    /*connect to socket*/
    if (connect(clientSocket, (struct sockaddr *)&sad, sizeof(sad)) < 0) {
      fprintf(stderr,"connection failed\n");
      exit(1);
    }
    printf("Connected to Socket\n");
    
    /*display menu*/
    printf("Please choose an option:\n1 - check username/email\n2 - check password\n3 - check both username/email and password\n4 - exit\n");
    fgets(buffer, 1000, stdin);
    sscanf(buffer, "%d", &option);

    /*check option*/
    if(option == 1)
    {
      /*Read username from keyboard*/
      char user[1000];
      printf("Enter username/email\n");
      fgets(buffer, 1000, stdin);
      strcpy(user, buffer);
      user[strcspn(user, "\n")] = 0;

      /*declare variables for hashing*/
      SHA256_CTX ctx;
      uint8_t hash[SHA256_DIGEST_SIZE];
      int fieldCheck = 1; /*this tells the server what the user wants the server to check (username and/or password)*/
      uint8_t *data;

      /*initialize the data to be hashed*/
      data = (uint8_t *) user;

      /*hashing operations*/
      sha256_init(&ctx);
      sha256_update(&ctx, data, strlen((char *)data));
      sha256_final(&ctx, hash);
      
      printf("Input for SHA-256 Hash: %s\n", data);

      /*start timer for server response*/
      clock_gettime(CLOCK_MONOTONIC, &begin);

      /*Send the hash to the server*/
      write(clientSocket, &fieldCheck, sizeof(int));
      write(clientSocket, &hash, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
    }
    /*check the option*/
    else if(option == 2)
    {
      /*read password from keyboard*/
      char pass[1000];
      printf("Enter password\n");
      fgets(buffer, 1000, stdin);
      strcpy(pass, buffer);
      pass[strcspn(pass, "\n")] = 0;

      /*variables for hashing*/
      SHA256_CTX ctx;
      uint8_t hash[SHA256_DIGEST_SIZE];
      int fieldCheck = 2; /*this tells the server what the user wants the server to check (username and/or password)*/
      uint8_t *data;

      /*initialize the data to be hashed*/
      data = (uint8_t *) pass;

      /*hash the data*/
      sha256_init(&ctx);
      sha256_update(&ctx, data, strlen((char *)data));
      sha256_final(&ctx, hash);
      
      printf("Input for SHA-256 Hash: %s\n", data);

      /*start timer for server response*/
      clock_gettime(CLOCK_MONOTONIC, &begin);

      /*send hash to server*/
      write(clientSocket, &fieldCheck, sizeof(int));
      write(clientSocket, &hash, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
      
    }
    /*check option*/
    else if(option == 3)
    {
      /*read username from keyboard*/
      char user[1000];
      printf("Enter username/email\n");
      fgets(buffer, 1000, stdin);
      strcpy(user, buffer);
      user[strcspn(user, "\n")] = 0;

      /*read password from keyboard*/
      char pass[1000];
      printf("Enter password\n");
      fgets(buffer, 1000, stdin);
      strcpy(pass, buffer);
      pass[strcspn(pass, "\n")] = 0;

      /*variables to be used in hashing*/
      SHA256_CTX ctx1, ctx2;
      uint8_t hash1[SHA256_DIGEST_SIZE], hash2[SHA256_DIGEST_SIZE];
      int fieldCheck = 3; /*this tells the server what the user wants the server to check (username and/or password)*/
      uint8_t *data1, *data2;

      /*initialize data to be hashed*/
      data1 = (uint8_t *) user;
      data2 = (uint8_t *) pass;
      
      /*hash the data*/
      sha256_init(&ctx1);
      sha256_update(&ctx1, data1, strlen((char *)data1));
      sha256_final(&ctx1, hash1);

      /*hash the data*/
      sha256_init(&ctx2);
      sha256_update(&ctx2, data2, strlen((char *)data2));
      sha256_final(&ctx2, hash2);
      printf("Input for SHA-256 Hash: %s:%s\n", data1, data2);

      /*start timer for server response*/
      clock_gettime(CLOCK_MONOTONIC, &begin);

      /*send hash to the server*/
      write(clientSocket, &fieldCheck, sizeof(int));
      write(clientSocket, &hash1, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
      write(clientSocket, &hash2, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
    }
    /*check invalid option*/
    else if(option != 4)
    {
      printf("Invalid option\n");
      continue;
    }
    /*if option is 4, skip to next iteration then exit loop*/
    else if(option == 4)
    {
      break;
    }
    /*read the message from the server, stop timer, then print message and the response time*/
    char message[100];
    read(clientSocket, message, 100);
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("<<<%s>>>\n", message);

    double elapsed = begin.tv_sec - end.tv_sec;
    elapsed += (end.tv_nsec - begin.tv_nsec) / 1000000000.0;
    elapsed += elapsed*1000;

    printf("Time to recieve server response: %0.2fms\n", elapsed);

    /* Close the socket. */
    printf("Terminating connection\n");  
    close(clientSocket);

  }while(option != 4);
  
  printf("Exiting program\n");

  return 0;  
}


