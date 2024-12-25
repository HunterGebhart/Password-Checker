/*include libraries and definitions to make some variables/functions visible*/
#define h_addr h_addr_list[0]
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256_lib.h"
#include "signal.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int     welcomeSocket, connectionSocket; /* socket descriptors  */
int     port;            /* protocol port number                */
FILE* file; /*global file pointer*/

/*SIGINT handler*/
void sigint_handler(int sig)
{
  /*Print closing message and close file and both socket descriptors then exit*/
  /*still gets bind failed error, not sure if I closed ports correctly*/
  printf("\n--- Closing files and ports due to CTRL-C: %d ---\n", sig);
  fclose(file);    
  close(connectionSocket);
  close(welcomeSocket);
  close(port);
  exit(0);
}

int main(int argc, char *argv[])
{
  struct  sockaddr_in sad; /* structure to hold server's address  */
  struct  sockaddr_in cad; /* structure to hold client's address  */
  socklen_t      alen;     /* length of address                   */
  
  /*setup SIGINT handler*/
  struct sigaction act_sigint;
  act_sigint.sa_handler = &sigint_handler;
  sigaction(SIGINT, &act_sigint, NULL);
  
  /* Check command-line argument for protocol port and extract   */
  /* port number if one is specified. Otherwise, give error      */
  if (argc > 1) {                /* if argument specified        */
    port = atoi(argv[1]);        /* convert argument to binary   */
  } else { 
    fprintf(stderr,"Usage: %s port-number\n",argv[0]);
    exit(1);
  }
  
  
  /* Create a socket */

  welcomeSocket = socket(PF_INET, SOCK_STREAM, 0); /* CREATE SOCKET */
  if (welcomeSocket < 0) {
    fprintf(stderr, "socket creation failed\n");
    exit(1);
  }
  
  /* Bind a local address to the socket */
  
  memset((char *)&sad,0,sizeof(sad)); /* clear sockaddr structure   */
  sad.sin_family = AF_INET;           /* set family to Internet     */
  sad.sin_addr.s_addr = INADDR_ANY;   /* set the local IP address   */
  sad.sin_port = htons((uint16_t)port);/* set the port number        */ 
  
  if (bind(welcomeSocket, (struct sockaddr *)&sad, sizeof(sad)) < 0) {
    fprintf(stderr,"bind failed\n");
    exit(1);
  }
  
  /* Specify the size of request queue */
  
  if (listen(welcomeSocket, 10) < 0) {
    fprintf(stderr,"listen failed\n");
    exit(1);
  }
  
  /* Main server loop - accept and handle requests */
  
  while (1) {
    /*open file*/
    file = fopen(argv[2], "r");
    if(file == NULL){printf("Error opening file\n"); exit(1);}
    printf("Listening for request\n");
    
    /*declare hash variables to store hashes from the client*/
    uint8_t userHash[SHA256_DIGEST_SIZE], passHash[SHA256_DIGEST_SIZE];

    /*accept requests*/
    alen = sizeof(cad);
    if ( (connectionSocket=accept(welcomeSocket, (struct sockaddr *)&cad, &alen)) < 0) {
      fprintf(stderr, "accept failed\n");
      exit(1);
    }
    
    /*declare some variables*/
    int fieldCheck, i;
    char userHashString[65], passHashString[65], temp1[3], temp2[3];

    /*empty the strings so there is no junk in them*/
    memset(passHashString,0,sizeof(passHashString));
    memset(userHashString,0,sizeof(userHashString));

    /*read which field to check from the client (username or password)*/
    read(connectionSocket, &fieldCheck, sizeof(int));

    /*check the field*/
    if(fieldCheck == 1)
    {
      /*read the username/email*/
      read(connectionSocket, &userHash, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
      printf("Checking username/email\n");
    
      /*convert the hash array into a string stored in userHashString*/
      for (i = 0; i < SHA256_DIGEST_SIZE; ++i){   
        sprintf(temp1, "%02x", userHash[i]);
        strcat(userHashString, temp1);
      }
    }
    /*check the field*/
    if(fieldCheck == 2)
    {
      /*read the password to be checked from the client*/
      read(connectionSocket, &passHash, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
      printf("Checking password\n");

      /*convert the hash array into a string stored in passHashString*/
      for (i = 0; i < SHA256_DIGEST_SIZE; ++i){   
        sprintf(temp2, "%02x", passHash[i]);
        strcat(passHashString, temp2);
      }
    }
    /*check the field*/
    if(fieldCheck == 3)
    {
      /*read both username/email and password from client*/
      read(connectionSocket, &userHash, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
      read(connectionSocket, &passHash, sizeof(uint8_t) * SHA256_DIGEST_SIZE);
      printf("Checking username/email and password\n");

      /*convert user and pass into strings*/
      for (i = 0; i < SHA256_DIGEST_SIZE; ++i){   
        sprintf(temp1, "%02x", userHash[i]);
        strcat(userHashString, temp1);
      }

      for (i = 0; i < SHA256_DIGEST_SIZE; ++i){   
        sprintf(temp2, "%02x", passHash[i]);
        strcat(passHashString, temp2);
      }
    }
    /*declare some variables*/
    char line[131];
    int breach = 0;

    /*loop to read from the file, check each line(s) field(s) against user given information*/
    while(fgets(line, 131, file))
    {
      /*read a line from the file and store username in field1 and password in field2*/
      char* field1, *field2;
      field1 = strtok(line, ":");
      field2 = strtok(NULL, "\n");

      /*If the user wants to check username/email and a match is found, set the appropriate message*/
      if(fieldCheck == 1 && strcmp(userHashString, field1) == 0)
      {
        printf("Breach found!\n");
        /*breach integer is 1, breach is found*/
        breach = 1;
        /*set the message to be sent*/
        char* message = "Username/email is breached";
        /*send the message to the client*/
        write(connectionSocket, message, strlen(message) + 1);
        printf("Sending reply to client...\n");
      }
      /*If the user wants to check password and a match is found, set the appropriate message*/
      if(fieldCheck == 2 && strcmp(passHashString, field2) == 0)
      {
        printf("Breach found!\n");
        /*breach integer is 1, breach is found*/
        breach = 1;
        /*set the message*/
        char* message = "Password is breached";
        /*send the message to the client*/
        write(connectionSocket, message, strlen(message) + 1);
        printf("Sending reply to client...\n");
      }
      /*if user wants to check both fields and a match is found, set the appropraite message*/
      if(fieldCheck == 3)
      {
        printf("Breach found!\n");
        /*declare variables*/
        char* message;
        int userBreach = 0, passBreach = 0;
        /*if a match is found for the username/email*/
        if(strcmp(userHashString, field1) == 0)
        {
          /*set breach integers to 1, breach is found*/
          breach = 1, userBreach = 1;
          /*set the message*/
          message = "Username/Email is breached";
        }
        /*if a match is found the password*/
        if(strcmp(passHashString, field2) == 0)
        {
          /*set breach integers to 1, breach is found*/
          breach = 1, passBreach = 1;
          /*set the message*/
          message = "Password is breached";
        }
        /*if both username/email and password were found to be breached*/
        if(userBreach == 1 && passBreach == 1)
        {
          /*still set breach to 1, breach is found*/
          breach = 1;
          /*set the message*/
          message = "Username/Email and Password is breached";
        }
        /*send the appropraite message to client, will tell if either, any, or both fields were compromised*/
        write(connectionSocket, message, strlen(message) + 1);
        printf("Sending reply to client...\n");
      }
    }
    /*if user wanted to check username/email but no breach was found*/
    if(breach == 0 && fieldCheck == 1)
    {
      /*set the message and send reply*/
      char* message = "Username/Email is not breached";
      write(connectionSocket, message, strlen(message) + 1);
      printf("Sending reply to client...\n");
    }
    /*if user wanted to check password but no breach was found*/
    if(breach == 0 && fieldCheck == 2)
    {
      /*set the message and send reply*/
      char* message = "Password is not breached";
      write(connectionSocket, message, strlen(message) + 1);
      printf("Sending reply to client...\n");
    }
    /*if user wanted to check both fields but no breaches were found*/
    if(breach == 0 && fieldCheck == 3)
    {
      /*set the message and send reply*/
      char* message = "Username/Email and Password are not breached";
      write(connectionSocket, message, strlen(message) + 1);
      printf("Sending reply to client...\n");
    }

    /*close file and socket descriptor*/
    fclose(file);
    close(connectionSocket);
  }
}





