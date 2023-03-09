/*
AUTHOR: Abhijeet Rastogi (http://www.google.com/profiles/abhijeet.1989)

This is a very simple HTTP server. Default port is 10000 and ROOT for the server is your current working directory..

You can provide command line arguments like:- $./a.aout -p [port] -r [path]

for ex. 
$./a.out -p 50000 -r /home/
to start a server at port 50000 with root directory as "/home"

$./a.out -r /home/shadyabhi
starts the server at port 10000 with ROOT as /home/shadyabhi

Digest Auth Demo (E.S.Orlov)

*/

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<signal.h>
#include<fcntl.h>

#define CONNMAX 1000
#define BYTES 1024
#define AUTH_DATA "auth.html"


char *ROOT;
int listenfd, clients[CONNMAX];
void error(char *);
void startServer(char *);
void respond(int);

int main(int argc, char* argv[])
{
	struct sockaddr_in clientaddr;
	socklen_t addrlen;
	char c;    
	
	//Default Values PATH = ~/ and PORT=10000
	char PORT[6];
	ROOT = getenv("PWD");
	strcpy(PORT,"10000");

	int slot=0;

	//Parsing the command line arguments
	while ((c = getopt (argc, argv, "p:r:")) != -1)
		switch (c)
		{
			case 'r':
				ROOT = malloc(strlen(optarg));
				strcpy(ROOT,optarg);
				break;
			case 'p':
				strcpy(PORT,optarg);
				break;
			case '?':
				fprintf(stderr,"Wrong arguments given!!!\n");
				exit(1);
			default:
				exit(1);
		}
	
	printf("Server started at port no. %s%s%s with root directory as %s%s%s\n","\033[92m",PORT,"\033[0m","\033[92m",ROOT,"\033[0m");
	printf("============================================\n");
	printf("\n");
	// Setting all elements to -1: signifies there is no client connected
	int i;
	for (i=0; i<CONNMAX; i++)
		clients[i]=-1;
	startServer(PORT);

	// ACCEPT connections
	while (1)
	{
		addrlen = sizeof(clientaddr);
		clients[slot] = accept (listenfd, (struct sockaddr *) &clientaddr, &addrlen);

		if (clients[slot]<0)
			error ("accept() error");
		else
		{
			if ( fork()==0 )
			{
				respond(slot);
				exit(0);
			}
		}

		while (clients[slot]!=-1) slot = (slot+1)%CONNMAX;
	}

	return 0;
}

//start server
void startServer(char *port)
{
	struct addrinfo hints, *res, *p;

	// getaddrinfo for host
	memset (&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo( NULL, port, &hints, &res) != 0)
	{
		perror ("getaddrinfo() error");
		exit(1);
	}
	// socket and bind
	for (p = res; p!=NULL; p=p->ai_next)
	{
		listenfd = socket (p->ai_family, p->ai_socktype, 0);
		if (listenfd == -1) continue;
		if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
	}
	if (p==NULL)
	{
		perror ("socket() or bind()");
		exit(1);
	}

	freeaddrinfo(res);

	// listen for incoming connections
	if ( listen (listenfd, 1000000) != 0 )
	{
		perror("listen() error");
		exit(1);
	}
}

// get file
void get_req_resource(const char* path, int client, char* auth_data) 
{
	char data_to_send[BYTES];
	int fd, bytes_read;
	if (strncmp(&path[strlen(path)-strlen(AUTH_DATA)], AUTH_DATA, strlen(AUTH_DATA))==0)
	{
		printf("Auth needed...\n");
		if (auth_data == NULL)
		{
			send(client, "HTTP/1.0 401 Unauthorized\n", 26, 0);
			send(client, "WWW-Authenticate: Digest realm=\"DigestRealm\", \
					nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
					opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\n",129,0); //45+42+42
			return;
		} else
			printf("Got Auth...%s\n", auth_data);
	}
	printf("file: %s\n", path);
	printf("============================================\n");
	printf("\n");
	if ( (fd=open(path, O_RDONLY))!=-1 )    //FILE FOUND
	{
		send(client, "HTTP/1.0 200 OK\n\n", 17, 0);
		while ( (bytes_read=read(fd, data_to_send, BYTES))>0 )
			write (client, data_to_send, bytes_read);
		close(fd);
	}
	else    write(client, "HTTP/1.0 404 Not Found\n", 23); //FILE NOT FOUND
}

//client connection
void respond(int n)
{
	char mesg[99999], *reqline[3], path[99999];
	int rcvd;
	char *auth_data, *line, *save_ptr;
	memset( (void*)mesg, (int)'\0', 99999 );

	rcvd=recv(clients[n], mesg, 99999, 0);

	if (rcvd<0)    // receive error
		fprintf(stderr,("recv() error\n"));
	else if (rcvd==0)    // receive socket closed
		fprintf(stderr,"Client disconnected unexpectedly.\n");
	else    // message received
	{
		printf("%s", mesg);
		reqline[0] = strtok_r (mesg, " \t\n", &save_ptr);
		if ( strncmp(reqline[0], "GET\0", 4)==0 )
		{
			reqline[1] = strtok_r (NULL, " \t", &save_ptr);
			reqline[2] = strtok_r (NULL, " \t\n", &save_ptr);
			if ( strncmp( reqline[2], "HTTP/1.0", 8)!=0 && strncmp( reqline[2], "HTTP/1.1", 8)!=0 )
			{
				write(clients[n], "HTTP/1.0 400 Bad Request\n", 25);
			}
			else
			{
				if ( strncmp(reqline[1], "/\0", 2)==0 )
					reqline[1] = "/index.html";        //Because if no file is specified, index.html will be opened by default (like it happens in APACHE...
				line = strtok_r (NULL, "\r\n", &save_ptr);
				while (line )
				{
					//printf("Next token: %s\n", line);
					auth_data = strstr(line, "Authorization");
					if (auth_data) break;
					line = strtok_r(NULL, "\r\n", &save_ptr);
				}
				//printf ("AuthData: %s\n",auth_data);
				strcpy(path, ROOT);
				strcpy(&path[strlen(ROOT)], reqline[1]);
				get_req_resource(path,clients[n],auth_data);

			}
		}
	}

	//Closing SOCKET
	shutdown (clients[n], SHUT_RDWR);         //All further send and recieve operations are DISABLED...
	close(clients[n]);
	clients[n]=-1;
}

