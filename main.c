#include <libssh/libssh.h>
#include <libssh/server.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTENADDRESS "127.0.0.1"
#define LOCALHOST "127.0.0.1"
#define RSA_KEYFILE "./sshpot.rsa.key"
#define DEBUG 1
#define MAXBUFFER 100

/* Global so they can be cleaned up at SIGINT. */
static ssh_session session;
static ssh_bind sshbind;

extern int errno;

void send_data(ssh_message msg, ssh_session sesh) {
	int socket_desc;
	struct sockaddr_in skaddrinfo;
	socket_desc = socket(AF_INET, SOCK_STREAM, 0);

	/* error check socket creation */
	if(socket_desc == -1) {
		printf("Error creating socket.\n");
		return;
	}

	skaddrinfo.sin_addr.s_addr = inet_addr("127.0.0.1");
	skaddrinfo.sin_family = AF_INET;
	skaddrinfo.sin_port = htons(8500);

	/* connect to database server */
	if(connect(socket_desc, (struct sockaddr*) &skaddrinfo, sizeof(skaddrinfo)) < 0) {
		puts("Error making connection to server.\n");
		return;
	}
	puts("Connection made!\n");

	/* Grab user name and pasword from ssh messsage */
	const char* user;
	const char* pass;
	user = ssh_message_auth_user(msg);
	pass = ssh_message_auth_password(msg);

	/* Grab client-ip from ssh_session */
	char clientip[MAXBUFFER];
	struct sockaddr_in sock;
	unsigned int len = sizeof(sock);
	if(getpeername(ssh_get_fd(sesh), &sock, &len) == 0) {
		//sock = (struct sockaddr_in)&temp;
		inet_ntop(AF_INET, &sock.sin_addr, clientip, sizeof(clientip));
	}
	else {
		printf("Error:%d", errno);
	}

	/* Grab time from system*/
	char* strtime;
	time_t t;
	t = time(NULL);
	int inttime = strftime(strtime, MAXBUFFER, "%Y-%m-%d %H:%M:%S", gmtime(&t));

	/* send attacker data to database */
	char buf[1000];
	snprintf(buf, sizeof(buf), "{\"timestamp\":%d, \"username\":\"%s\", \"password\":\"%s\", \"srcip\":\"%s\", \"dstip\":\"%s\"}", 
			inttime, user, pass, clientip, LOCALHOST);
	

	//snprintf(buf, sizeof(buf), "Hello World\n");

	/* error check sending of data */
	if(send(socket_desc, buf, strlen(buf), 0) < 0) {
		puts("Error sending data.\n");
		return;
	}

	close(socket_desc);
	puts("Data sent!\n");
}

int main(int argc, char *argv[]) {
    int port = 2269;

    /* Create and configure the ssh session. */
    session=ssh_new();
    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,RSA_KEYFILE);

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return -1;
    }
    if (DEBUG) { printf("Listening on port %d.\n", port); }

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: `%s'.\n",ssh_get_error(sshbind));
            return -1;
        }
	if(fork() != 0) {
		continue;
	}
        if (DEBUG) { printf("Accepted a connection.\n"); }
	//TO-DO
	//Handle login attempts
	//print username and pass
	/* Perform key exchange. */
        if (ssh_handle_key_exchange(session)) {
            fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(session));
            return -1;
        }

	while(1) {
	    ssh_message msg = ssh_message_get(session);
	    if(msg == NULL) {
		break;
	    }

	    if (ssh_message_subtype(msg) == SSH_AUTH_METHOD_PASSWORD) {
                printf("[%s] [%s]\n", ssh_message_auth_user(msg), ssh_message_auth_password(msg));
		send_data(msg, session);
            }
            else {
                if (DEBUG) { fprintf(stderr, "Not a password authentication attempt.\n"); }
	    }
	    ssh_message_reply_default(msg);
	    ssh_message_free(msg);
	}
	exit(0);
    }
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}
