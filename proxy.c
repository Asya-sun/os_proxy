#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h> 


#include "logger/logger.h"
#include "client.h"
// #include "http_parser/http_parser.h"
#include "hashmap/hashmap.h"

#define PORT 0x1234
#define ADDRESS "127.0.0.1"
#define USERS_NUMBER 5


int SHOULD_GO_DOWN = 0;


static void handleSignal(int signal) {
    SHOULD_GO_DOWN = 1;
}

static int registerSignal() {
    struct sigaction action = {0};
    action.sa_handler = handleSignal;
    action.sa_flags = 0;
    return sigaction(SIGINT, &action, NULL);
}



int main() {
    int server_socket;
    int client_socket;
    struct sockaddr_in server_sockaddr;
    struct sockaddr_in client_sockaddr;
    Logger *logger;

    pthread_t tid;
    pthread_attr_t attr;
    int error_check;

    // creating logger
    logger = createLogger("logs/logfile.txt");
    if (logger == NULL) {
        return 1; // Ошибка при создании логгера
    }

    // register SIGINT
    error_check = registerSignal();
    if (error_check) {
        elog(logger, FATAL, "couldn't register SIGINT: %s\n", strerror(errno));
    }

    // creating server socket fd
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        elog(logger, ERROR, "socket error: %s\n", strerror(errno));
        exit(1);
    }

    //thets needed just to be able run this file many times in a row
    const int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // setting server_sockaddr
    memset(&server_sockaddr, 0, sizeof(struct sockaddr));
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(PORT);
    inet_pton(AF_INET, ADDRESS, &server_sockaddr.sin_addr);
    bzero(&(server_sockaddr.sin_zero),8);

    //bing=ding server socket to server_sockaddr
    error_check = bind(server_socket, (struct sockaddr *) &server_sockaddr, sizeof (server_sockaddr));
    if (error_check == -1) {
        elog(logger, ERROR, "bind error: %s\n", strerror(errno));
        close(server_socket);
        exit(1);
    }

    // setting sever socket to listen mode
    error_check = listen(server_socket, USERS_NUMBER);
    if (error_check == -1) {
        elog(logger, ERROR, "listen() error: %s\n", strerror(errno));
        close(server_socket);
        exit(1);
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);


    HashMap *cache = create_hashmap();


    while (!SHOULD_GO_DOWN) {
        unsigned int len;
        // timeout для accept
        elog(logger, INFO, "waiting for a new client");
        client_socket = accept(server_socket, (struct sockaddr *) &client_sockaddr, &len);
        if (client_socket == -1) {
            elog(logger, ERROR, "accept() error: %s\n", strerror(errno));
            close(server_socket);
            exit(1);
        }
        elog(logger, INFO, "got new client client_socket: %d\n", client_socket);

        to_serving_args *_args  = (to_serving_args *) malloc(sizeof(to_serving_args));
        _args->client_socket = client_socket;
        _args->client_sockaddr = client_sockaddr;
        _args->cache = cache;

        error_check = pthread_create(&tid, &attr, serving_thread_work, (void *)_args);
        if (error_check != 0) {
            elog(logger, ERROR, "pthread_create failed, new client wasn't handled");
            close(client_socket);
            free(_args);
        } else {
            elog(logger, INFO, "new client connected");
        }

    }

    elog(logger, INFO, "server is shitting down, no new connections attached");

    closeLogger(logger);
    close(server_socket);
    pthread_exit(NULL);
}
