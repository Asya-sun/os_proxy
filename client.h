#ifndef PROXY_CLIENT_H
#define PROXY_CLIENT_H

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
#include "hashmap/hashmap.h"

typedef struct to_serving_args {
    int client_socket;
    struct sockaddr_in client_sockaddr;
    HashMap *cache;
} to_serving_args;


// #define BUFF_SIZE 256 * 8
// #define START_RESPONCE_BUFF_SIZE 256 * 8
// #define SERVER_STRING_SIZE 100
// #define HEADERS_NUM 100
// #define METHOD_MAX_LEN 16

// #define TTL 360


int write_all_bytes(const char *data, int data_size, int fd, Logger *logger);


void *serving_thread_work(void *_args);




#endif //PROXY_CLIENT_H
