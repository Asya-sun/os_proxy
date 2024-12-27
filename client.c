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
#include "http_utils/http_utils.h"
#include "llhttp.h"

// #include "http_parser/http_request_parser.h"
// #include "picohttpparser.h"
#include "hashmap/hashmap.h"


#define BUFF_SIZE 256 * 8
#define START_RESPONCE_BUFF_SIZE 1024 * 1024
#define MAX_RESPONCE_BUF_SIZE 1024 * 1024 * 1024 //1 Gb
#define SERVER_STRING_SIZE 124
#define HEADERS_NUM 100
#define METHOD_MAX_LEN 16

#define TTL 360

typedef struct download_from_server_ro_entry_args {
    int server_fd;
    data_entry_t *data_entry;
    Logger *logger;
} download_from_server_ro_entry_args;


void *download_from_server_ro_entry_thread(void *args) {
    download_from_server_ro_entry_args* parsed = (download_from_server_ro_entry_args *) args; 
    int server_fd = parsed->server_fd;
    data_entry_t *data_entry = parsed->data_entry;
    Logger *client_logger = parsed->logger;

    free(args); // = free(parsed)

    int err = 0;
    char *responce_buffer = malloc(START_RESPONCE_BUFF_SIZE);
    if (responce_buffer == NULL) {
        elog(client_logger, ERROR, "SERVER: couldn't allocate responce_buffer: %s", strerror(errno));
        // here free memory and close everything needed
        close(server_fd);
        pthread_exit(NULL);
    }
    size_t responce_buffer_size = 0;
    http_response_t responce;
    http_response_init(&responce);

    elog(client_logger, INFO, "SERVER: http_responce was inited\n");

    err = read_parse_responce_write_to_entry(&responce, &responce_buffer, &responce_buffer_size, server_fd, data_entry, client_logger);
    if (err) {
        elog(client_logger, ERROR, "SERVER: got error while reading or parsing responce from server, exiting thread\n");
        // here we free resourses
        // free(buffer);
        // free(request);
        // closeLogger(client_logger);
        // free(_args);
        // close(client_socket);
        pthread_exit(NULL);
    }

    elog(client_logger, INFO, responce_buffer);
    close(server_fd);
    pthread_exit(NULL);

}

int parse_url(const char *url, char *host, size_t max_host_len, int *port, Logger *logger) {
    memset(host, 0, max_host_len);
    *port = 80;

    if (url == NULL) {
        return -1;
    }

    // Найдем начало хоста
    const char *host_start = strstr(url, "://");
    if (host_start != NULL) {
        host_start += 3; // Пропускаем "://"
    } else {
        host_start = url; // Если "://" не найден, начинаем с начала строки
    }

    // Найдем конец хоста (найдем первый символ '/' или ':')
    const char *host_end = strpbrk(host_start, ":/");
    if (host_end == NULL) {
        host_end = host_start + strlen(host_start); // Если ничего не найдено, устанавливаем конец строки
    }

    // Выделяем память под имя хоста и копируем его
    size_t host_length = host_end - host_start;
    if (host_length > max_host_len) {
        elog(logger, ERROR, "surprisingly too long url: %.*s", host_length, host_start);
        return -1;
    }

    strncpy(host, host_start, host_length);
    host[host_length] = '\0'; // Завершаем строку

    // Если мы нашли символ ':', то это означает, что есть порт
    if (*host_end == ':') {
        *port = atoi(host_end + 1); // Преобразуем строку в число
    }

    return 0;
}


int read_parse_request(http_request_t *request, char **buffer, size_t *buf_size, int client_fd, Logger *logger) {
    int request_maxsize = BUFF_SIZE;
    memset(*buffer, 0, request_maxsize);

    int total_read = 0;

    while(!request->finished) {

        if (total_read == request_maxsize) {
            request_maxsize = request_maxsize * 3 / 2;
            char *tmp = realloc(*buffer, request_maxsize);
            if (tmp == NULL) {
                elog(logger, ERROR, "realloc error: %s\n", strerror(errno));
                return -1;
            } 
            *buffer = tmp;
        }

        int n = read(client_fd, *buffer + total_read, request_maxsize - total_read);
        if (n < 0) {
            elog(logger, ERROR, "error while reading request: %s\n", strerror(errno));
            return -1;
        } else if (n == 0) {
            elog(logger, ERROR, "client closed connection: %s\n", strerror(errno));
            return -1;
        }

        // if error
        if( http_request_parse(request, *buffer + total_read, n)) {
            elog(logger, ERROR, "error paring request\n");
            return -1;
        }

        total_read += n;
    }

    *buf_size = total_read;
    return 0;
}


int read_parse_responce_write_to_entry(http_response_t *responce, char **buffer, size_t *buffer_size, int server_fd, data_entry_t *data_entry, Logger *logger) {
    int responce_maxsise = START_RESPONCE_BUFF_SIZE;
    memset(*buffer, 0, responce_maxsise);

    int err = 0;

    int total_read = 0;

    while(!responce->finished) {

        if (total_read == responce_maxsise) {
            responce_maxsise = responce_maxsise * 3 / 2;
            char *tmp = realloc(*buffer, responce_maxsise);
            if (tmp == NULL) {
                elog(logger, ERROR, "SERVER: realloc error: %s\n", strerror(errno));
                entry_set_incorrect(data_entry);
                return -1;
            } 
            *buffer = tmp;
        }


        int n = read(server_fd, *buffer + total_read, responce_maxsise - total_read);
        if (n < 0) {
            elog(logger, ERROR, "SERVER: error while reading responce: %s\n", strerror(errno));
            entry_set_incorrect(data_entry);
            return -1;
        } else if (n == 0) {
            elog(logger, ERROR, "SERVER: server closed connection: %s\n", strerror(errno));
            entry_set_incorrect(data_entry);
            return -1;
        }

        if (http_response_parse(responce, *buffer + total_read, n)) {
            elog(logger, ERROR, "SERVER: error paring responce\n");
            entry_set_incorrect(data_entry);
            return -1;
        }
        // !!!!!!!!
        err = write_to_entry(data_entry, *(buffer + total_read), n);
        if (err) {
            entry_set_incorrect(data_entry);
            return -1;
        }

        total_read += n;

    }

    entry_set_whole(data_entry);

    *buffer_size = total_read;
    return 0;

}


int read_parse_responce(http_response_t *responce, char **buffer, size_t *buffer_size, int server_fd, Logger *logger) {
    int responce_maxsise = START_RESPONCE_BUFF_SIZE;
    memset(*buffer, 0, responce_maxsise);

    int total_read = 0;

    while(!responce->finished) {

        if (total_read == responce_maxsise) {
            responce_maxsise = responce_maxsise * 3 / 2;
            char *tmp = realloc(*buffer, responce_maxsise);
            if (tmp == NULL) {
                elog(logger, ERROR, "realloc error: %s\n", strerror(errno));
                return -1;
            } 
            *buffer = tmp;
        }


        int n = read(server_fd, *buffer + total_read, responce_maxsise - total_read);
        if (n < 0) {
            elog(logger, ERROR, "error while reading responce: %s\n", strerror(errno));
            return -1;
        } else if (n == 0) {
            elog(logger, ERROR, "server closed connection: %s\n", strerror(errno));
            return -1;
        }

        if (http_response_parse(responce, *buffer + total_read, n)) {
            elog(logger, ERROR, "error paring responce\n");
            return -1;
        }

        total_read += n;

    }

    *buffer_size = total_read;
    return 0;

}

int is_digit(char c) { return c >= '0' && c <= '9'; }

/**
 * return serverFD on success, -1 if not
 */
int open_connection_with_server(const char *targetHost, int port, Logger *logger) {
    elog(logger, INFO, "open_connection_with_server: targetHost: %s\n", targetHost);
    fflush(stdout);
    int err;
    int serverFD;

    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *rp;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(targetHost, NULL, &hints, &result);
    if (err) {
        // fprintf(stderr, "single host server: getaddrinfo: %s\n", gai_strerror(err));
        elog(logger, ERROR, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    elog(logger, INFO, "got address info\n");

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        serverFD = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        elog(logger, INFO, "AFTER SOCKET\n");
        if (serverFD == -1) {
            continue;
        }
        elog(logger, INFO, "SOCKETED SUCCESSFULLY\n");

        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
            ipv4->sin_port = htons(port);
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
            ipv6->sin6_port = htons(port);
        }

        err = connect(serverFD, rp->ai_addr, rp->ai_addrlen);
        if (err == 0) {
            elog(logger, INFO, "CONNECTED SUCCESSFULLY\n");
            freeaddrinfo(result);
            return serverFD;
        }

        elog(logger, INFO, "CONNECT FAILED\n");

        err = close(serverFD);
        if (err) {
            freeaddrinfo(result);
            return -1;
        }
    }
    fflush(stdout);
    freeaddrinfo(result);
    return -1;
}

int write_all_bytes(const char *data, int data_size, int fd, Logger *logger) {
    int wroteBytes;
    int totallyWroteBytes = 0;

    while (totallyWroteBytes != data_size) {
        // wroteBytes = send(fd, data + totallyWroteBytes,
        //                   data_size - totallyWroteBytes, MSG_NOSIGNAL);
        wroteBytes = write(fd, data + totallyWroteBytes, data_size - totallyWroteBytes);
        if (wroteBytes == -1) {
            elog(logger, ERROR,  "single host server: send request to client: write: %s\n", strerror(errno));
            return -1;
        }
        totallyWroteBytes += wroteBytes;
        elog(logger, INFO, "TOTALLY WROTE BYTES: %d OF %d PID: %ld\n",
               totallyWroteBytes, data_size, pthread_self());
    }
    return 0;
}


void split_host_port(char *addr, char *host, int *port) {
    // Находим символ ':', который разделяет хост и порт
    char *colon_position = strchr(addr, ':');
    if (colon_position != NULL) {
        // Копируем хост в указанное место
        size_t host_length = colon_position - addr;
        strncpy(host, addr, host_length);
        host[host_length] = '\0'; // завершаем строку

        // Преобразуем строку порта в целое число
        *port = atoi(colon_position + 1);
    } else {
        // Если символ ':' не найден, то устанавливаем порт в 0
        strcpy(host, addr); // Копируем весь адрес как хост
        *port = 0; // Порт не задан
    }
}


void *serving_thread_work(void *_args) {
    to_serving_args args = *((to_serving_args *) _args); //so they are on the current thread's stack now
    int client_socket = args.client_socket; 
    // struct sockaddr_in client_sockaddr = args.client_sockaddr;
    HashMap *cache = args.cache;
    int err = 0;

    const int tid = gettid();
    char name[128];
    snprintf(name, 128, "logs/%d.log", tid);
    Logger *client_logger = createLogger(name);

    elog(client_logger, INFO, "client_socket: %d\n", client_socket);


    int is_get_request = 0;
    int is_cached_data = 0;
    time_t cached_time;

    char *buffer = malloc(BUFF_SIZE);
    if (buffer == NULL) {
        elog(client_logger, ERROR, "%s", strerror(errno));
        // here free memory and close everything needed
        // free(request);
        closeLogger(client_logger);
        free(_args);
        close(client_socket);
        pthread_exit(NULL);
    }

    size_t buffer_size = 0;


    http_request_t request;
    http_request_init(&request);
    elog(client_logger, INFO, "client_socket: %d\n", client_socket);
    err = read_parse_request(&request,  &buffer, &buffer_size, client_socket, client_logger);
    if (err) {
        elog(client_logger, ERROR, "got error while reading or parsing request, exiting thread\n");
        // here we free resourses
        free(buffer);
        // free(request);
        closeLogger(client_logger);
        free(_args);
        close(client_socket);
        pthread_exit(NULL);
    }

    elog(client_logger, INFO, "request\nmethod : %s\nurl: %s\n \n\n", llhttp_method_name(request.method), request.url);
    // elog(client_logger, INFO, "message from client: \n%s\n", buffer);

////////////
    // int is_1_0_request = (int)(request.major == 1 && request.minor == 0);
    // int is_get = (int) (request.method == HTTP_GET);
    // // тоесть если это не 1.0 get, то все =(
    // if (!is_1_0_request || !is_get) {
    //     elog(client_logger, ERROR, "only 1.0 GET method is supported\n");
    //     // here we free what needed
    //     pthread_exit(NULL);
    // }
////////////////////////////////    

    is_get_request = (int) (request.method == HTTP_GET);

    // char *responce_buffer = malloc(START_RESPONCE_BUFF_SIZE);
    // if (responce_buffer == NULL) {
    //     elog(client_logger, ERROR, "couldn't allocate responce_buffer: %s", strerror(errno));
    //     // here free memory and close everything needed
    //     free(buffer);
    //     // free(request);
    //     closeLogger(client_logger);
    //     free(_args);
    //     close(client_socket);
    //     pthread_exit(NULL);
    // }

    //somewhere here should be check for cache-storing
    // if (is_get_request) {
    //     // WHAT IS KEY...
    //     // let it be buffer
    //     // we tried to get response from cache
    //     is_cached_data = 1 - get_data_from_hashmap(cache, buffer, responce_buffer, &cached_time);
    //     elog(client_logger, INFO, "is_cached_data : %d cached_time: %ld\n", is_cached_data, cached_time);
    //     // if we got response and have appropriate cached time - we send it
    //     if (is_cached_data && (cached_time < TTL)) {
    //         err = write_all_bytes(responce_buffer, strlen(responce_buffer), client_socket, client_logger);
    //         if (err) {
    //             elog(client_logger, ERROR, "problems writing to clienr socket: %s\n", strerror(errno));
    //         } else {
    //             elog(client_logger, INFO, "wrote answer from cache\n");
    //         }            
    //         free(responce_buffer);
    //         free(buffer);
    //         closeLogger(client_logger);
    //         free(_args);
    //         close(client_socket);
    //         pthread_exit(NULL);
    //     }
    //     // otherwise, if we got responce from cache, but time is wrong - it's bad 
    //     else if (is_cached_data) {
    //         elog(client_logger, INFO, "data were found in cache, but they are outdated\n");
    //     }
    // }


    //if we're here, it means it's not GET request or it's GET request, but data isn't appropriate


    if (!is_get_request) {
        elog(client_logger, ERROR, "NOT GET, SORRY: %s %d %d\n", llhttp_method_name(request.method), request.method, HTTP_GET);
        // here we clear resourses
        pthread_exit(NULL);
    }
    



    // so, if we inserted request(key), we must do smth to insert responce(value)
    int is_already_inserted = insert_entry(cache, buffer, NULL);
    // int is_in_cache = get_data_from_hashmap(cache, buffer, responce_buffer, &cached_time);
    // int is_in_cache = seize_hashmap(cache, buffer, responce_buffer, &cached_time);
    data_entry_t *is_in_cache = seize_entry(cache, buffer);
    if (is_in_cache == NULL) {
        elog(client_logger, ERROR, "some bugs with hashmap, please fix it\n");
        // here we free resourses
        pthread_exit(NULL);
    }

    if (is_already_inserted) {
        // if we are here, it means that smbd already inserted key so we just need to send it - other stuff is not our resonsibility
        elog(client_logger, INFO, "request (key) already inserted\n");
        // unseize our entry
        // unseize_hashmap(cache);
    } else {
        // if we are here, it was me, who inserted request (key) to cache - so I am responsible to do smth to get responce (value) to cache too
        elog(client_logger, INFO, "I am responsible to do smth to insert responce to cache\n");

        // so I start to work on it
        //here we open connection with server
        int server_port = 0;
        char server_host[SERVER_STRING_SIZE];
        memset(server_host, 0, SERVER_STRING_SIZE);
        elog(client_logger, INFO, "request.url: %s\n", request.url);
        err = parse_url(request.url, server_host, SERVER_STRING_SIZE, &server_port, client_logger);
        if (err) {
            elog(client_logger, ERROR, "couldn't create connection with server\n");
            unseize_entry(is_in_cache);
            free(buffer);
            // free(request);
            closeLogger(client_logger);
            free(_args);
            close(client_socket);
            pthread_exit(0);
        }
        elog(client_logger, INFO, "server_host: %s server_post : %d\n", server_host, server_port);
        int server_fd = open_connection_with_server(server_host, server_port, client_logger);
        if (server_fd == -1) {
            elog(client_logger, ERROR, "couldn't create connection with server\n");
            unseize_entry(is_in_cache);
            free(buffer);
            // free(request);
            closeLogger(client_logger);
            free(_args);
            close(client_socket);
            pthread_exit(0);
        }

        //here we have connected to server already
        // now we are goig to send request to server
        elog(client_logger, INFO, "I'm going to send data to client\n");
        // here we send our request to the server
        elog(client_logger, INFO, "strlen(buffer): %ld    buffer_size: %ld\n", strlen(buffer), buffer_size);
        err = write_all_bytes(buffer, strlen(buffer), server_fd, client_logger);
        if (err) {
            elog(client_logger, ERROR, "problems writing to server socket: %s", strerror(err));
            unseize_entry(is_in_cache); // UNSEIZE ENTRY !!!
            free(buffer);
            // free(request);
            closeLogger(client_logger);
            free(_args);
            close(client_socket);
            pthread_exit(0);
        }

        // now we need to download responce from server


        pthread_t download_data_thread;
        download_from_server_ro_entry_args *new_args = (download_from_server_ro_entry_args *) malloc (sizeof (download_from_server_ro_entry_args));
        new_args->server_fd = server_fd;
        new_args->data_entry = is_in_cache;
        new_args->logger = client_logger;

        // pthread_attr_t attr;
        // pthread_attr_init(&attr);
        // pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

        // int created_download_data_thread = pthread_create(&download_data_thread, 
        //                                     &attr, 
        //                                     download_from_server_ro_entry_thread,
        //                                     new_args);
        // pthread_attr_destroy(&attr);

        int created_download_data_thread = pthread_create(&download_data_thread, 
                                            NULL, 
                                            download_from_server_ro_entry_thread,
                                            new_args);


        if (created_download_data_thread != 0) {
            elog(client_logger, ERROR, "couldn't create thread: %s\n", strerror(errno));
            unseize_entry(is_in_cache); // UNSEIZE ENTRY !!!
            free(buffer);
            // free(request);
            closeLogger(client_logger);
            free(_args);
            close(client_socket);
            pthread_exit(0);
        }

        pthread_join(created_download_data_thread, NULL);

    }

    // we processed the fact, whether we inserted entry to cach or not, so now we can leave it
    unseize_entry(is_in_cache);


    elog(client_logger, INFO, "starting to send data to client\n");


    int wroteBytes;
    int totallyWroteBytes = 0;
    char responce_buffer[256];
    int already_read = 0;
    int get_from_entry;

    while (1) {
        get_from_entry = read_from_entry(is_in_cache, responce_buffer, already_read, 256);
        if (get_from_entry == -1) {
            elog(client_logger, ERROR, "couldn/t get data from cahce, error\n");
            // here we clear resourses
            pthread_exit(NULL);
        }

        

        // wroteBytes = send(fd, data + totallyWroteBytes,
        //                   data_size - totallyWroteBytes, MSG_NOSIGNAL);
        wroteBytes = write(client_socket, buffer, get_from_entry);
        if (wroteBytes == -1) {
            elog(client_logger, ERROR,  "single host server: send request to client: write: %s\n", strerror(errno));
            elog(client_logger, ERROR, "problems writing to client socket");
            free(buffer);
            // free(request);
            closeLogger(client_logger);
            free(_args);
            close(client_socket);
            pthread_exit(0);    
        }
        totallyWroteBytes += wroteBytes;
        elog(client_logger, INFO, "TOTALLY WROTE BYTES: %d PID: %ld\n",
               totallyWroteBytes, pthread_self());
        
        int entry_size = entry_data_size(is_in_cache);
        if (entry_size != -1 && entry_size == totallyWroteBytes) {
            break;
        }
    }

    

    free(buffer);
    // free(request);
    closeLogger(client_logger);
    free(_args);
    close(client_socket);
    pthread_exit(0);
    pthread_exit(0);    

}
