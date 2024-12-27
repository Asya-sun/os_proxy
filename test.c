#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logger/logger.h"

int parse_url(const char *url, char *host, size_t max_host_len, int *port, Logger *logger) {
    // Инициализация значений по умолчанию
    // *host = NULL;
    memset(host, 0, max_host_len);
    *port = 80; // Задаем порт по умолчанию для HTTP

    if (url == NULL) {
        return -1; // Если URL равен NULL, ничего не делаем
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

int main() {
    const char *url1 = "http://www.example.com:8080/path/to/resource";
    // const char *url2 = "http://www.example.com/path/to/resource";
    const char *url2 = "http://www.example.com:9000";
    
    char *host;
    int port;

    parse_url(url1, &host, &port, NULL);
    printf("URL: %s\nHost: %s\nPort: %d\n", url1, host, port);
    free(host); // Освобождаем память после использования

    parse_url(url2, &host, &port, NULL);
    printf("URL: %s\nHost: %s\nPort: %d\n", url2, host, port);
    free(host); // Освобождаем память после использования

    return 0;
}