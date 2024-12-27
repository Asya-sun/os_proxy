#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <llhttp.h>

typedef struct http_request {
    int major;
    int minor;
    int method;
    char *url;

    int finished;
    llhttp_t parser;
    llhttp_settings_t settings;
} http_request_t;

typedef struct http_response {
    int major;
    int minor;
    int status;

    int finished;
    llhttp_t parser;
    llhttp_settings_t settings;
} http_response_t;

void http_request_init(http_request_t *request);
void http_response_init(http_response_t *response);

int http_request_parse(http_request_t *request, char *buf, int len);
int http_response_parse(http_response_t *response, char *buf, int len);

#endif /* HTTP_UTILS_H */