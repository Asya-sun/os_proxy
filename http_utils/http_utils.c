#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <llhttp.h>

#include "http_utils.h"

static int method_complete_callback(llhttp_t *parser) {
    http_request_t *request = parser->data;
    request->method = llhttp_get_method(parser);
    return 0;
}

static int url_request_callback(llhttp_t *parser, const char *url, unsigned long len) {
    http_request_t *request = parser->data;

    if (request->url) {
        int curr_len = strlen(request->url);
        request->url = realloc(request->url, curr_len + len + 1);
        memcpy(request->url + curr_len, url, len);
        request->url[curr_len + len] = 0;
    } else {
        request->url = strndup(url, len);
    }

    return 0;
}

static int url_complete_request_callback(llhttp_t *parser, const char *url, unsigned long len) {
    http_request_t *request = parser->data;
    
    request->url = strndup(url, len);

    return 0;
}

static int version_complete_request_callback(llhttp_t *parser) {
    http_request_t *request = parser->data;
    request->major = llhttp_get_http_major(parser);
    request->minor = llhttp_get_http_minor(parser);
    return 0;
}

static int version_complete_response_callback(llhttp_t *parser) {
    http_response_t *response = parser->data;
    response->major = llhttp_get_http_major(parser);
    response->minor = llhttp_get_http_minor(parser);
    return 0;
}

static int request_complete_callback(llhttp_t *parser) {
    http_request_t *request = parser->data;
    request->finished = 1;
    return 0;
}

static int response_complete_callback(llhttp_t *parser) {
    http_response_t *response = parser->data;
    response->finished = 1;
    return 0;
}

static int status_complete_callback(llhttp_t *parser) {
    http_response_t *response = parser->data;
    response->status = llhttp_get_status_code(parser);
    return 0;
}

void http_request_init(http_request_t *request) {
    memset(request, 0, sizeof(http_request_t));

    llhttp_settings_init(&request->settings);
    request->settings.on_message_complete = request_complete_callback;
    request->settings.on_version_complete = version_complete_request_callback;
    request->settings.on_url = url_request_callback;
    // request->settings.on_url_complete = url_complete_request_callback;
    request->settings.on_method_complete = method_complete_callback;

    llhttp_init(&request->parser, HTTP_REQUEST, &request->settings);
    request->parser.data = request;
}

void http_response_init(http_response_t *response) {
    memset(response, 0, sizeof(http_response_t));

    llhttp_settings_init(&response->settings);
    response->settings.on_message_complete = response_complete_callback;
    response->settings.on_version_complete = version_complete_response_callback;
    response->settings.on_status_complete = status_complete_callback;

    llhttp_init(&response->parser, HTTP_RESPONSE, &response->settings);
    response->parser.data = response;
}

int http_request_parse(http_request_t *request, char *buf, int len) {
    llhttp_errno_t err = llhttp_execute(&request->parser, buf, len);
    if (err != HPE_OK) {
        return -1;
    }

    return 0;
}

int http_response_parse(http_response_t *response, char *buf, int len) {
    llhttp_errno_t err = llhttp_execute(&response->parser, buf, len);
    if (err != HPE_OK) {
        return -1;
    }

    return 0;
}