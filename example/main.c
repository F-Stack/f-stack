#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "ff_config.h"
#include "ff_api.h"

#define MAX_EVENTS 512

/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;

char html[] = 
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack\r\n"
"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 439\r\n"
"Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
"Connection: keep-alive\r\n"
"Accept-Ranges: bytes\r\n"
"\r\n"
"<!DOCTYPE html>\r\n"
"<html>\r\n"
"<head>\r\n"
"<title>Welcome to F-Stack!</title>\r\n"
"<style>\r\n"
"    body {  \r\n"
"        width: 35em;\r\n"
"        margin: 0 auto; \r\n"
"        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
"    }\r\n"
"</style>\r\n"
"</head>\r\n"
"<body>\r\n"
"<h1>Welcome to F-Stack!</h1>\r\n"
"\r\n"
"<p>For online documentation and support please refer to\r\n"
"<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
"\r\n"
"<p><em>Thank you for using F-Stack.</em></p>\r\n"
"</body>\r\n"
"</html>";

int loop(void *arg)
{
    /* Wait for events to happen */
    unsigned nevents = kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;

        /* Handle disconnect */
        if (event.flags & EV_EOF) {

            /* Simply close socket */
            close(clientfd);

            //printf("A client has left the server...,fd:%d\n", clientfd);
        } else if (clientfd == sockfd) {
            int nclientfd = accept(sockfd, NULL, NULL);

            assert(nclientfd > 0);

            /* Add to event list */
            kevSet.data     = 0;
            kevSet.fflags   = 0;
            kevSet.filter   = EVFILT_READ;
            kevSet.flags    = EV_ADD;
            kevSet.ident    = nclientfd;
            kevSet.udata    = NULL;

            assert(kevent(kq, &kevSet, 1, NULL, 0, NULL) == 0);

            //printf("A new client connected to the server..., fd:%d\n", nclientfd);

        } else if (event.filter == EVFILT_READ) {
            char buf[256];
            size_t readlen = read(clientfd, buf, sizeof(buf));

            //printf("bytes %zu are available to read...,fd:%d\n", (size_t)event.data, clientfd);

            write(clientfd, html, sizeof(html));

        } else {
            printf("unknown event: %8.8X\n", event.flags);
        }
    }
}

int main(int argc, char * argv[])
{
    char *conf;
    if (argc < 2) {
        conf = "./config.ini";
    } else {
        conf = argv[1];
    }

    ff_init(conf, argc, argv);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        printf("socket failed\n");

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("bind failed\n");
    }

    ret = listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("listen failed\n");
    }

    kevSet.data     = MAX_EVENTS;
    kevSet.fflags   = 0;
    kevSet.filter   = EVFILT_READ;
    kevSet.flags    = EV_ADD;
    kevSet.ident    = sockfd;
    kevSet.udata    = NULL;

    assert((kq = kqueue()) > 0);

    /* Update kqueue */
    kevent(kq, &kevSet, 1, NULL, 0, NULL);

    ff_run(loop, NULL);
    return 0;
}


