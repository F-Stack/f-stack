#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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
#ifdef INET6
int sockfd6;
#endif

char html[] = 
"HTTP/1.1 200 OK\r\n"
"Server: F-Stack\r\n"
"Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 438\r\n"
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
    unsigned nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    unsigned i;

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;

        /* Handle disconnect */
        if (event.flags & EV_EOF) {
            /* Simply close socket */
            ff_close(clientfd);
#ifdef INET6
        } else if (clientfd == sockfd || clientfd == sockfd6) {
#else
        } else if (clientfd == sockfd) {
#endif
            int available = (int)event.data;
            do {
                int nclientfd = ff_accept(clientfd, NULL, NULL);
                if (nclientfd < 0) {
                    printf("ff_accept failed:%d, %s\n", errno,
                        strerror(errno));
                    break;
                }

                /* Add to event list */
                EV_SET(&kevSet, nclientfd, EVFILT_READ, EV_ADD, 0, 0, NULL);

                if(ff_kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0) {
                    printf("ff_kevent error:%d, %s\n", errno,
                        strerror(errno));
                    return -1;
                }

                available--;
            } while (available);
        } else if (event.filter == EVFILT_READ) {
            char buf[256];
            size_t readlen = ff_read(clientfd, buf, sizeof(buf));

            ff_write(clientfd, html, sizeof(html) - 1);
        } else {
            printf("unknown event: %8.8X\n", event.flags);
        }
    }
}

int main(int argc, char * argv[])
{
    ff_init(argc, argv);

    assert((kq = ff_kqueue()) > 0);

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("ff_socket failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }

     ret = ff_listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    /* Update kqueue */
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

#ifdef INET6
    sockfd6 = ff_socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd6 < 0) {
        printf("ff_socket failed, sockfd6:%d, errno:%d, %s\n", sockfd6, errno, strerror(errno));
        exit(1);
    }

    struct sockaddr_in6 my_addr6;
    bzero(&my_addr6, sizeof(my_addr6));
    my_addr6.sin6_family = AF_INET6;
    my_addr6.sin6_port = htons(80);
    my_addr6.sin6_addr = in6addr_any;

    ret = ff_bind(sockfd6, (struct linux_sockaddr *)&my_addr6, sizeof(my_addr6));
    if (ret < 0) {
        printf("ff_bind failed, sockfd6:%d, errno:%d, %s\n", sockfd6, errno, strerror(errno));
        exit(1);
    }

    ret = ff_listen(sockfd6, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed, sockfd6:%d, errno:%d, %s\n", sockfd6, errno, strerror(errno));
        exit(1);
    }

    EV_SET(&kevSet, sockfd6, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);
#endif

    ff_run(loop, NULL);
    return 0;
}
