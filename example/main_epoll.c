#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "ff_config.h"
#include "ff_api.h"


#define MAX_EVENTS 512

struct epoll_event ev;

struct epoll_event events[MAX_EVENTS];

int epfd;
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

    int nevents = epoll_wait(epfd,  events, MAX_EVENTS, 0);
    int i;

    for (i = 0; i < nevents; ++i) {    
        /* Handle new connect */
        if (events[i].data.fd == sockfd) {
            int nclientfd = accept(sockfd, NULL, NULL);
            assert(nclientfd > 0);
            /* Add to event list */
            ev.data.fd = nclientfd;
            ev.events  = EPOLLIN;
            assert(epoll_ctl(epfd, EPOLL_CTL_ADD, nclientfd, &ev) == 0);
            //fprintf(stderr, "A new client connected to the server..., fd:%d\n", nclientfd);

        } else { 
            if (events[i].events & EPOLLERR ) {
                /* Simply close socket */
                epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                close(events[i].data.fd);
                //fprintf(stderr, "A client has left the server...,fd:%d\n", events[i].data.fd);

            } else if (events[i].events & EPOLLIN) {
                char buf[256];
                size_t readlen = read( events[i].data.fd, buf, sizeof(buf));
                //fprintf(stderr, "bytes are available to read..., readlen:%d, fd:%d\n", readlen, events[i].data.fd);

                if(readlen > 0){
                    write( events[i].data.fd, html, sizeof(html));

                } else {
                    epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    close( events[i].data.fd);
                    //fprintf(stderr, "A client has left the server...,fd:%d\n", events[i].data.fd);        
                }

            } else {
                //fprintf(stderr, "unknown event: %8.8X\n", events[i].events);
            }
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
    if (sockfd < 0) {
        printf("socket failed\n");
    }

    int on = 1;
    ioctl(sockfd, FIONBIO, &on);

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
    
    assert((epfd = fepoll_create(0)) > 0);
    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    ff_run(loop, NULL);
    return 0;
}


