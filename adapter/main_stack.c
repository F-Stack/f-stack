#include <stdio.h>
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
#include <sys/ioctl.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

//#include "ff_config.h"
//#include "ff_api.h"
#include "ff_event.h"
#include "ff_adapter.h"
#include "ff_hook_syscall.h"

pthread_t hworker;

#define MAX_EVENTS 512

/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;

struct timespec timeout = {0, 100000};

static int exit_flag = 0;

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

void sig_term(int sig)
{
    printf("we caught signal %d, to exit helloworld\n", sig);
    exit_flag = 1;
    alarm_event_sem();
    return;
}

void *loop(void *arg)
{
    /* Wait for events to happen */
    while (!exit_flag) {
        /*
         * If timeout is NULL, must call alarm_event_sem();
         */
        int nevents = kevent(kq, NULL, 0, events, MAX_EVENTS, &timeout);
        int i;

        if (nevents <= 0) {
            if (nevents) {
                    printf("ff_kevent failed:%d, %s\n", errno,
                                    strerror(errno));
                    return NULL;
            }
            //usleep(100);
            //sleep(1);
        }
        //printf("get nevents:%d\n", nevents);

        for (i = 0; i < nevents; ++i) {
            struct kevent event = events[i];
            int clientfd = (int)event.ident;

            /* Handle disconnect */
            if (event.flags & EV_EOF) {
                /* Simply close socket */
                close(clientfd);
            } else if (clientfd == sockfd) {
                int available = (int)event.data;
                do {
                    int nclientfd = accept(clientfd, NULL, NULL);
                    if (nclientfd < 0) {
                        printf("ff_accept failed:%d, %s\n", errno,
                            strerror(errno));
                        break;
                    }

                    /* Add to event list */
                    EV_SET(&kevSet, nclientfd, EVFILT_READ, EV_ADD, 0, 0, NULL);

                    if(kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0) {
                        printf("ff_kevent error:%d, %s\n", errno,
                            strerror(errno));
                        close(nclientfd);
                        break;
                    }

                    available--;
                } while (available);
            } else if (event.filter == EVFILT_READ) {
                char buf[256];
                ssize_t readlen = read(clientfd, buf, sizeof(buf));
                ssize_t writelen = write(clientfd, html, sizeof(html) - 1);
                if (writelen < 0){
                    printf("ff_write failed, readlen:%lu, writelen:%lu, :%d, %s\n",
                        readlen, writelen, errno, strerror(errno));
                    close(clientfd);
                }
            } else {
                printf("unknown event: %8.8X\n", event.flags);
            }
        }
    }

    return NULL;
}

int main(int argc, char * argv[])
{
    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("ff_socket failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        return -1;;
    }

    /* Set non blocking */
    int on = 1;
    ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = bind(sockfd, (const struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        close(sockfd);
        return -1;
    }

     ret = listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    kq = kqueue();
    printf("kq:%d\n", kq);
    if (kq < 0) {
        printf("ff_kqueue failed, errno:%d, %s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    /* Update kqueue */
    ret = kevent(kq, &kevSet, 1, NULL, 0, &timeout);
    if (ret < 0) {
        printf("kevent failed\n");
        close(kq);
        close(sockfd);
        return -1;
    }

    if(pthread_create(&hworker, NULL, loop, NULL) < 0) {
        printf("create loop thread failed., errno:%d/%s\n",
            errno, strerror(errno));
        close(kq);
        close(sockfd);
        return -1;
    }

    pthread_join(hworker, NULL);

    close(kq);
    close(sockfd);

    return 0;
}
