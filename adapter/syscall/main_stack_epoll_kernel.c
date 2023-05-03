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
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#define SOCK_FSTACK 0x01000000
#define SOCK_KERNEL 0x02000000

#define MAX_WORKERS 128
pthread_t hworker[MAX_WORKERS];

#define MAX_EVENTS 512
struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];
int epfd;
int sockfd, sockfd_kernel;

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
    //alarm_event_sem();
    return;
}

void *loop(void *arg)
{
    /* Wait for events to happen */
    while (!exit_flag) {
        /*
         * If not call alarm_event_sem, and epoll_wait timeout is 0,
         * it can't exit normal, so timeout can't set to 0.
         */
        int nevents = epoll_wait(epfd, events, MAX_EVENTS, -1);
        int i;

        if (nevents <= 0) {
            if (nevents) {
                printf("hello world epoll wait ret %d, errno:%d, %s\n",
                    nevents, errno, strerror(errno));
                break;
            }
            usleep(100);
            //sleep(1);
        }
        //printf("get nevents:%d\n", nevents);

        for (i = 0; i < nevents; ++i) {
            /* Handle new connect */
            if (events[i].data.fd == sockfd || events[i].data.fd == sockfd_kernel) {
                while (1) {
                    int nclientfd = accept(events[i].data.fd, NULL, NULL);
			    printf("accept sockfd(_kernel):%d, nclientfd:%d, errono:%d/%s\n", events[i].data.fd, nclientfd, errno, strerror(errno));
                    if (nclientfd < 0) {
                        break;
                    }

                    /* Add to event list */
                    ev.data.fd = nclientfd;
                    ev.events  = EPOLLIN;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, nclientfd, &ev) != 0) {
                        printf("ff_epoll_ctl failed:%d, %s\n",
                            errno, strerror(errno));
                        close(nclientfd);
                        break;
                    }
		    if (events[i].data.fd == sockfd_kernel) {
		    	break;
		    }
                }
            } else {
                if (events[i].events & EPOLLERR ) {
                    /* Simply close socket */
                    epoll_ctl(epfd, EPOLL_CTL_DEL,  events[i].data.fd, NULL);
                    close(events[i].data.fd);
                } else if (events[i].events & EPOLLIN) {
                    char buf[256];
                    size_t readlen = read( events[i].data.fd, buf, sizeof(buf));
                    if(readlen > 0) {
                        write( events[i].data.fd, html, sizeof(html) - 1);
                    } else {
                        epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                        close(events[i].data.fd);
                    }
                } else {
                    printf("unknown event: %d:%8.8X\n", i, events[i].events);
                }
            }
        }
    }

    return NULL;
}

int main(int argc, char * argv[])
{
    int i, worker_num = 1;

    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0) {
        printf("ff_socket failed\n");
        return -1;
    }

    int on = 1;
    ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = bind(sockfd, (const struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed\n");
        close(sockfd);
        return -1;
    }

    ret = listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed\n");
        close(sockfd);
        return -1;
    }

    sockfd_kernel = socket(AF_INET, SOCK_STREAM | SOCK_KERNEL, 0);
    printf("sockfd_kernel:%d\n", sockfd_kernel);
    if (sockfd_kernel < 0) {
        printf("ff_socket failed\n");
        return -1;
    }

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(80);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(sockfd_kernel, (const struct sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0) {
        printf("ff_bind failed\n");
        close(sockfd);
        close(sockfd_kernel);
        return -1;
    }

    ret = listen(sockfd_kernel, MAX_EVENTS);
    if (ret < 0) {
        printf("ff_listen failed\n");
        close(sockfd);
        close(sockfd_kernel);
        return -1;
    }

    epfd = epoll_create(512);
    printf("epfd:%d\n", epfd);
    if (epfd <= 0) {
        printf("ff_epoll_create failed, errno:%d, %s\n",
            errno, strerror(errno));
        close(sockfd);
        return -1;
    }

    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);
    if (ret < 0) {
        printf("ff_listen failed\n");
        close(epfd);
        close(sockfd);
        close(sockfd_kernel);
        return -1;
    }
    ev.data.fd = sockfd_kernel;
    ev.events = EPOLLIN;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd_kernel, &ev);
    if (ret < 0) {
        printf("ff_listen failed\n");
        close(epfd);
        close(sockfd);
        close(sockfd_kernel);
        return -1;
    }

    for (i = 0; i < worker_num; i++) {
        if(pthread_create(&hworker[i], NULL, loop, (void *)&i) < 0) {
            printf("create loop thread failed., errno:%d/%s\n",
                errno, strerror(errno));
            close(epfd);
            close(sockfd);
            close(sockfd_kernel);
            return -1;
        }
    }

    for (i = 0; i < worker_num; i++) {
        pthread_join(hworker[i], NULL);
    }

    close(epfd);
    close(sockfd);
    close(sockfd_kernel);

    return 0;
}
