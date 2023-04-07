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

#define MAX_WORKERS 128
pthread_t hworker[MAX_WORKERS];
pthread_spinlock_t worker_lock;
#define MAX_EVENTS 512

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
    return;
}

void *loop(void *arg)
{
    struct epoll_event ev;
    struct epoll_event events[MAX_EVENTS];
    int epfd;
    int sockfd;
    int thread_id;

    thread_id = *(int *)arg;
    pthread_spin_unlock(&worker_lock);

    printf("start thread %d\n", thread_id);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("thread %d, sockfd:%d\n", thread_id, sockfd);
    if (sockfd < 0) {
        printf("thread %d, ff_socket failed\n", thread_id);
        exit(1);
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
        printf("thread %d, ff_bind failed\n", thread_id);
        exit(1);
    }

    ret = listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("thread %d, ff_listen failed\n", thread_id);
        exit(1);
    }

    epfd = epoll_create(0);
    if (epfd <= 0) {
        printf("thread %d, ff_epoll_create failed, errno:%d, %s\n",
            thread_id, errno, strerror(errno));
        exit(1);
    }
    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);

    /* Wait for events to happen */
    while (!exit_flag) {
        int nevents = epoll_wait(epfd, events, MAX_EVENTS, 100);
        if (nevents <= 0) {
            if (nevents) {
                printf("thread %d, hello world epoll wait ret %d, errno:%d, %s\n",
                    thread_id, nevents, errno, strerror(errno));
            }
            //usleep(100);
            sleep(1);
        }
        printf("thread %d, get nevents:%d\n", thread_id, nevents);
        int i;

        for (i = 0; i < nevents; ++i) {
            /* Handle new connect */
            if (events[i].data.fd == sockfd) {
                while (1) {
                    int nclientfd = accept(sockfd, NULL, NULL);
                    if (nclientfd < 0) {
                        break;
                    }

                    /* Add to event list */
                    ev.data.fd = nclientfd;
                    ev.events  = EPOLLIN;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, nclientfd, &ev) != 0) {
                        printf("thread %d, ff_epoll_ctl failed:%d, %s\n",
                            thread_id, errno, strerror(errno));
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
                    printf("thread %d, unknown event: %8.8X\n", events[i].events);
                }
            }
        }
    }
}

int main(int argc, char * argv[])
{
    int i, worker_num;

    signal(SIGINT, sig_term);
    signal(SIGTERM, sig_term);

    if (argc == 1) {
        worker_num = 1;
    } else {
        worker_num = atoi(argv[1]);
    }
    printf("to init %d workers.\n", worker_num);

    pthread_spin_init(&worker_lock, PTHREAD_PROCESS_SHARED);

    for (i = 0; i < worker_num; i++) {
        pthread_spin_lock(&worker_lock);
        if(pthread_create(&hworker[i], NULL, loop, (void *)&i) < 0) {
            printf("create loop thread failed., errno:%d/%s\n",
                errno, strerror(errno));
            pthread_spin_unlock(&worker_lock);
            pthread_spin_destroy(&worker_lock);
            return -1;
        }
        sleep(5);
    }

    for (i = 0; i < worker_num; i++) {
        pthread_join(hworker[i], NULL);
    }

    pthread_spin_destroy(&worker_lock);

    return 0;
}
