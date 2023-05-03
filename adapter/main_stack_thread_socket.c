#define _GNU_SOURCE
#include <sched.h>
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

#define MAX_WORKERS 128
pthread_t hworker[MAX_WORKERS];
pthread_spinlock_t worker_lock;
#define MAX_EVENTS 512

/* 100 ms */
struct timespec timeout = {0, 100000000};

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
    /* kevent set */
    struct kevent kevSet;
    /* events */
    struct kevent events[MAX_EVENTS];
    /* kq */
    int kq;
    int sockfd;

    int thread_id;

    thread_id = *(int *)arg;
    printf("start thread %d\n", thread_id);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("thread %d, sockfd:%d\n", thread_id, sockfd);
    if (sockfd < 0) {
        printf("thread %d, ff_socket failed\n", thread_id);
        pthread_spin_unlock(&worker_lock);
        return NULL;
    }

    /* socket will init adapter,so unlock after socket */
    pthread_spin_unlock(&worker_lock);

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
        close(sockfd);
        return NULL;
    }

    ret = listen(sockfd, MAX_EVENTS);
    if (ret < 0) {
        printf("thread %d, ff_listen failed\n", thread_id);
        close(sockfd);
        return NULL;
    }


    kq = kqueue();
    printf("thread %d, kq:%d\n", thread_id, kq);
    if (kq < 0) {
       printf("thread %d, ff_kqueue failed, errno:%d, %s\n", thread_id, errno, strerror(errno));
       close(sockfd);
       return NULL;
    }

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    /* Update kqueue */
    ret = kevent(kq, &kevSet, 1, NULL, 0, &timeout);
    if (ret < 0) {
        printf("thread %d, kevent failed\n", thread_id);
        close(kq);
        close(sockfd);
        return NULL;
    }

    /* Wait for events to happen */
    while (!exit_flag) {
        /*
         * If not call alarm_event_sem, and epoll_wait timeout is NULL,
         * it can't exit normal, so timeout can't set to NULL.
         */
        int nevents = kevent(kq, NULL, 0, events, MAX_EVENTS, &timeout);
        int i;

        if (nevents <= 0) {
            if (nevents) {
                    printf("thread %d, ff_kevent failed:%d, %s\n", thread_id, errno,
                                    strerror(errno));
                    return NULL;
            }
            //usleep(100);
            //sleep(1);
        }
        //printf("thread %d, get nevents:%d\n", thread_id, nevents);

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
                        printf("thread %d, ff_accept failed:%d, %s\n", thread_id, errno,
                            strerror(errno));
                        break;
                    }

                    /* Add to event list */
                    EV_SET(&kevSet, nclientfd, EVFILT_READ, EV_ADD, 0, 0, NULL);

                    if(kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0) {
                        printf("thread %d, ff_kevent error:%d, %s\n", thread_id, errno,
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
                    printf("thread %d, ff_write failed, readlen:%lu, writelen:%lu, :%d, %s\n",
                        thread_id, readlen, writelen, errno, strerror(errno));
                    close(clientfd);
                }
            } else {
                printf("thread %d, unknown event: %d:%8.8X\n", thread_id, i, event.flags);
            }
        }
    }

    close(kq);
    close(sockfd);

    return NULL;
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

    pthread_spin_init(&worker_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_lock(&worker_lock);

    for (i = 0; i < worker_num; i++) {
        if(pthread_create(&hworker[i], NULL, loop, (void *)&i) < 0) {
            printf("create loop thread failed., errno:%d/%s\n",
                errno, strerror(errno));
            pthread_spin_unlock(&worker_lock);
            pthread_spin_destroy(&worker_lock);
            return -1;
        }
        if (i > 0) {
            cpu_set_t cpuinfo;
            int lcore_id = 2 + i;

            CPU_ZERO(&cpuinfo);
            CPU_SET_S(lcore_id, sizeof(cpuinfo), &cpuinfo);
            if(0 != pthread_setaffinity_np(hworker[i], sizeof(cpu_set_t), &cpuinfo))
            {
                 printf("set affinity recver faild\n");
                 exit(0);
            }
            printf("set affinity recver sucssed, thread:%d, lcore_id:%d\n", i, lcore_id);
        }
        pthread_spin_lock(&worker_lock);
    }

    for (i = 0; i < worker_num; i++) {
        pthread_join(hworker[i], NULL);
    }

    pthread_spin_destroy(&worker_lock);

    return 0;
}
