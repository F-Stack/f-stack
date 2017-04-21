
/**
 * Tencent is pleased to support the open source community by making MSEC available.
 *
 * Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.
 *
 * Licensed under the GNU General Public License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. You may 
 * obtain a copy of the License at
 *
 *     https://opensource.org/licenses/GPL-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the 
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mt_incl.h"
#include "micro_thread.h"

using namespace NS_MICRO_THREAD;

static bool run = true;

static struct sockaddr_in addr;

int mt_tcp_create_sock(void)
{
    int fd;
    //int flag;

    // 创建socket
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        printf("create tcp socket failed, error: %m\n");
        return -1;
    }

    // 设置socket非阻塞
	
	/* 
    flag = fcntl(fd, F_GETFL, 0);
    if (flag == -1)
    {
        ::close(fd);
        printf("get fd flags failed, error: %m\n");
        return -2;
    }

    if (flag & O_NONBLOCK)
        return fd;

    if (fcntl(fd, F_SETFL, flag | O_NONBLOCK | O_NDELAY) == -1)
    {
        ::close(fd);
        printf("set fd flags failed, error: %m\n");
        return -3;
    }
	*/


	int nb = 1;
	ioctl(fd, FIONBIO, &nb);

    return fd;
}

void echo(void* arg)
{
    char buf[1024];
    int ret = 0;
	int *p = (int *)arg;
	int clt_fd = *p;
	printf("start to echo with client: %d\n", clt_fd);
	while (1) {
		ret = mt_recv(clt_fd, (void*)buf,1024,0,-1);
		if(ret<0)
		{
			printf("recv client data failed[%m]\n");
			mt_sleep(1);
			break;
		}

		ret = mt_send(clt_fd, (void*)buf, ret, 0, 1000);
		if (ret < 0) {
			printf("send client data failed[%m]\n");
			mt_sleep(1);
			break;
		}
	}
	if(clt_fd>0)     close(clt_fd);
	delete p;
}

void server(void* arg)
{
    int fd = mt_tcp_create_sock();
    if(fd<0)
    {
        run = false;
        printf("create listen socket failed\n");
        return;
    }


    int optval = 1;
    unsigned optlen = sizeof(optval);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        printf("bind failed [%m]\n");
        return ;
    }

    if (listen(fd, 1024) < 0)
    {
        close(fd);
        printf("listen failed[%m]\n");
        return ;
    }
    
    int clt_fd = 0;
	int *p;
    while(run)
    {   
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);;
        
        clt_fd = mt_accept(fd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len, -1);
        if(clt_fd<0)
        {
            mt_sleep(1);
            continue;
        }
		int nb = 1;
		ioctl(clt_fd, FIONBIO, &nb);
		p = new int(clt_fd);
		printf("start a new micro thread to echo with client: %d\n", clt_fd);
		mt_start_thread((void*)echo, (void *)p);
        mt_sleep(1);
    }
    printf("server exit\n"); 
    
    
}

struct MsgCtx
{
    int check_count;
    int msg_id;
};

int TcpMsgChecker(void* buf, int len, bool closed, void* msg_ctx, bool& msg_len_detected)
{
    
    struct MsgCtx* ctx = (struct MsgCtx*)msg_ctx;
    
    ctx->check_count++;
    printf("#%d msg check msg times #%d, buf=%p, len=%d, closed=%d\n", ctx->msg_id, ctx->check_count, buf,len,closed);    

    if(len<4)
    {
        return 0;
    }

    
    int r_len=ntohl(*(uint32_t*)buf);
    //if(r_len!=len)
   // {
    //    return 0;
    //}
    msg_len_detected = true;

    return r_len;
}


/*
void client(void* arg)
{
    //char buf[1024];
    
    struct MsgCtx ctx;
    void* rcv_buf = NULL;
    int   rcv_len = 0;
    bool keep_rcv_buf = true;
    int ret = 0;
    char snd_ch = 1;
    int count=0;
    while(true)
    {
        rcv_buf = NULL;
        rcv_len = 1;
        keep_rcv_buf = (((++count)%2) == 0);
        ctx.check_count = 0;
        ctx.msg_id = count;
        ret = mt_tcpsendrcv_ex((struct sockaddr_in*)&addr, (void*)&snd_ch, 1, rcv_buf, rcv_len,20000, &TcpMsgChecker, (void*)&ctx, MT_TCP_SHORT,keep_rcv_buf);
        if(ret<0)
        {
            printf("client send rcv failed[%m]\n");
            continue;
        }
        printf("#%d client tcp finished: rcv_len=%d, rcv_buf=%p, keep_rcv_buf=%d\n",count, rcv_len, rcv_buf,keep_rcv_buf);

        if(keep_rcv_buf)
        {
            if(rcv_buf==NULL)
            {
                printf("client should hold rcvbuf, something wrong\n");
                continue;
            }
            free(rcv_buf);
        }
    }

    printf("client exit!");
}
*/

int main(int argc, char* argv[])
{

    memset((void*)&addr,0,sizeof(addr));
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr = inet_addr("112.90.143.29");
    addr.sin_port = htons(19999);

    mt_init_frame("./config.ini", argc, argv);

    mt_start_thread((void*)server,NULL);

	while (run) {
		mt_sleep(10);
	}

    printf("main exit");
}
