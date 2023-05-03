#include <stdio.h>
#include <stdlib.h>
#include "mt_incl.h"
#include "micro_thread.h"

using namespace NS_MICRO_THREAD;

int set_fd_nonblock(int fd)
{
	int nonblock = 1;
	return ioctl(fd, FIONBIO, &nonblock);
}

int create_tcp_sock()
{
	int fd;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "create tcp socket failed, error: %m\n");
		return -1;
	}
	if (set_fd_nonblock(fd) == -1) {
		fprintf(stderr, "set tcp socket nonblock failed\n");
		return -1;
	}

	return fd;
}

void echo(void *arg)
{
	int ret;
	int *p = (int *)arg;
	int clt_fd = *p;
	delete p;
	char buf[64 * 1024];
	while (true) {
		ret = mt_recv(clt_fd, (void *)buf, 64 * 1024, 0, -1);
		if (ret < 0) {
			printf("recv from client error\n");
			break;
		}
		ret = mt_send(clt_fd, (void *)buf, ret, 0, 1000);
		if (ret < 0) {
			//printf("send data to client error\n");
			break;
		}
	}
	close(clt_fd);
}

int echo_server()
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(80);

	int fd = create_tcp_sock();
	if (fd < 0) {
		fprintf(stderr, "create listen socket failed\n");
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		fprintf(stderr, "bind failed [%m]\n");
		return -1;
	}

	if (listen(fd, 1024) < 0) {
		close(fd);
		fprintf(stderr, "listen failed [%m]\n");
		return -1;
	}
    int clt_fd = 0;
	int *p;
	while (true) {
		struct sockaddr_in client_addr;
		int addr_len = sizeof(client_addr);

        clt_fd = mt_accept(fd, (struct sockaddr*)&client_addr, (socklen_t*)&addr_len, -1);
		if (clt_fd < 0) {
			mt_sleep(1);
			continue;
		}
		if (set_fd_nonblock(clt_fd) == -1) {
			fprintf(stderr, "set clt_fd nonblock failed [%m]\n");
			break;
		}

		p = new int(clt_fd);
		mt_start_thread((void *)echo, (void *)p);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	mt_init_frame(argc, argv);
	echo_server();
}
