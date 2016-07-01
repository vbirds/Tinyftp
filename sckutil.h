#ifndef _SCK_UTIL_H_
#define _SCK_UTIL_H_

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>

#include <netdb.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define ERR_EXIT(m) \
  do \
  { \
    perror(m); \
	exit(EXIT_FAILURE); \
  } \
  while (0)

	  
#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND      32
#define MAX_ARG			 1024

/*获取本机IP*/
int getlocalip(char *ip);	  
/*创建客户端监听套接字*/
int tcp_client(const char *address, unsigned short port);

/*设置套接字为非阻塞*/
int activate_nonblock(int fd);
/*设置套接字为阻塞*/
int deactivate_nonblock(int fd);

/*带超时的数据接收*/
int read_timeout(int fd, unsigned int wait_seconds);
/*带超时的数据发送*/
int write_timeout(int fd, unsigned int wait_seconds);
/*带超时的accept*/
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);
/*带超时的connect*/
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);


ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
ssize_t readline(int sockfd, void *buf, size_t maxline);

/*发送文件描述符*/
void send_fd(int sock_fd, int fd_to_send);
/*发送接收描述符*/
int recv_fd(const int sock_fd);

/*获取权限位信息*/
const char* statbuf_get_perms(struct stat *sbuf);
const char* statbuf_get_date(struct stat *sbuf);

//锁
/*加锁*/
int lock_internal(int fd, int lock_type);
/*加读锁*/
int lock_file_read(int fd);
/*加写锁*/
int lock_file_write(int fd);
/*解锁*/
int unlock_file(int fd);

//时间
long get_time_sec();
long get_time_usec();
void nano_sleep(double seconds);

//紧急模式
void activate_oobinline(int fd);
/*开启接收SIGURG*/
void activate_sigurg(int fd);


#endif /* _SYS_UTIL_H_ */
