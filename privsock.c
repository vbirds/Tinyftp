#include "privsock.h"
#include "common.h"
#include "sckutil.h"

/*初始化内部进程间通讯通道*/
void priv_sock_init(session_t *sess)
{
	int sockfds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
	{
		ERR_EXIT("socketpair");
	}	
	
	sess->parent_fd = sockfds[0];
	sess->child_fd = sockfds[1];
}
/*关闭内部进程间通讯通道*/
void priv_sock_close(session_t *sess)
{
	if (sess->parent_fd != -1)
	{
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
	if (sess->child_fd != -1)
	{
		close(sess->child_fd);
		sess->child_fd = -1;
	}	
}

/*设置父进程环境*/
void priv_sock_set_parent_context(session_t *sess)
{
	if (sess->child_fd != -1)
	{
		close(sess->child_fd);
		sess->child_fd = -1;
	}	
}
/*设置子进程环境*/
void priv_sock_set_child_context(session_t *sess)
{
	if (sess->parent_fd != -1)
	{
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
}

/*发送命令（子->父）*/
void priv_sock_send_cmd(int fd, char cmd)
{
	int ret = 0;
	ret = writen(fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
	{
		fprintf(stderr, "priv_sock_send_cmd error");
		exit(EXIT_FAILURE);
	}
}
/*接受命令（父<-子）*/
char priv_sock_get_cmd(int fd)
{
	char res;
	int ret = 0;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res))
	{
		fprintf(stderr, "priv_sock_get_cmd error");
		exit(EXIT_FAILURE);
	}	
	return res;
}

/*发送结果（父->子）*/
void priv_sock_send_result(int fd, char res)
{
	int ret = 0;
	ret = writen(fd, &res, sizeof(res));
	if (ret != sizeof(res))
	{
		fprintf(stderr, "priv_sock_send_result error");
		exit(EXIT_FAILURE);
	}
}
/*接收结果（子<-父）*/
char priv_sock_get_result(int fd)
{
	char res;
	int ret = 0;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res))
	{
		fprintf(stderr, "priv_sock_get_result error");
		exit(EXIT_FAILURE);
	}	
	return res;	
}

/*发送一个整数*/
void priv_sock_send_int(int fd, int the_int)
{
	int ret = 0;
	ret = writen(fd, &the_int, sizeof(the_int));
	if (ret != sizeof(the_int))
	{
		fprintf(stderr, "priv_sock_send_result error");
		exit(EXIT_FAILURE);
	}
}
/*接收一个整数*/
int priv_sock_get_int(int fd)
{
	int the_int = 0;
	
	int ret = 0;
	ret = readn(fd, &the_int, sizeof(the_int));
	if (ret != sizeof(the_int))
	{
		fprintf(stderr, "priv_sock_get_int error");
		exit(EXIT_FAILURE);
	}	
	
	return the_int;
}

/*发送一个字符串*/
void priv_sock_send_buf(int fd, const char *buf, unsigned int len)
{
	/*先发送字符串的长度*/
	priv_sock_send_int(fd, len);
	/*发送字符串*/
	int ret = writen(fd, buf, len);
	if (ret != (int)len)
	{
		fprintf(stderr, "priv_sock_send_buf error");
		exit(EXIT_FAILURE);
	}	
}
/*接收一个字符串*/
void priv_sock_recv_buf(int fd, char *buf, unsigned int len)
{
	unsigned int recv_len = (unsigned int)priv_sock_get_int(fd);
	if (recv_len > len)
	{
		fprintf(stderr, "priv_sock_recv_buf error\n");
		exit(EXIT_FAILURE);		
	}
	
	int ret = readn(fd, buf, recv_len);
	if (ret != recv_len)
	{
		fprintf(stderr, "priv_sock_recv_buf error\n");
		exit(EXIT_FAILURE);			
	}
	
}
/*发送文件描述符*/
void priv_sock_send_fd(int sock_fd, int fd)
{
	send_fd(sock_fd, fd);
}
/*接受文件描述符*/
int priv_sock_recv_fd(int sock_fd)
{
	return recv_fd(sock_fd);
}