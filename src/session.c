#include "commsocket.h"
#include "sckutil.h"
#include "session.h"
#include "pwd.h"
#include "privsock.h"


void begin_session(session_t *sess)
{	
	/*开启接收带外数据*/
	activate_oobinline(sess->ctrl_fd);

/*
	int sockfds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
	{
		ERR_EXIT("socketpair");
	}
*/
	/*初始化内部进程间通讯通道*/
	priv_sock_init(sess);
	
	pid_t pid;
	pid = fork();
	if (pid < 0)
	{
		ERR_EXIT("fork");
	}
	
	if (pid == 0)
	{
		//ftp服务进程
		/*
		close(sockfds[0]);
		sess->child_fd = sockfds[1];
		*/
		/*设置子进程环境*/
		priv_sock_set_child_context(sess);		
		handle_child(sess);
	}
	else
	{
		//nobody进程
		/*
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		*/
		/*设置父进程环境*/
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}