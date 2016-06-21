#include "commsocket.h"
#include "sckutil.h"
#include "session.h"
#include "pwd.h"


void begin_session(session_t *sess)
{	
	int sockfds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
	{
		ERR_EXIT("socketpair");
	}
	
	pid_t pid;
	pid = fork();
	if (pid < 0)
	{
		ERR_EXIT("fork");
	}
	
	if (pid == 0)
	{
		//ftp服务进程
		close(sockfds[0]);
		sess->child_fd = sockfds[1];
		handle_child(sess);
	}
	else
	{
		/*将父进程变成nobody进程*/
		struct passwd *pw = getpwnam("nobody");
		if (pw == NULL)
		{
			return;
		}
		if (setegid(pw->pw_gid) < 0)
		{
			ERR_EXIT("setegid");
		}
		if (seteuid(pw->pw_uid) < 0)
		{
			ERR_EXIT("seteuid");
		}
		//nobody进程
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		handle_parent(sess);
	}
}