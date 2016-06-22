#include "privparent.h"
#include "sckutil.h"
#include "commsocket.h"
#include "common.h"

void handle_parent(session_t *sess)
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
	
	char buf[MAX_COMMAND_LINE];
	while (1)
	{
		readn(sess->parent_fd, buf, sizeof(buf));
		//解析命令
		
		//处理命令
	}
}