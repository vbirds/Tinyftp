#include "privparent.h"
#include "sckutil.h"
#include "commsocket.h"

void handle_parent(session_t *sess)
{
	char buf[MAX_COMMAND_LINE];
	while (1)
	{
		readn(sess->parent_fd, buf, sizeof(buf));
		//解析命令
		
		//处理命令
	}
}