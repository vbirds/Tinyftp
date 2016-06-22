#include "privparent.h"
#include "sckutil.h"
#include "commsocket.h"
#include "common.h"
#include "privsock.h"
#include "tunable.h"


static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

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
	
	char cmd;
	while (1)
	{
		//readn(sess->parent_fd, buf, sizeof(buf));
		cmd = priv_sock_get_cmd(sess->parent_fd);
		//解析命令
		//处理命令
		switch (cmd)
		{
		case PRIV_SOCK_GET_DATA_SOCK:
			privop_pasv_get_data_sock(sess);
			break;
		case PRIV_SOCK_PASV_ACTIVE:
			privop_pasv_active(sess);
			break;
		case PRIV_SOCK_PASV_LISTEN:
			privop_pasv_listen(sess);
			break;
		case PRIV_SOCK_PASV_ACCETP:
			privop_pasv_accept(sess);
			break;
		}
	}
}

static void privop_pasv_get_data_sock(session_t *sess)
{
	/*接收port*/
	unsigned short port = priv_sock_get_int(sess->parent_fd);
	/*接收ip*/
	char ip[16] = {0};
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
	
	/*创建数据连接*/
	int data_sockfd = -1;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	//addr.sin_addr = inet_addr(ip)
	inet_pton(AF_INET, ip, &addr.sin_addr);
	
	/*绑定20端口*/
	sckServer_init(tunable_listen_address, 20, &data_sockfd);
	if (data_sockfd == -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	
	if (connect_timeout(data_sockfd, &addr, tunable_connect_timeout) < 0)
	{
		close(data_sockfd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	/*发送成功信息*/
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	/*传输文件描述符*/
	priv_sock_send_fd(sess->parent_fd, data_sockfd);

	close(data_sockfd);
}
static void privop_pasv_active(session_t *sess)
{

}
static void privop_pasv_listen(session_t *sess)
{
	
}
static void privop_pasv_accept(session_t *sess)
{
	
}
