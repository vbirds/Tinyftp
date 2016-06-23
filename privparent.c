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

int capset(cap_user_header_t hdrp, const cap_user_data_t datap);
/*设置最小化特权*/
int minimize_privilege();

int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	/*系统调用capset*/
	syscall(__NR_capset, hdrp, datap);
	return 0;
}

int minimize_privilege()
{
	/*设置权限 让nobody进程可以绑定20端口*/
    struct __user_cap_header_struct  cap_header;
	struct __user_cap_data_struct  cap_data;
	
	memset(&cap_header, 0, sizeof(cap_header));
	memset(&cap_data, 0, sizeof(cap_data));
	
	cap_header.version = _LINUX_CAPABILITY_VERSION_1;
	cap_header.pid = 0;
	
	__u32 cap_mask = 0;
	cap_mask |= (1 << CAP_NET_BIND_SERVICE); //绑定系统端口
	cap_data.effective = cap_data.permitted = cap_mask;
	cap_data.inheritable = 0;
	
	capset(&cap_header, &cap_data);	
	
	return 0;
}

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
	
	minimize_privilege();
	
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
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
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
	//sckServer_init(tunable_listen_address, 20, &data_sockfd);
	data_sockfd = tcp_client(tunable_listen_address, 20);
	
	if (data_sockfd == -1)
	{ 
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	
	printf("helloo\n");
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
	int active;
	if (sess->pasv_listen_fd != -1)
	{
		active = 1;
	}
	else
	{
		active = 0;
	}
	
	priv_sock_send_int(sess->parent_fd, active); 
}
static void privop_pasv_listen(session_t *sess)
{
	/*监听套接字*/
	char ip[16] = {0};
	strcpy(ip, tunable_listen_address);
	
	int fd = -1;
	sckServer_init(ip, 0, &fd);
	sess->pasv_listen_fd = fd;
	
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}
	unsigned short port = ntohs(addr.sin_port);
	priv_sock_send_int(sess->parent_fd, port);
}
static void privop_pasv_accept(session_t *sess)
{
	int connfd = -1;
	int ret = sckServer_accept(sess->pasv_listen_fd, &connfd, tunable_accept_timeout);
	
	//关闭监听套接字
	close(sess->pasv_listen_fd);
	if (ret != Sck_Ok)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, connfd);
	
	close(connfd);
}
