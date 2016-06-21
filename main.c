#include "commsocket.h"
#include "sckutil.h"
#include "session.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"

void paint_conf()
{
	printf("tunable_pasv_enable: %d\n", 			tunable_pasv_enable);
	printf("tunable_port_enable: %d\n", 			tunable_port_enable);
	printf("tunable_listen_port: %u\n", 			tunable_listen_port);
	printf("tunable_max_clients: %u\n",			tunable_max_clients);
	printf("tunable_max_per_ip:  %u\n", 			tunable_max_per_ip);
	printf("tunable_accept_timeout: %u\n", 		tunable_accept_timeout);
	printf("tunable_connect_timeout: %u\n", 		tunable_connect_timeout);
	printf("tunable_idle_session_timeout: %u\n", 	tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout: %u\n",tunable_data_connection_timeout);
	printf("tunable_local_umask: %u\n", 			tunable_local_umask);
	printf("tunable_upload_max_rate: %u\n", 		tunable_upload_max_rate);
	printf("tunable_download_max_rate: %u\n", 		tunable_download_max_rate);
	//printf("tunable_listen_address: %s\n", 			tunable_listen_address);
	
	if (tunable_listen_address == NULL)
	{
		printf("tunable_listen_address: NULL\n");
	}
	else
	{
		printf("tunable_listen_address: %s\n",tunable_listen_address);
	}
}


int main(void)
{
	
	parseconf_load_file("./miniftpd.conf");
	
	paint_conf();
	
	//list_common();
	
	if (getuid() !=0)
	{
		fprintf(stderr, "miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}
	
	session_t sess = {
		/*控制连接*/
		0,-1,"","","",
		/*数据连接*/
		NULL,-1,-1,
		/*父子进程通道*/
		-1,-1,
		/*FTP协议状态*/
		0
	};
	
	int listenfd = 0;
	int ret = sckServer_init(tunable_listen_address, tunable_listen_port, &listenfd);
	int connfd = 0;
	pid_t pid;
	while (1)
	{
		ret = sckServer_accept(listenfd, &connfd, 0);
		if (ret == Sck_ErrTimeOut)
		{
			ERR_EXIT("accept timeout");
		}
		
		pid = fork();
		if (pid == -1)
		{
			ERR_EXIT("fork");
		}
		if (pid == 0)
		{
			close(listenfd);
			sess.ctrl_fd = connfd;
			//开启一个新会话
			begin_session(&sess);
		}
		else
		{
			close(connfd);
		}
	}
	
	return 0;
}