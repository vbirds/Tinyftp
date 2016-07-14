#include "commsocket.h"
#include "sckutil.h"
#include "session.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "common.h"

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

extern session_t *p_sess;
static unsigned int s_children;


void check_limits(session_t *sess);
void handle_sigchld(int sig);

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
		NULL,-1,-1,0,
		/*限速*/
		0,0,0,0,
		/*父子进程通道*/
		-1,-1,
		/*FTP协议状态*/
		0,0,NULL,0,
		/*连接数限制*/
		0
	};
	p_sess = &sess;
	
	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;
	
	
	signal(SIGCHLD, handle_sigchld);
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
		
		++s_children;
		sess.num_clients = s_children;
		
		pid = fork();
		if (pid == -1)
		{
			--s_children;
			ERR_EXIT("fork");
		}
		if (pid == 0)
		{
			close(listenfd);
			sess.ctrl_fd = connfd;
			//开启一个新会话
			
			check_limits(&sess);
			
			//让session中的进程忽略handle_sigchld处理函数
			signal(SIGCHLD, SIG_IGN);
			begin_session(&sess);
		}
		else
		{
			close(connfd);
		}
	}
	
	return 0;
}

void check_limits(session_t *sess)
{
	if (tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		//421响应 FTP_TOO_MANY_USERS
		ftp_relply(sess, FTP_TOO_MANY_USERS, "There are too many connected users please try later");
		exit(EXIT_FAILURE);
	}
}

void handle_sigchld(int sig)
{
	//避免僵尸进程
	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		;
	}
	
	--s_children;

}

