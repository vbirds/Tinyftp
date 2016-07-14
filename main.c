#include "commsocket.h"
#include "sckutil.h"
#include "session.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "common.h"
#include "hash.h"

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

static hash_t *s_ip_count_hash;
static hash_t *s_pid_ip_hash;  //pid与ip对应关系哈希表


void check_limits(session_t *sess);
void handle_sigchld(int sig);
unsigned int hash_func(unsigned int buckets, void *key);

unsigned int handle_ip_count(void *ip);
void drop_ip_count(void *ip);

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
		0,0
	};
	p_sess = &sess;
	
	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;
	s_ip_count_hash = hash_alloc(256, hash_func);
	s_pid_ip_hash = hash_alloc(256, hash_func);
	
	signal(SIGCHLD, handle_sigchld);
	int listenfd = 0;
	int ret = sckServer_init(tunable_listen_address, tunable_listen_port, &listenfd);
	int connfd = 0;
	pid_t pid;
	struct sockaddr_in addr;
	
	while (1)
	{
		
		//connfd = accept_timeout(listenfd, &addr, 0);
		ret = sckServer_accept(listenfd, &connfd, (void*)&addr, 0);
		if (ret == Sck_ErrTimeOut)
		{
			ERR_EXIT("accept timeout");
		}

		unsigned int ip = addr.sin_addr.s_addr;
		//printf("get_sock_addr ip: %u\n", ip);//++++
		sess.num_this_ip = handle_ip_count(&ip);

		
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
			
			check_limits(&sess);
			
			//让session中的进程忽略handle_sigchld处理函数
			signal(SIGCHLD, SIG_IGN);
			//开启一个新会话
			begin_session(&sess);
		}
		else
		{
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid),
				&ip, sizeof(unsigned int));
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
	
	if (tunable_max_per_ip >0 && sess->num_this_ip > tunable_max_per_ip)
	{
		//421响应 FTP_IP_LIMIT
		ftp_relply(sess, FTP_IP_LIMIT, "There are too many connecter from your internal addr");
		exit(EXIT_FAILURE);
	}
	
}

void handle_sigchld(int sig)
{
	//避免僵尸进程
	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		--s_children;
		unsigned int *ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if (ip == NULL)
		{
			continue;
		}
		
		drop_ip_count(ip);
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}
	
}

unsigned int hash_func(unsigned int buckets, void *key)
{
	unsigned int *number = (unsigned int*)key;
	
	return (*number) % buckets;
}

unsigned int handle_ip_count(void *ip)
{
	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, 
		ip, sizeof(unsigned int));
		
	if (p_count == NULL)
	{
		//该ip第一次连接
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int),
			&count, sizeof(unsigned int));
	}
	else
	{
		count = *p_count;
		++count;
		*p_count = count;
	}
	
	//printf("handle_ip_count :%u\n", count);//+++++
	
	return count;
}

void drop_ip_count(void *ip)
{
	unsigned int count;
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash, 
		ip, sizeof(unsigned int));
		
	if (p_count == NULL)
	{
		//该ip第一次连接
		return;
	}

	count = *p_count;
	if (count <= 0)
	{
		return;
	}
	--count;
	*p_count = count;
	
	if (count == 0)
	{
		//删除表项
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
	
	//printf("drop_ip_count :%u\n", count);//++++++
	
}
