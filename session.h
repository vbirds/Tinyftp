#ifndef _SESSION_H_
#define _SESSION_H_

#include "sckutil.h"

typedef struct session
{
	//控制连接
	uid_t uid;	
	int  ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	
	//数据连接
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;
	int data_fd;
	int data_process;  /*当前有没处于传输数据的状态*/
	
	//限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;
	
	//父子进程通道
	int parent_fd;
	int child_fd;
	
	//FTP协议状态
	int is_ascii;
	long long restart_pos; //设置断点续传
	char *rnfr_name;
	int abor_received;
	
	//连接数限制
	unsigned int num_clients;
	
} session_t;

void begin_session(session_t *sess);

#endif /*_SESSION_H_*/