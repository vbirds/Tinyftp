#define _GNU_SOURCE 
#include <crypt.h>
#include <sys/types.h>
#include <shadow.h>
#include <fcntl.h>

#include "common.h"
#include "ftpproto.h"
#include "sckutil.h"
#include "commsocket.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"

void handle_alarm_timeout(int sig);
void handle_sigurg(int sig);
void handle_sigalrm(int sig);
void start_cmdio_alarm(void);
void start_data_alarm(void);

void check_abor(session_t *sess);

void ftp_relply(session_t *sess, int status, const char *text);
void ftp_lrelply(session_t *sess, int status, const char *text);
void ftp_frelply(session_t *sess, const char *text); /*feature relply*/

int list_common(session_t *sess, int detail); /*列出目录*/
void upload_common(session_t *sess, int is_apped);
void limit_rate(session_t *sess, int bytes, int is_upload);
void file_stat(const char *path, char *buf, struct stat *sbuf);/*文件的信息 权限位 uid gid size等等*/

int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);

int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);

static void  do_user(session_t *sess);
static void  do_pass(session_t *sess);
static void  do_cwd(session_t *sess);
static void  do_cdup(session_t *sess);
static void  do_quit(session_t *sess);
static void  do_port(session_t *sess);
static void  do_pasv(session_t *sess);
static void  do_type(session_t *sess);
static void  do_stru(session_t *sess);
static void  do_mode(session_t *sess);
static void  do_retr(session_t *sess);
static void  do_stor(session_t *sess);
static void  do_appe(session_t *sess);
static void  do_list(session_t *sess);
static void  do_nlst(session_t *sess);
static void  do_rest(session_t *sess);
static void  do_abor(session_t *sess);
static void  do_pwd(session_t *sess);
static void  do_mkd(session_t *sess);
static void  do_rmd(session_t *sess);
static void  do_dele(session_t *sess);
static void  do_rnfr(session_t *sess);
static void  do_rnto(session_t *sess);
static void  do_site(session_t *sess);
static void  do_syst(session_t *sess);
static void  do_feat(session_t *sess);
static void  do_size(session_t *sess);
static void  do_stat(session_t *sess);
static void  do_noop(session_t *sess);
static void  do_help(session_t *sess);

typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

/*命令映射*/
static ftpcmd_t ctrl_cmds[] = {
	/*访问控制命令*/
	{"USER",  do_user },
	{"PASS",  do_pass },
	{"CWD",   do_cwd  },
	{"XCWD",  do_cwd  },
	{"CDUP",  do_cdup },
	{"XCUP",  do_cdup },
	{"QUIT",  do_quit },
	{"ACCT",  NULL    },
	{"SMNT",  NULL    },
	{"REIN",  NULL    },
	/*传输参数命令*/
	{"PORT",  do_port },
	{"PASV",  do_pasv },
	{"TYPE",  do_type },
	{"STRU",  do_stru },
	{"MODE",  do_mode },
	/*服务命令*/
	{"RETR",  do_retr },
	{"STOR",  do_stor },
	{"APPE",  do_appe },
	{"LIST",  do_list },
	{"NLST",  do_nlst },
	{"REST",  do_rest },
	{"ABOR",  do_abor },
	{"\377\364\377\362ABOR", do_abor },
	{"PWD",   do_pwd  },
	{"XPWD",  do_pwd  },
	{"MKD",   do_mkd  },
	{"RMD",   do_rmd  },
	{"XRMD",  do_rmd  },
	{"DELE",  do_dele },
	{"RNFR",  do_rnfr },
	{"RNTO",  do_rnto },
	{"SITE",  do_site },
	{"SYST",  do_syst },
	{"FEAT",  do_feat },
	{"SIZE",  do_size },
	{"STAT",  do_stat },
	{"NOOP",  do_noop },
	{"HELP",  do_help },
	{"STOU",  NULL    },
	{"ALLO",  NULL    }
};

session_t *p_sess;
void handle_alarm_timeout(int sig)
{
	/*关闭读端*/
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_relply(p_sess, FTP_IDLE_TIMEOUT, "Timeout.");//421
	/*关闭写端*/
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_FAILURE);
}

void handle_sigalrm(int sig)
{
	if (p_sess->data_process == 0)
	{
		ftp_relply(p_sess, FTP_DATA_TIMEOUT, "Dta timeout. Reconnect. Sorry");//421
		exit(EXIT_FAILURE);	
	}
	//否则，当前处于数据传输的状态收到了超时信号
	p_sess->data_process = 0;
	start_data_alarm();
}

void handle_sigurg(int sig)
{
	if (p_sess->data_fd == -1)
	{
		return;
	}
	
	//处于数据传输状态
	char cmdline[MAX_COMMAND_LINE] = {0};
	int ret = readline(p_sess->ctrl_fd, cmdline, MAX_COMMAND_LINE);
	if (ret <= 0)
	{
		ERR_EXIT("readline");
	}
	str_trim_crlf(cmdline);
	/*判断是否ABOR命令*/
	if (strcmp(cmdline, "ABOR") == 0
		|| strcmp(cmdline,"\377\364\377\362ABOR") == 0)
	{
		p_sess->abor_received = 1;
		//断开数据连接通道
		shutdown(p_sess->data_fd, SHUT_RDWR);
	}
	else //错误命令
	{
		//500
		ftp_relply(p_sess, FTP_BADCMD, "Unknown command");
	}
	
}
/*检查ABOR是否接收*/
void check_abor(session_t *sess)
{
	if (sess->abor_received == 1)
	{
		sess->abor_received = 0;
		//226
		ftp_relply(sess, FTP_ABOROK, "ABOR successful");
	}
}

void start_cmdio_alarm(void)
{
	if (tunable_idle_session_timeout > 0)
	{
		//安装信号
		signal(SIGALRM, handle_alarm_timeout);
		//启动闹钟
		alarm(tunable_idle_session_timeout);
	}
}

void start_data_alarm(void)
{
	if (tunable_data_connection_timeout > 0)
	{
		//安装信号
		signal(SIGALRM, handle_alarm_timeout);
		//启动闹钟
		alarm(tunable_data_connection_timeout);
	}
	else if (tunable_idle_session_timeout > 0)
	{
		//关闭先前安装的闹钟
		alarm(0);
	}
}
		
void handle_child(session_t *sess)
{
	int ret = 0;
	ftp_relply(sess, FTP_GREET, "(miniftpd 0.1)");

	while (1)
	{
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));
		
		/*启动闹钟*/
		start_cmdio_alarm();
		
		ret = readline(sess->ctrl_fd, (void*)(sess->cmdline), MAX_COMMAND_LINE);
		if (ret < 0)
		{
			ERR_EXIT("readline");
		}
		else if (ret == 0)
		{
			exit(EXIT_SUCCESS);
		}
		
		//printf("cmdline=[%s]\n", sess->cmdline);
		//去除\r\n
		str_trim_crlf(sess->cmdline);
		//printf("cmdline=[%s]\n", sess->cmdline);
		//解析TFP命令和参数
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		//printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		//将命令转换为大写
		str_upper(sess->cmd);
		//处理FTP命令
		int i = 0;
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		for (i = 0; i < size; ++i)
		{
			if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if (ctrl_cmds[i].cmd_handler != NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);	
				}
				else
				{
					/*未实现命令*/
					ftp_relply(sess, FTP_COMMANDNOTIMPL, "Uncompletement command");	
				}	
				break;
			}
		} /*end for*/
		if (i == size)
		{
			/*不认识命令*/
			ftp_relply(sess, FTP_BADCMD, "Bad command");			
		}
	}
}

void ftp_relply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lrelply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));	
}

void ftp_frelply(session_t *sess, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, " %s\r\n", text);
	writen(sess->ctrl_fd, buf, strlen(buf));	
}

int list_common(session_t *sess, int detail)
{
	DIR *dir = opendir(".");
	if (dir == NULL)
	{
		return 0;
		
	}
	struct dirent *dt = NULL;
	struct stat sbuf;
	
	
	while ((dt = readdir(dir)) != NULL)
	{
		/*lstat(const char *path, struct stat *buf);*/
		
		/*权限获取*/
		if (lstat(dt->d_name, &sbuf) < 0)
		{
			continue;
		}
		/*过滤 '.'和'..' 目录 和文件*/
		if (dt->d_name[0] == '.')
		{
			continue;
		}
		char buf[1024] = {0};
		if (detail)
		{
			/*获取权限位信息*/
			const char *perms =statbuf_get_perms(&sbuf);
			
			int off = 0;
			/*权限位*/
			off += sprintf(buf, "%s ", perms);
			/*硬连接数 uid gid*/
			off += sprintf(buf + off,"%3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			/*文件大小*/
			off += sprintf(buf + off, "%-8lu ", (unsigned long)sbuf.st_size);
			
			/*时间格式化*/
			const char *datebuf = statbuf_get_date(&sbuf);
			
			off += sprintf(buf + off, "%s ", datebuf);
			
			/*格式化添加文件名*/
			
			/*判读是否连接文件，如果是连接文件添加指向的文件名*/
			if (S_ISLNK(sbuf.st_mode))
			{
				char real_file_buf[64] = {0};
				readlink(dt->d_name, real_file_buf, sizeof(real_file_buf));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, real_file_buf);
			}
			else
			{
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}
			
		}/*end if*/
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}
		//printf("%s", buf);
		writen(sess->data_fd, buf, strlen(buf));
			
	}/*end while*/
	
	/*关闭目录*/
	closedir(dir);
	
	return 0;
}

/*限速*/
void limit_rate(session_t *sess, int bytes, int is_upload)
{
	sess->data_process = 1;
	//睡眠时间 = （当前传输速度/最大速度 -1）* 当前传输时间
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();
	
	double elapsed;
	elapsed = (double)(curr_sec - sess->bw_transfer_start_sec);
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;
	if (elapsed < (double)0)
	{
		elapsed = (double)0.01;
	}
	
	
	/*计算当前传输速度*/
	unsigned int  bw_rate = (unsigned int)((double)bytes / elapsed);
	double rate_ratio;
	if (is_upload)
	{
		if (bw_rate < sess->bw_upload_rate_max)
		{
			//不需要限速
			/*重新更新时间*/
			sess->bw_transfer_start_sec = get_time_sec();
			sess->bw_transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	}
	else
	{
		if (bw_rate < sess->bw_download_rate_max)
		{
			//不需要限速
			/*重新更新时间*/
			sess->bw_transfer_start_sec = get_time_sec();
			sess->bw_transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}
	double pause_time;
	pause_time = (rate_ratio - (double)(1)) * elapsed;
	
	nano_sleep(pause_time);
	
	/*重新更新时间*/
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
}

/*上传文件*/
void upload_common(session_t *sess, int is_apped)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	/*保存断点*/
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	//打开文件
	int fd = open(sess->arg, O_CREAT | O_WRONLY | O_APPEND, 0666);
	if (fd == -1)
	{
		ftp_relply(sess, FTP_UPLOADFAIL, "Could not creat file.");
		return;
	}
	//加锁
	int ret = lock_file_write(fd);
	if (ret == -1)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Could not creat file.");
		return;		
	}

	//STOR 
	//REST + STOR 
	//APPE
	if (!is_apped && offset == 0) //STOR
	{
		//ftruncate 清零
		ftruncate(fd, 0);
		//定位到文件头
		if (lseek(fd, 0, SEEK_SET) < 0)
		{
			ftp_relply(sess, FTP_FILEFAIL, "Could not creat file.");
			return;				
		}
	}
	else if (!is_apped && offset != 0) //REST + STOR 
	{
		if (lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_relply(sess, FTP_FILEFAIL, "Could not creat file.");
			return;			
		}
	}
	else if (is_apped)//APPE模式
	{
		if (lseek(fd, 0, SEEK_END) < 0)
		{
			ftp_relply(sess, FTP_FILEFAIL, "Could not creat file.");
			return;	
		}
	}	
	
	//获取文件状态
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_relply(sess, FTP_FILEFAIL, "Could not creat file.");
		return;		
	}
	
	//向客户端响应 150  
	//Opening BINARY mode data connection for /home/jhz/dump.rdb (18 bytes).

	ftp_relply(sess, FTP_DATACONN, "Ok to send data.");
	

	//上传文件
	int flag = 0;
	char buf[65536] = {0};
	/*记录当前时间*/
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
	while (1)
	{
		ret = read(sess->data_fd, buf, sizeof(buf));
		if  (ret == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				flag = 1;
				break;
			}
		}
		else if (ret == 0)  //传输完成
		{
			flag = 0;
			break;
		}
		
		//限速
		limit_rate(sess, ret, 1);
		if (sess->abor_received == 1)
		{
			//426
			flag = 1;
			break;
		}
		
		if (writen(fd, buf, ret) != ret)
		{
			flag = 2;
			break;
		}
	}

	
	//关闭数据连接套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	close(fd);
	
	//传输完毕 发送226
	if (flag == 0 && !sess->abor_received)
	{
		//226
		ftp_relply(sess, FTP_TRANSFEROK, "Transfer complete.");
		
	}
	else if (flag == 1)
	{
		//426 FTP_BADSENDNET
		ftp_relply(sess, FTP_BADSENDNET, "Failure reading from local file.");
	}
	else if (flag == 2)
	{
		//451
		ftp_relply(sess, FTP_BADSENDFILE, "Failure recving to network stream.");
	}
	
	/*检查是否接收ABOR  426*/
	check_abor(sess);
	
	/*重新开启控制连接闹钟*/
	start_cmdio_alarm();
}

void file_stat(const char *path, char *buf, struct stat *sbuf)
{
	if (path == NULL || buf == NULL || sbuf == NULL)
	{
		fprintf(stderr, "file_stat buf == NULL || sbuf == NULL");
		return;
	}
	
	if (lstat(path, sbuf) < 0)
	{
		return;
	}
	
	/*获取权限位信息*/
	const char *perms =statbuf_get_perms(sbuf);
	
	int off = 0;
	/*权限位*/
	off += sprintf(buf, "%s ", perms);
	/*硬连接数 uid gid*/
	off += sprintf(buf + off,"%3d %-8d %-8d ", sbuf->st_nlink, sbuf->st_uid, sbuf->st_gid);
	/*文件大小*/
	off += sprintf(buf + off, "%-8lu ", (unsigned long)sbuf->st_size);
	
	/*时间格式化*/
	const char *datebuf = statbuf_get_date(sbuf);
	
	off += sprintf(buf + off, "%s ", datebuf);
	
	/*格式化添加文件名*/
	
	/*判读是否连接文件，如果是连接文件添加指向的文件名*/
	if (S_ISLNK(sbuf->st_mode))
	{
		char real_file_buf[64] = {0};
		readlink(path, real_file_buf, sizeof(real_file_buf));
		off += sprintf(buf + off, "%s -> %s\r\n", path, real_file_buf);
	}
	else
	{
		off += sprintf(buf + off, "%s\r\n", path);
	}
}

static void  do_user(session_t *sess)
{
	//USER XXX
	struct passwd *pw = getpwnam(sess->arg);
	if (pw == NULL)
	{
		//用户不存在
		ftp_relply(sess, FTP_LOGINERR, "Login incorrect");
		return;
	}
	sess->uid = pw->pw_uid;
	ftp_relply(sess, FTP_GIVEPWORD, "Please specify the password");
}

static void  do_pass(session_t *sess)
{
	//PASS 123456
	struct passwd *pw = getpwuid(sess->uid);	
	if (pw == NULL)
	{
		//用户不存在
		ftp_relply(sess, FTP_LOGINERR, "Login incorrect");
		return;
	}
	
	struct spwd *sp = getspnam(pw->pw_name);
	if (sp == NULL)
	{
		ftp_relply(sess, FTP_LOGINERR, "Login incorrect");
		return;		
	}
	
	// 加密明文
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
	//验证密码
	if (strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_relply(sess, FTP_LOGINERR, "Login incorrect");
		return;			
	}
	/*更改掩码*/
	umask(tunable_local_umask);
	
	// 登入成功
	ftp_relply(sess, FTP_LOGINOK, "Login successful");
	
	//接收SIGURG
	signal(SIGURG, handle_sigurg);
	/*开启接收SIGURG*/
	activate_sigurg(sess->ctrl_fd);
	
	//将当前进程用户更改为 登入用户
	if (setegid(pw->pw_gid) < 0)
	{
		ERR_EXIT("setegid");
	}
	if (seteuid(pw->pw_uid) < 0)
	{
		ERR_EXIT("seteuid");
	}
	//更改用户目录
	if ( chdir(pw->pw_dir) < 0 )
	{
		ERR_EXIT("chdir");
	}		
}
int port_active(session_t *sess)
{
	if (sess->port_addr)
	{
		 if (pasv_active(sess))
		 {
			 fprintf(stderr, "both port and pasv are active");
			 exit(EXIT_FAILURE);
		 }
		return 1;
	}
	return 0;
}

int pasv_active(session_t *sess)
{
	/*
	if (sess->pasv_listen_fd != -1)
	{
		if (port_active(sess))
		{
			fprintf(stderr, "both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	*/
	/*向nobody进程请求是否处于被动模式*/
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int  active = priv_sock_get_int(sess->child_fd);
	if (active)
	{
		if (port_active(sess))
		{
			fprintf(stderr, "both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	
	return 0;
}


int get_port_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	/*发送端口*/
	priv_sock_send_int(sess->child_fd, (int)port);
	/*发送ip*/
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));
	/*接受应答*/
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		/*接收文件描述符*/
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	
	return 1;
}

int get_pasv_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCETP);
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	
	return 1;
}

int get_transfer_fd(session_t *sess)
{ 
	int  ret = 1;
	//判断先前是否接收过PORT或PASV
	if (!port_active(sess) && !pasv_active(sess))
	{
		ftp_relply(sess, FTP_BADSENDCONN, "Use PORT or PASV first");
		return 0;
	}
	
	//创建数据套接字
	
	
	/*
	void *handle = NULL;
	int data_sockfd = 0;
	if (port_active(sess))
	{
		sckCliet_init(&handle, tunable_connect_timeout, 0, 0, 1);
		int ret = sckCliet_getconn(handle, inet_ntoa(sess->port_addr->sin_addr), ntohs(sess->port_addr->sin_port), &data_sockfd);
		if (ret != Sck_Ok)
		{
			sckClient_destroy(handle);
		}
		sess->data_fd = data_sockfd;
	}
	*/
	/*如果是主动模式*/
	if (port_active(sess))
	{
		/*创建数据套接字失败*/
		if (get_port_fd(sess) == 0)
		{ 
			ret = 0;
		}		
	}

	
	//被动模式
	if (pasv_active(sess))
	{
		/*
		int connfd = -1;
		int ret = sckServer_accept(sess->pasv_listen_fd, &connfd, tunable_accept_timeout);
		{
			//关闭监听套接字
			close(sess->pasv_listen_fd);
			if (ret != Sck_Ok)
			{
				return 0;
			}
		}
		sess->data_fd = connfd;
		*/
		if (get_pasv_fd(sess) == 0)
		{
			return 0;
		}
	}
	
	if (ret == 0)
	{
		if (sess->port_addr)
		{
			free(sess->port_addr);
			sess->port_addr = NULL;
		}
	}

	if (ret)
	{
		/*开启数据连接闹钟*/
		start_data_alarm();
	}
	return 1;
}

static void  do_cwd(session_t *sess)
{
	char *cwdir = sess->arg;
	//更改用户目录
	if ( chdir(cwdir) < 0 )
	{
		ftp_relply(sess, FTP_NOPERM,"Failured to change directory.");
		return;
	}	
	
	ftp_relply(sess, FTP_CWDOK,"Directory successfully changed.");
}
static void  do_cdup(session_t *sess)
{
	//更改用户目录
	if ( chdir("..") < 0 )
	{
		ftp_relply(sess, FTP_NOPERM,"Failured to change directory.");
		return;
	}	
	
	ftp_relply(sess, FTP_CWDOK,"Directory successfully changed.");	
}
static void  do_quit(session_t *sess)
{
	//221应答
	ftp_relply(sess, FTP_GOODBYE, "Goodbye.");
	exit(EXIT_SUCCESS);
}
static void  do_port(session_t *sess)
{
	//PORT 192,168,150,13,123,233  //最后两个 一个是高八位 一个是低八位
	unsigned int v[6];
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	
	sess->port_addr->sin_family = AF_INET;
	
	unsigned char *p = (unsigned char *)&(sess->port_addr->sin_port);
	p[0] = v[0];
	p[1] = v[1];
	
	p = (unsigned char *)&(sess->port_addr->sin_addr);
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];
	
	ftp_relply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV");
	
}
static void  do_pasv(session_t *sess)
{
	char ip[16] = {0};
	strcpy(ip, tunable_listen_address);
	
	/*监听套接字*/
	/*
	int fd = -1;
	sckServer_init(ip, 0, &fd);
	sess->pasv_listen_fd = fd;
	
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}
	*/
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (int)priv_sock_get_int(sess->child_fd);
	
	//unsigned short port = ntohs(addr.sin_port);
	
	//格式化ip和 端口
	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0],&v[1],&v[2],&v[3]);
	
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", v[0],v[1],v[2],v[3], port>>8, port&0xFF);
	
	ftp_relply(sess, FTP_PASVOK, text);
}
static void  do_type(session_t *sess)
{
	if (strcmp(sess->arg, "A") == 0)
	{
		ftp_relply(sess, FTP_TYPEOK, "Swiching to ASCII mode");
	}
	else if (strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 1;
		ftp_relply(sess, FTP_TYPEOK, "Swiching to Binarry mode");
	}
	else
	{
		ftp_relply(sess, FTP_BADCMD, "Unrecognised Type command");	
	}
}
static void  do_stru(session_t *sess)
{
	
}
static void  do_mode(session_t *sess)
{
	
}
/*下载文件 支持断点续载*/
static void  do_retr(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	//打开文件
	int fd = open(sess->arg, O_RDONLY);
	if (fd == -1)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Failured to open file.");
		return;
	}
	//加锁
	int ret = lock_file_read(fd);
	if (ret == -1)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Failured to open file.");
		return;		
	}
	//判断是否为普通文件
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_relply(sess, FTP_FILEFAIL, "Failured to open file.");
		return;		
	}
	
	long long bytes_to_send = sbuf.st_size;
	if (offset > bytes_to_send)
	{
		bytes_to_send = 0;
	}
	else
	{
		bytes_to_send -= offset;
	}
	
	//向客户端响应 150  
	//Opening BINARY mode data connection for /home/jhz/dump.rdb (18 bytes).
	char text[1024] = {0};
	if (sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lu bytes).", sess->arg, sbuf.st_size);
	}
	sprintf(text, "Opening BINARY mode data connection for %s (%lu bytes).", sess->arg, sbuf.st_size);
	 
	ftp_relply(sess, FTP_DATACONN, text);
	
	/*为了方便，默认在此不对二进制传输进行转换*/
	
	//零拷贝传输数据  下载文件
	/*防止传输被中断*/
	int flag = 0;
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
	while (bytes_to_send)
	{
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		ssize_t bytes = sendfile(sess->data_fd, fd, (off_t*)&offset, (size_t)num_this_time);
		if (bytes == -1)
		{
			flag = 2;
			break;
		}/*end if*/
		/*限速*/
		limit_rate(sess, bytes, 0);
		if (sess->abor_received == 1)
		{
			flag = 1;
			break;
		}
		bytes_to_send -= bytes;
	}/*end while*/
	if (bytes_to_send == 0)
	{
		flag = 0;
	}
	
	//关闭数据连接套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	close(fd);
	
	//传输完毕 发送226
	if (flag == 0 && !sess->abor_received)
	{
		//226
		ftp_relply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	if (flag == 1)
	{
		//426
		ftp_relply(sess, FTP_TRANSFEROK, "Failure reading from local file");
	}
	else if (flag == 2)
	{
		//451
		ftp_relply(sess, FTP_BADSENDFILE, "Failure writting to network stream.");
	}
	
	check_abor(sess);
	
	/*重新开启控制连接闹钟*/
	start_cmdio_alarm();
}
/*上传文件 STOR 支持断点续传*/
static void  do_stor(session_t *sess)
{
	/*0 为非appe模式*/
	upload_common(sess, 0);
}
static void  do_appe(session_t *sess)
{
	/*1 为appe模式*/
	upload_common(sess, 1);
}
static void  do_list(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	//向客户端响应 150
	ftp_relply(sess, FTP_DATACONN, "Here comes the directory listing");
	//传输列表
	list_common(sess, 1);
	//关闭数据连接套接字
	close(sess->data_fd);
	//226
	ftp_relply(sess, FTP_TRANSFEROK, "Directory send OK");
}
static void  do_nlst(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	//向客户端响应 150
	ftp_relply(sess, FTP_DATACONN, "Here comes the directory listing");
	//传输列表
	list_common(sess, 0);
	//关闭数据连接套接字
	close(sess->data_fd);
	//226
	ftp_relply(sess, FTP_TRANSFEROK, "Directory send OK");	
}

static void  do_rest(session_t *sess)
{
	sess->restart_pos = str_tolonglong(sess->arg);
	char text[1024] = {0};
	
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_relply(sess, FTP_RESTOK, text);//350
}

static void  do_abor(session_t *sess)
{
	//225
	ftp_relply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR.");
}
static void  do_pwd(session_t *sess)
{
	/*实现1：
	struct passwd *pw = getpwuid(sess->uid);
	if (pw == NULL)
	{
		ftp_relply(sess, FTP_LOGINERR, "Login incorrect");
		return;		
	}
	ftp_relply(sess, FTP_PWDOK, pw->pw_dir);
	*/
	/*实现2*/
	char text[1024] ={0};
	char dir[1024] = {0};
	
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);  //需要转义
	
	ftp_relply(sess, FTP_PWDOK, text);
}
/*新建文件夹*/
static void  do_mkd(session_t *sess)
{
	//0777 & umask
	int ret = mkdir(sess->arg, 0777);
	if (ret < 0)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Create directory operation failed");//550
		return;
	}
	char text[200] = {0};
	/*判断是否绝对路径*/
	if (sess->arg[0] == '/')
	{
		sprintf(text, "\"%s\" created", sess->arg);
	}
	else
	{
		char dir[200] = {0};
		getcwd(dir, sizeof(dir));
		
		if (dir[strlen(dir)-1] == '/')
		{
			sprintf(text, "\"%s%s\" created", dir, sess->arg);
		}
		else
		{
			sprintf(text, "\"%s/%s\" created", dir, sess->arg);
		}
	}/*end else*/
	ftp_relply(sess, FTP_MKDIROK, text);	
}

/*删除空目录*/
static void  do_rmd(session_t *sess)
{
	const char *path = sess->arg;
	if (path == NULL)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Remove directory operation failed"); //550
		return;
	}
	int ret = rmdir(path);
	if (ret < 0)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Remove directory operation failed"); //550
		return;		
	}
	ftp_relply(sess, FTP_RMDIROK, "Remove directory operation successful.");//250	
}

/*删除文件*/
static void  do_dele(session_t *sess)
{
	const char *path = sess->arg;
	if (path == NULL)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Delete operation failed."); //550
		return;
	}
	int ret = unlink(path);
	if (ret < 0)
	{
		ftp_relply(sess, FTP_FILEFAIL, "Delete operation failed."); //550
		return;				
	}

	ftp_relply(sess, FTP_DELEOK, "Delete operation successful."); //250
}

static void  do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char *)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->arg) + 1);
	strcpy(sess->rnfr_name, sess->arg);
	
	ftp_relply(sess, FTP_RNFROK, "Ready for RNTO");
	
}
static void  do_rnto(session_t *sess)
{
	if (sess->rnfr_name == NULL)
	{
		ftp_relply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	
	int ret = rename(sess->rnfr_name, sess->arg);
	if (ret < 0)
	{
		ftp_relply(sess, FTP_BADPROT, "Rename directory operation failed");
		return;
	}
	ftp_relply(sess, FTP_RENAMEOK, "Rename successful.");
	
	if (sess->rnfr_name)
	{
		free(sess->rnfr_name);
		sess->rnfr_name = NULL;
	}
}
static void  do_site(session_t *sess)
{
	
}
static void  do_syst(session_t *sess)
{
	ftp_relply(sess, FTP_SYSTOK, "Unix Type: L8");
}
static void  do_feat(session_t *sess)
{
	ftp_lrelply(sess, FTP_FEAT, "Features:");
	
	ftp_frelply(sess, "EPRT");
	ftp_frelply(sess, "EPSV");
	ftp_frelply(sess, "MDTM");
	ftp_frelply(sess, "PASV");
	ftp_frelply(sess, "REST STREAM");
	ftp_frelply(sess, "SIZE");
	ftp_frelply(sess, "TVFS");
	ftp_frelply(sess, "UTF8");
	
	ftp_relply(sess, FTP_FEAT, "End");
/*
 211-Features:
  EPRT
  EPSV
  MDTM
  PASV
  REST STREAM
  SIZE
  TVFS
  UTF8
 211 End
*/	

}
/*获取文件大小*/
static void  do_size(session_t *sess)
{
	const char *path = sess->arg;
	struct stat buf;
	memset(&buf, 0, sizeof(buf));
	
	int ret = stat(path, &buf);
	if (ret < 0)
	{
		printf("hello\n");
		ftp_relply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	/*如果不是普通文件则返回错误*/
	if (!S_ISREG(buf.st_mode))
	{
		printf("hello world\n");
		ftp_relply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	
	char text[1024] = {0};
	sprintf(text, "%ld", buf.st_size);
	ftp_relply(sess, FTP_STATFILE_OK, text);
}

static void  do_stat(session_t *sess)
{
	if (sess->arg)
	{
		ftp_lrelply(sess, FTP_STATFILE_OK, "Status follows:");
	
		//发送信息
		char buf[1024] = {0};
		struct stat sbuf;
		memset(&sbuf, 0, sizeof(sbuf));
		
		file_stat(sess->arg, buf, &sbuf);
		writen(sess->ctrl_fd, buf, strlen(buf));
		
		
		ftp_relply(sess, FTP_STATFILE_OK, "End of status");
	
	}
	char text[1024] = {0};
	
	ftp_lrelply(sess, FTP_STATOK, "FTP server status:");
	
	//连接ip
	char *ip = get_sock_addr(sess->ctrl_fd);
	sprintf(text,
		"Connected to %s",
		ip
		);
	ftp_frelply(sess, text);	
	
	//登入用户
	struct passwd *pw = getpwuid(sess->uid);
	memset(text, 0, sizeof(text));
	sprintf(text,
		"Logged in as %s",
		pw->pw_name
		);
	ftp_frelply(sess, text);
	
	//ascii ?
	if (sess->is_ascii)
	{
		ftp_frelply(sess, "TYPE: ASCII");
	}
	else
	{
		ftp_frelply(sess, "TYPE: BINARY");
	}
	//上传下载速率
	if (sess->bw_download_rate_max >0)
	{
		memset(text, 0, sizeof(text));
		sprintf(text,
			"session download limit in byte/s is %u",
			sess->bw_download_rate_max
			);
		ftp_frelply(sess, text);
	}
	if (sess->bw_upload_rate_max > 0)
	{
		memset(text, 0, sizeof(text));
		sprintf(text,
			"session upload limit in byte/s is %u",
			sess->bw_upload_rate_max
			);
		ftp_frelply(sess, text);		
	}
	// session_timeout
	if (tunable_idle_session_timeout > 0)
	{
		memset(text, 0, sizeof(text));
		sprintf(text,
			"Session timeout in seconds is %u",
			tunable_idle_session_timeout
			);
		ftp_frelply(sess, text);			
	}
	
	ftp_frelply(sess, "Control connection is plain text");
	ftp_frelply(sess, "Data connections will be plain text");
	
	memset(text, 0, sizeof(text));
	sprintf(text,
		"At session startup, client count was %d",
		sess->num_clients
		);	
	ftp_frelply(sess, text);
	
	ftp_frelply(sess, "Tinyftp 1.0 - secure, fast, stable");

	ftp_relply(sess, FTP_STATOK, "End of status");

}
static void  do_noop(session_t *sess)
{
	//FTP_NOOPOK 200
	ftp_relply(sess, FTP_NOOPOK, "NOOP ok");
}

static void  do_help(session_t *sess)
{
	ftp_lrelply(sess, FTP_HELP, "The following commands are recognized.");
	
	ftp_frelply(sess, "ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD");
	ftp_frelply(sess, "MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR");
	ftp_frelply(sess, "RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD");
	ftp_frelply(sess, "XPWD XRMD");
	
	ftp_relply(sess, FTP_HELP, "Help OK.");
}
