#include "sckutil.h"


int getlocalip(char *ip)
{
	char host[100] = {0};
	if (gethostname(host, sizeof(host)) < 0)
	{
		return -1;
	}
	struct hostent *hp;
	if ((hp = gethostbyname(host)) == NULL)
	{
		return -1;
	}
	strcpy(ip, inet_ntoa(*(struct in_addr*)hp->h_addr));
	
	return 0;
}

/*获取socket_ip地址 */
char*  get_sock_addr(int sockfd)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	char *ip = NULL;
	
	int ret = getpeername(sockfd, (struct sockaddr*)&addr, &len);
	if (ret == -1)
	{
		ERR_EXIT("get_sock_addr");
	}
	ip = (char*)malloc(32);
	
	inet_ntop(AF_INET, (void*)&(addr.sin_addr), ip, INET_ADDRSTRLEN);
	
	return ip;
}

int tcp_client(const char *address, unsigned short port)
{
	int sock;
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		ERR_EXIT("tcp_client");
	}

	if (port > 0)
	{
		struct sockaddr_in localaddr;
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(port);
		inet_pton(AF_INET, address, &localaddr.sin_addr);		
		
		int on = 1;
		int ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (ret < 0)
		{
			ret = errno;
			ERR_EXIT("setsockopt");
		}
		ret = bind(sock, (struct sockaddr*) &localaddr, sizeof(localaddr));
		if (ret < 0)
		{
			ret = errno;
			ERR_EXIT("bind");
		}		
	}
	
	return sock;
}

/* read函数的调用方法
int ret;
ret = read_timeout(fd, 5);
if (ret == 0)
{
	read(fd, ...);
}
else if (ret == -1 && errno == ETIMEDOUT)
{
	timeout....
}
else
{
	ERR_EXIT("read_timeout");
}
*/

/**
 * read_timeout - 读超时检测函数，不含读操作
 * @fd: 文件描述符
 * @wait_seconds: 等待超时秒数，如果为0表示不检测超时
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
//客户端端接受报文
/*
 * 函数名：read_timeout
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int read_timeout(int fd, unsigned int wait_seconds)
{
	int ret = 0;
	if (wait_seconds > 0)
	{
		fd_set read_fdset;
		struct timeval timeout;

		FD_ZERO(&read_fdset);
		FD_SET(fd, &read_fdset);

		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;

		//select返回值三态
		//1 若timeout时间到（超时），没有检测到读事件 ret返回=0
		//2 若ret返回<0 &&  errno == EINTR 说明select的过程中被别的信号中断（可中断睡眠原理）
		//2-1 若返回-1，select出错
		//3 若ret返回值>0 表示有read事件发生，返回事件发生的个数

		do
		{
			ret = select(fd + 1, &read_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		if (ret == 0)
		{
			ret = -1;
			errno = ETIMEDOUT;
		} else if (ret == 1)
			ret = 0;
	}

	return ret;
}

/**
 * write_timeout - 写超时检测函数，不含写操作
 * @fd: 文件描述符
 * @wait_seconds: 等待超时秒数，如果为0表示不检测超时
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
/*
 * 函数名：write_timeout
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int write_timeout(int fd, unsigned int wait_seconds)
{
	int ret = 0;
	if (wait_seconds > 0)
	{
		fd_set write_fdset;
		struct timeval timeout;

		FD_ZERO(&write_fdset);
		FD_SET(fd, &write_fdset);

		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do
		{
			ret = select(fd + 1, NULL, &write_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		if (ret == 0)
		{
			ret = -1;
			errno = ETIMEDOUT;
		} else if (ret == 1)
			ret = 0;
	}

	return ret;
}

/**
 * accept_timeout - 带超时的accept
 * @fd: 套接字
 * @addr: 输出参数，返回对方地址
 * @wait_seconds: 等待超时秒数，如果为0表示正常模式
 * 成功（未超时）返回已连接套接字，超时返回-1并且errno = ETIMEDOUT
 */
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	if (wait_seconds > 0)
	{
		fd_set accept_fdset;
		struct timeval timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(fd, &accept_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do
		{
			ret = select(fd + 1, &accept_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret == -1)
			return -1;
		else if (ret == 0)
		{
			errno = ETIMEDOUT;
			return -1;
		}
	}

	//一但检测出 有select事件发生，表示对等方完成了三次握手，客户端有新连接建立
	//此时再调用accept将不会堵塞
	if (addr != NULL)
		ret = accept(fd, (struct sockaddr*) addr, &addrlen); //返回已连接套接字
	else
		ret = accept(fd, NULL, NULL);
	if (ret == -1)
	{
		ret = errno;
		printf("func accept() err:%d \n", ret);
		return ret;
	}

	return ret;
}

/**
 * activate_noblock - 设置I/O为非阻塞模式
 * @fd: 文件描符符
 */
/*
 * 函数名：activate_nonblock
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int activate_nonblock(int fd)
{
	int ret = 0;
	/*
	 * int fcntl(int fd, int cmd, ... \* arg \*)
	 获取文件或者修改文件状态
	 F_GETLK 取得文件锁定的状态。
	 返回值 成功则返回0，若有错误则返回-1，错误原因存于errno.
	 */
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
	{
		ret = flags;
		printf("func activate_nonblock() err:%d", ret);
		return ret;
	}
	/*
	 *  按位或，加上没有锁的状态
	 * */
	flags |= O_NONBLOCK;
	/*
	 * . F_SETFL ：设置文件状态标志。
	 其中O_RDONLY， O_WRONLY， O_RDWR， O_CREAT， O_EXCL， O_NOCTTY 和 O_TRUNC不受影响，
	 可以更改的标志有 O_APPEND，O_ASYNC， O_DIRECT， O_NOATIME 和 O_NONBLOCK。
	 * */
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
	{
		printf("func activate_nonblock() err:%d", ret);
		return ret;
	}
	return ret;
}


/**
 * deactivate_nonblock - 设置I/O为阻塞模式
 * @fd: 文件描符符
 */

int deactivate_nonblock(int fd)
{
	int ret = 0;
	/*
	 * int fcntl(int fd, int cmd, ... \* arg \*)
	 获取文件或者修改文件状态
	 F_GETLK 取得文件锁定的状态。
	 返回值 成功则返回0，若有错误则返回-1，错误原因存于errno.
	 */
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
	{
		ret = flags;
		printf("func deactivate_nonblock() err:%d", ret);
		return ret;
	}

	/*
	 * 按位与， NONBLOCK的按位反 并上状态
	 * */
	flags &= ~O_NONBLOCK;
	/*
	 * . F_SETFL ：设置文件状态标志。
	 其中O_RDONLY， O_WRONLY， O_RDWR， O_CREAT， O_EXCL， O_NOCTTY 和 O_TRUNC不受影响，
	 可以更改的标志有 O_APPEND，O_ASYNC， O_DIRECT， O_NOATIME 和 O_NONBLOCK。
	 * */
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
	{
		printf("func deactivate_nonblock() err:%d", ret);
		return ret;
	}
	return ret;
}


/**
 * connect_timeout - connect
 * @fd: 套接字
 * @addr: 要连接的对方地址
 * @wait_seconds: 等待超时秒数，如果为0表示正常模式
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
/*
 *
 *struct sockaddr_in {
 *	 sa_family_t    sin_family; // address family: AF_INET
 *	 in_port_t      sin_port;   // port in network byte order
 *	 struct in_addr sin_addr;   // internet address
 *};
 * */

/*
 * 函数名：connect_timeout
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int connect_timeout(int fd, struct sockaddr_in *addr,
		unsigned int wait_seconds)
{
	int ret;
	//获取socket结构体的大小。
	socklen_t addrlen = sizeof(struct sockaddr_in);
	//如果传入的等待时间大于0就取消socket的阻塞状态，0则不执行。
	if (wait_seconds > 0)
		activate_nonblock(fd);
	//链接
	/*
	 * int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
	 *
	 * */
	ret = connect(fd, (struct sockaddr*) addr, addrlen);
	//EINPROGRESS 正在处理
	if (ret < 0 && errno == EINPROGRESS)
	{
		/*
		 * void FD_CLR(int fd, fd_set *set);
		 * int  FD_ISSET(int fd, fd_set *set);
		 * void FD_SET(int fd, fd_set *set);
		 * void FD_ZERO(fd_set *set);
		 * */
		//设置监听集合
		fd_set connect_fdset;
		struct timeval timeout;
		//初始化集合
		FD_ZERO(&connect_fdset);
		//把fd 文件描述符的socket加入监听集合
		FD_SET(fd, &connect_fdset);
		/*
		 * struct timeval {
		 *     long    tv_sec;         // seconds       秒
		 *     long    tv_usec;        // microseconds  微妙
		 *     };
		 * */
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do
		{
			// 一但连接建立，则套接字就可写  所以connect_fdset放在了写集合中
			ret = select(fd + 1, NULL, &connect_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret == 0)
		{
			ret = -1;
			/*
			 * #define ETIMEDOUT       110     // Connection timed out
             *  Tcp是面向连接的。在程序中表现为，当tcp检测到对端socket不再可
             *  用时(不能发出探测包，或探测包没有收到ACK的响应包)，select会
             *  返回socket可读，并且在recv时返回-1，同时置上errno为ETIMEDOUT。
			 * */
			errno = ETIMEDOUT;
		} else if (ret < 0)
			return -1;
		else if (ret == 1)
		{
			//printf("22222222222222222\n");
			/* ret返回为1（表示套接字可写），可能有两种情况，一种是连接建立成功，一种是套接字产生错误，*/
			/* 此时错误信息不会保存至errno变量中，因此，需要调用getsockopt来获取。 */
			int err;
			socklen_t socklen = sizeof(err);
			//获取socket的状态
			int sockoptret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err,
					&socklen);
			if (sockoptret == -1)
			{
				return -1;
			}
			if (err == 0)
			{
				ret = 0;
			} else
			{
				errno = err;
				ret = -1;
			}
		}
	}
	if (wait_seconds > 0)
	{
		deactivate_nonblock(fd);
	}
	return ret;
}

/**
 * readn - 读取固定字节数
 * @fd: 文件描述符
 * @buf: 接收缓冲区
 * @count: 要读取的字节数
 * 成功返回count，失败返回-1，读到EOF返回<count
 */
//ssize_t 在x64下为long  在x86下为int
/*
 * 函数名：readn
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
 
ssize_t readn(int fd, void *buf, size_t count)
{
	//size_t 在x64下为 unsigned long 类型， 在x86下为 unsigned int 类型
	size_t nleft = count; //将count接过来 ，个数
	ssize_t nread;
	char *bufp = (char*) buf; //将空指针类型转换为char类型指针。
	while (nleft > 0)
	{
		/*ssize_t read(int fd, void *buf, size_t count);
		 * 从文件描述符fd中读取count字节存到buf中
		 * 返回读取字节数的个数。
		 * */
		if ((nread = read(fd, bufp, nleft)) < 0)
		{
			/*
			 * 如果是被信号中断的继续读
			 * */
			if (errno == EINTR)
				continue;
			return -1;
		}
		/*
		 * 如果输入的读取个数为0，那么返回的读取个数为0
		 * 不执行任何操作。
		 * nleft为剩余的需要读取的字节个数。
		 * 如果为0，说明读到文件尾，
		 *
		 * */
		else if (nread == 0)
			return count - nleft;
		bufp += nread; //将字符指针向前推进已成功读取字符数的大小单位。
		nleft -= nread; //剩余的个数减去已经成功读取的字节数。
	}
	return count;
}

/**
 * writen - 发送固定字节数
 * @fd: 文件描述符
 * @buf: 发送缓冲区
 * @count: 要读取的字节数
 * 成功返回count，失败返回-1
 */
/*
 * 函数名：writen
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
ssize_t writen(int fd, const void *buf, size_t count)
{
	size_t nleft = count; //剩余的需要写入的字节数。
	ssize_t nwritten; //成功写入的字节数。
	char *bufp = (char*) buf; //将缓冲的指针强制转换为字符类型的指针。
	/*
	 * 如果剩余需要写入的字节数大于0则继续
	 * */
	while (nleft > 0)
	{
		/*
		 * ssize_t write(int fd, const void *buf, size_t count);
		 * fd为需要写入的文件描述符，buf为字符缓存区，count为需要写入的字节数。
		 *
		 * */
		if ((nwritten = write(fd, bufp, nleft)) < 0)
		{
			/*
			 * 如果是被信号中断的继续读
			 * */
			if (errno == EINTR)
				continue;
			return -1;
		} else if (nwritten == 0)
			continue;
		//字符指针推移已经写入成功大小的字节数。
		bufp += nwritten;
		//剩余的字节数。
		nleft -= nwritten;
	}
	return count;
}

/**
 * recv_peek - 仅仅查看套接字缓冲区数据，但不移除数据
 * @sockfd: 套接字
 * @buf: 接收缓冲区
 * @len: 长度
 * 成功返回>=0，失败返回-1
 */
/*
 * 函数名：recv_peek
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
ssize_t recv_peek(int sockfd, void *buf, size_t len)
{
	while (1)
	{
		/*
		 * ssize_t recv(int sockfd, void *buf, size_t len, int flags);
		 * sockfd 套接字
		 * len 需要读取的长度
		 * MSG_PEEK只从队列中查看，但不取出。
		 * 返回接受到的字节的长度，失败返回-1，接受到关闭信号返回0；
		 * */
		int ret = recv(sockfd, buf, len, MSG_PEEK);
		/*
		 * 如果被信号中断了，继续
		 * */
		if (ret == -1 && errno == EINTR)
			continue;
		return ret;
	}
}

/**
 * readline - 按行读取数据
 * @sockfd: 套接字
 * @buf: 接收缓冲区
 * @maxline: 每行最大长度
 * 成功返回>=0，失败返回-1
 */
ssize_t readline(int sockfd, void *buf, size_t maxline)
{
	int ret;
	int nread;
	char *bufp = buf;
	int nleft = maxline;
	while (1)
	{
		ret = recv_peek(sockfd, bufp, nleft);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			return ret;

		nread = ret;
		int i;
		for (i=0; i<nread; i++)
		{
			if (bufp[i] == '\n')
			{
				ret = readn(sockfd, bufp, i+1);
				if (ret != i+1)
					exit(EXIT_FAILURE);

				return ret;
			}
		}

		if (nread > nleft)
			exit(EXIT_FAILURE);

		nleft -= nread;
		ret = readn(sockfd, bufp, nread);
		if (ret != nread)
			exit(EXIT_FAILURE);

		bufp += nread;
	}

	return -1;
}

void send_fd(int sock_fd, int fd_to_send)
{
	int ret = 0;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd_to_send))];
	int *p_fds;
	char sendchar  =0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd_to_send));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd_to_send;
	
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	
	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
	{
		ERR_EXIT("sendmsg");
	}
}

int recv_fd(const int sock_fd)
{
	int ret = 0;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;
	
	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
	{
		ERR_EXIT("recvmsg");
	}
	
	p_cmsg= CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
	{
		ERR_EXIT("no passed fd");
	}
	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
	{
		ERR_EXIT("no passed fd");
	}
	
	return recv_fd;
}

/*获取权限位信息*/
const char* statbuf_get_perms(struct stat *sbuf)
{
		static char perms[] = "----------"; /*10位权限位*/
		perms[0] = '?';
		
		/*获取文件类型*/
		mode_t mode = sbuf->st_mode;
		switch (mode & S_IFMT)
		{
		case S_IFREG:
			perms[0] = '-';
			break;
		case S_IFDIR:
			perms[0] = 'd';
			break;
		case S_IFLNK:
			perms[0] = 'l';
			break;
		case S_IFIFO:
			perms[0] = 'p';
			break;
		case S_IFSOCK:
			perms[0] = 's';
			break;
		case S_IFCHR:
			perms[0] = 'c';
			break;
		case S_IFBLK:
			perms[0] = 'b';
			break;	
			
		}/*end switch*/
		/*文件所有者权限 owner*/
		if (mode & S_IRUSR)
		{
			perms[1] = 'r';
		}
		if (mode & S_IWUSR)
		{
			perms[2] = 'w';
		}
		if (mode & S_IXUSR)
		{
			perms[3] = 'x';
		}
		/*所在组成员权限 group*/
		if (mode & S_IRGRP)
		{
			perms[4] = 'r';
		}
		if (mode & S_IWGRP)
		{
			perms[5] = 'w';
		}
		if (mode & S_IXGRP)
		{
			perms[6] = 'x';
		}	
		/*其他访问者权限 other*/
		if (mode & S_IROTH)
		{
			perms[7] = 'r';
		}
		if (mode & S_IWOTH)
		{
			perms[8] = 'w';
		}
		if (mode & S_IXOTH)
		{
			perms[9] = 'x';
		}	
		/*特殊权限*/
		if (mode & S_ISUID)
		{
			perms[3] = (perms[3] == 'x') ? 's' : 'S';
		}
		if (mode & S_ISGID)
		{
			perms[6] = (perms[6] == 'x') ? 's' : 'S';		
		}
		if (mode & S_ISVTX)
		{
			perms[9] = (perms[9] == 'x') ? 't' : 'T';		
		}
		
		return perms;
}

const char* statbuf_get_date(struct stat *sbuf)
{
	static char datebuf[64] = {0};
	/*时间格式化*/
	const char *p_data_fomat = "%b %e %H:%M";
	struct timeval tv;	
	int ret = gettimeofday(&tv, NULL);
	if (ret == -1)
	{
		ERR_EXIT("gettimeofday");
	}
	
	time_t local_time = tv.tv_sec;
	if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 182*24*60*60)
	{
		p_data_fomat = "%b %e %Y";
	}
	
	
	/*将秒转换为结构体*/
	struct tm *p_tm = localtime(&local_time);
	/*将tm转为指定格式的字符串*/
	strftime(datebuf, sizeof(datebuf), p_data_fomat, p_tm);	
	
	return datebuf;
}

int lock_internal(int fd, int lock_type)
{
	int ret = 0;
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	
	the_lock.l_type = lock_type;/*锁类型*/
	the_lock.l_whence = SEEK_SET; /*加锁位置*/
	the_lock.l_start = 0;/*加锁偏移位置*/
	the_lock.l_len = 0;
	
	/*防止信号中断*/
	do  
	{
		ret = fcntl(fd, F_SETLKW, &the_lock);
	}
	while (ret < 0 && errno == EINTR);
	
	return ret;	
}

//读锁
int lock_file_read(int fd)
{
	return lock_internal(fd, F_RDLCK);
}
//写锁
int lock_file_write(int fd)
{
	return lock_internal(fd, F_WRLCK);
}
//解锁
int unlock_file(int fd)
{
	int ret = 0;
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	
	the_lock.l_type = F_UNLCK;/*锁类型 解锁*/
	the_lock.l_whence = SEEK_SET; /*加锁位置*/
	the_lock.l_start = 0;/*加锁偏移位置*/
	the_lock.l_len = 0;
	
	/*非阻塞模式*/
	ret = fcntl(fd, F_SETLK, &the_lock);

	return ret;	
}

static struct timeval s_curr_time;
long get_time_sec()
{
	int ret = gettimeofday(&s_curr_time, NULL);
	if (ret < 0)
	{
		ERR_EXIT("gettimeofday");
	}
	return s_curr_time.tv_sec;
	
}

long get_time_usec()
{
	return s_curr_time.tv_usec;	
}

/*睡眠规定时间*/
void nano_sleep(double seconds)
{
	time_t secs = (time_t)seconds;//整数部分
	double fractional = seconds - (double)secs;//小数部分
	
	struct timespec ts;
	ts.tv_sec = secs;
	ts.tv_nsec = (long)(fractional*(double)1000000000); //纳秒 9个0
	
	int ret;
	do
	{
		ret = nanosleep(&ts, &ts);
	}
	while (ret == -1 && ret == EINTR);
}

//开启fd接收带外数据
void activate_oobinline(int fd)
{
	int oob_inline = 1;
	int ret;
	ret = setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &oob_inline, sizeof(oob_inline));
	if (ret == -1)
	{
		ERR_EXIT("setsockopt");
	}
}

/*开启接收SIGURG（当fd有带外数据是，将产生SIGURG信号*/
/*该函数设定当前进程能够接收fd所产生的SIGURG信号*/
void activate_sigurg(int fd)
{
	int ret = 0;
	ret = fcntl(fd, F_SETOWN, getpid());
	if (ret == -1)
	{
		ERR_EXIT("fcntl");
	}
}