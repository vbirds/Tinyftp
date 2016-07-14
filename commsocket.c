#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "commsocket.h"
#include "sckutil.h"

typedef struct _SckHandle
{
	//int sockArray[100]; //定义socket池数组
	int arrayNum; //数组大小
	int sockfd; //socket句柄
	int contime; //链接超时时间
	int sendtime; //发送超时时间
	int revtime; //接受超时时间
} SckHandle;







//函数声明
//客户端环境初始化
/*
 * handle 在函数内部分配内存，socket结构体
 * contime 链接超时时间
 * sendtime 发送超时时间
 * revtime 接受超时时间
 * nConNum 链接池的数目
 * */
/*
 * 函数名：sckCliet_init
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int sckCliet_init(void **handle, int contime, int sendtime, int revtime,
		int nConNum)
{
	int ret = 0;
	//判断传入的参数
	if (handle == NULL || contime < 0 || sendtime < 0 || revtime < 0)
	{
		ret = Sck_ErrParam; //赋值预先定义的错误。
		printf(
				"func sckCliet_init() err: %d, check  (handle == NULL ||contime<0 || sendtime<0 || revtime<0)\n",
				ret);
		return ret;
	}
	//定义结构体
	SckHandle *tmp = (SckHandle *) malloc(sizeof(SckHandle));
	if (tmp == NULL)
	{
		ret = Sck_ErrMalloc;
		printf("func sckCliet_init() err: malloc %d\n", ret);
		return ret;
	}

	tmp->contime = contime;
	tmp->sendtime = sendtime;
	tmp->revtime = revtime;
	tmp->arrayNum = nConNum;
	tmp->sockfd = -1;
	*handle = tmp;
	return ret;
}





/*
 * 函数名：sckCliet_getconn
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int sckCliet_getconn(void *handle, char *ip, int port, int *connfd)
{

	int ret = 0;
	SckHandle *tmp = NULL;
	if (handle == NULL || ip == NULL || connfd == NULL || port < 0
			|| port > 65537)
	{
		ret = Sck_ErrParam;
		printf(
				"func sckCliet_getconn() err: %d, check  (handle == NULL || ip==NULL || connfd==NULL || port<0 || port>65537) \n",
				ret);
		return ret;
	}

	//
	int sockfd;
	sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockfd < 0)
	{
		ret = errno;
		printf("func socket() err:  %d\n", ret);
		return ret;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	servaddr.sin_addr.s_addr = inet_addr(ip);

	tmp = (SckHandle*) handle;

	/*
	 ret = connect(sockfd, (struct sockaddr*) (&servaddr), sizeof(servaddr));
	 if (ret < 0)
	 {
	 ret = errno;
	 printf("func connect() err:  %d\n", ret);
	 return ret;
	 }
	 */

	ret = connect_timeout(sockfd, (struct sockaddr_in*) (&servaddr),
			(unsigned int) tmp->contime);
	if (ret < 0)
	{
		if (ret == -1 && errno == ETIMEDOUT)
		{
			ret = Sck_ErrTimeOut;
			return ret;
		} else
		{
			printf("func connect_timeout() err:  %d\n", ret);
		}
	}

	*connfd = sockfd;

	return ret;

}



//客户端发送报文
/*
 * 函数名：sckClient_send
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int sckClient_send(void *handle, int connfd, unsigned char *data, int datalen)
{
	int ret = 0;

	SckHandle *tmp = NULL;
	tmp = (SckHandle *) handle;
	ret = write_timeout(connfd, tmp->sendtime);
	if (ret == 0)
	{
		int writed = 0;
		unsigned char *netdata = (unsigned char *)malloc(sizeof(unsigned char)*(datalen +4));		
		if (netdata == NULL)
		{
			ret = Sck_ErrMalloc;
			printf("func sckClient_send() mlloc Err:%d\n ", ret);
			return ret;
		}
		
		int netlen = htonl(datalen);
		memcpy(netdata, &netlen, 4);
		memcpy(netdata + 4, data, datalen);

		writed = writen(connfd, netdata, datalen + 4);
		if (writed < (datalen + 4))
		{	
			if (netdata != NULL)
			{
				free(netdata);
				netdata = NULL;
			}
			
			return writed;
		}

	}

	if (ret < 0)
	{
		//失败返回-1，超时返回-1并且errno = ETIMEDOUT
		if (ret == -1 && errno == ETIMEDOUT)
		{
			ret = Sck_ErrTimeOut;
			printf("func sckClient_send() mlloc Err:%d\n ", ret);
			return ret;
		}
		return ret;
	}

	return ret;
}



//客户端端接受报文
/*
 * 函数名：sckClient_rev
 * 描述：客服端接受数据
 * 参数：
 *
 * 返回：
 * */
int sckClient_rev(void *handle, int connfd, unsigned char *out, int *outlen)
{

	int ret = 0;
	SckHandle *tmpHandle = (SckHandle *) handle;

	if (handle == NULL || out == NULL)
	{
		ret = Sck_ErrParam;
		printf("func sckClient_rev() timeout , err:%d \n", Sck_ErrTimeOut);
		return ret;
	}

	ret = read_timeout(connfd, tmpHandle->revtime); //bugs modify bombing
	if (ret != 0)
	{
		if (ret == -1 || errno == ETIMEDOUT)
		{
			ret = Sck_ErrTimeOut;
			printf("func sckClient_rev() timeout , err:%d \n", Sck_ErrTimeOut);
			return ret;
		} else
		{
			printf("func sckClient_rev() timeout , err:%d \n", Sck_ErrTimeOut);
			return ret;
		}
	}

	int netdatalen = 0;
	ret = readn(connfd, &netdatalen, 4); //读包头 4个字节
	if (ret == -1)
	{
		printf("func readn() err:%d \n", ret);
		return ret;
	} else if (ret < 4)
	{
		ret = Sck_ErrPeerClosed;
		printf("func readn() err peer closed:%d \n", ret);
		return ret;
	}

	int n;
	n = ntohl(netdatalen);
	ret = readn(connfd, out, n); //根据长度读数据
	if (ret == -1)
	{
		printf("func readn() err:%d \n", ret);
		return ret;
	} else if (ret < n)
	{
		ret = Sck_ErrPeerClosed;
		printf("func readn() err peer closed:%d \n", ret);
		return ret;
	}

	*outlen = n;

	return 0;
}

// 客户端环境释放 
int sckClient_destroy(void *handle)
{
	if (handle != NULL)
	{
		SckHandle *tmp = (SckHandle*)handle;
		if (tmp->sockfd != -1)
		{
			close(tmp->sockfd);
			tmp = NULL;
		}
		free(handle);
	}
	return 0;
}

int sckCliet_closeconn(int *connfd)
{
	if (*connfd >= 0)
	{
		close(*connfd);
	}
	return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
//函数声明
//服务器端初始化
/*
 * 函数名：sckServer_init
 * 描述：服务器端的socket初始化
 * 参数：address  ip地址
		 port 绑定的端口
 *       listenfd 监听的socket文件
 * 返回：如果成功返回0 ，失败返回<0 或者 成功发送的数据的字节大小。
 * */
int sckServer_init(const char *address, int port, int *listenfd)
{
	int ret = 0;
	int mylistenfd;
	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);
	
	if (address == NULL)
	{
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	inet_pton(AF_INET, address, &servaddr.sin_addr);
	//servaddr.sin_addr.s_addr = htonl(address);
	
    //返回一个新的socket描述符
	mylistenfd = socket(PF_INET, SOCK_STREAM, 0);
	if (mylistenfd < 0)
	{
		ret = errno;
		printf("func socket() err:%d \n", ret);
		return ret;
	}

	int on = 1;
	ret = setsockopt(mylistenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (ret < 0)
	{
		ret = errno;
		printf("func setsockopt() err:%d \n", ret);
		return ret;
	}

	ret = bind(mylistenfd, (struct sockaddr*) &servaddr, sizeof(servaddr));
	if (ret < 0)
	{
		ret = errno;
		printf("func bind() err:%d \n", ret);
		return ret;
	}

	ret = listen(mylistenfd, SOMAXCONN);
	if (ret < 0)
	{
		ret = errno;
		printf("func listen() err:%d \n", ret);
		return ret;
	}

	*listenfd = mylistenfd;

	return 0;
}


/*
 * 函数名：sckServer_accept
 * 描述：服务器端等待数据
 * 参数： listenfd 监听的sock
 * 	     timeout 定义的超时时间
 * 返回：如果成功返回0 ，失败返回<0 或者 成功发送的数据的字节大小。
 * */

int sckServer_accept(int listenfd, int *connfd, void *addr, int timeout)
{
	int ret = 0;
	struct sockaddr_in *p_addr = NULL;
	if (addr != NULL)
	{
		p_addr = (struct sockaddr_in*)addr;
	}
	 
    //
	ret = accept_timeout(listenfd, p_addr, (unsigned int) timeout);
	if (ret < 0)
	{
		if (ret == -1 && errno == ETIMEDOUT)
		{
			ret = Sck_ErrTimeOut;
			printf("func accept_timeout() timeout err:%d \n", ret);
			return ret;
		} else
		{
			ret = errno;
			printf("func accept_timeout() err:%d \n", ret);
			return ret;
		}
	}

	*connfd = ret;
	return 0;
}
//服务器端发送报文
/*
 * 函数名：sckServer_send
 * 描述：发送报文，并进行了粘包处理。
 * 参数： connfd 链接的socket描述符
 * 	     data 发送的数据  ，传入数据，在内部重新打包封装。
 * 	     datalen 要发送的数据的长度
 * 	     timeout 定义的超时时间
 * 返回：如果成功返回0 ，失败返回<0 或者 成功发送的数据的字节大小。
 * */
int sckServer_send(int connfd, unsigned char *data, int datalen, int timeout)
{
	int ret = 0;
    //写时超时检测
	ret = write_timeout(connfd, timeout);
	if (ret == 0)
	{
		int writed = 0;
		//分配内存空间
		unsigned char *netdata = (unsigned char *)malloc(sizeof(unsigned char)*(datalen +4));
		if (netdata == NULL)
		{
			ret = Sck_ErrMalloc;
			printf("func sckServer_send() mlloc Err:%d\n ", ret);
			return ret;
		}
		//将本地数据转换为网络数据  ;小端===》大端
		int netlen = htonl(datalen);
		//将数据的长度加到数据包的头4字节处
		memcpy(netdata, &netlen, 4);
		//将数据打包到新的数据包中。
		memcpy(netdata + 4, data, datalen);
        //发送数据
		//writed为成功发送的数据的字节长度。
		writed = writen(connfd, netdata, datalen + 4);
		//直到数据分包 封装 发送完成之后，返回
		if (writed < (datalen + 4))
		{
			//释放内存
			if (netdata != NULL)
			{
				free(netdata);
				netdata = NULL;
			}
			return writed;
		}

	}
    //检测超时
	if (ret < 0)
	{
		//失败返回-1，超时返回-1并且errno = ETIMEDOUT
		//链接超时
		if (ret == -1 && errno == ETIMEDOUT)
		{
			ret = Sck_ErrTimeOut;
			printf("func sckServer_send() mlloc Err:%d\n ", ret);
			return ret;
		}
		return ret;
	}

	return ret;
}
//服务器端端接受报文
/*
 * 函数名：sckServer_rev
 * 描述：接受报文，并进行了粘包处理。
 * 参数： connfd 链接的socket描述符
 * 	     out 读取的内容，在外部分配内存
 * 	     outlen 读取到内容的长度。
 * 	     timeout 定义的超时时间
 * 返回：如果成功返回0 ，失败返回<0 或者错误码。
 * */
int sckServer_rev(int connfd, unsigned char *out, int *outlen, int timeout)
{

	int ret = 0;
    //检测传入的参数是否是有效的参数。
	if (out == NULL || outlen == NULL)
	{
		ret = Sck_ErrParam;
		printf("func sckClient_rev() timeout , err:%d \n", Sck_ErrTimeOut);
		return ret;
	}
    //检测是否可读，防止阻塞假死，一个链接的等待时间是1.5倍的RTT 一个RTT 75秒
	ret = read_timeout(connfd, timeout); //bugs modify bombing
	if (ret != 0)
	{
		if (ret == -1 || errno == ETIMEDOUT)
		{
			ret = Sck_ErrTimeOut;
			printf("func sckClient_rev() timeout , err:%d \n", Sck_ErrTimeOut);
			return ret;
		} else
		{
			printf("func sckClient_rev() timeout , err:%d \n", Sck_ErrTimeOut);
			return ret;
		}
	}
	/*
	 * 防止粘包
	 * */

    //定义收取的数据的长度，以用来获取收取数据的长度，初始化为0；
	//通过调用readn返回数据的长度
	int netdatalen = 0;
	ret = readn(connfd, &netdatalen, 4); //读包头 4个字节
	if (ret == -1)
	{
		printf("func readn() err:%d \n", ret);
		return ret;
	} else if (ret < 4)
	{
		ret = Sck_ErrPeerClosed;
		printf("func readn() err peer closed:%d \n", ret);
		return ret;
	}
	int n;
	//将网络数据转换为本地数据，大端===>小端
	n = ntohl(netdatalen);
	ret = readn(connfd, out, n); //根据长度读数据
	if (ret == -1)
	{
		printf("func readn() err:%d \n", ret);
		return ret;
	} else if (ret < n)
	{
		ret = Sck_ErrPeerClosed;
		printf("func readn() err peer closed:%d \n", ret);
		return ret;
	}
    //抛出需要读取的字节长度。
	*outlen = n;
	return 0;
}

//服务器端环境释放 
int sckServer_destroy(void *handle)
{
     if(handle!=NULL)
     {
    	 free(handle);
    	 handle=NULL;//没有起作用。
     }
	return 0;
}
