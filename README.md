## Tinyftpd
----------
[![CMake](https://github.com/vbirds/Tinyftp/actions/workflows/cmake.yml/badge.svg)](https://github.com/vbirds/Tinyftp/actions/workflows/cmake.yml)

### 概述
Tinyftpd是用c语言实现的简单、快速、高效的Linux FTP服务器，只需简单的配置，就可快速的将主机变成高效的FTP服务器。

### 模块简介
TinyFTP分为 字符串工具模块、参数配置模块、socket模块、内部进程间通讯模块、系统调用工具模块。

1. 字符串工具模块：字符串模块主要用来处理开发过程中，各种对字符串的处理。模块在`string.h` 与 `string.c`
2. 参数配置模块：参数配置模块提供参数配置的功能。具体在`parseconf.h` 和 `parseconf.c` 
3. socket模块：用于socket通讯建立与数据传输。可见 `commonsock.h` `commonsock.c`
4. 内部进程间通讯模块：用于子进程 与 父进程间的通讯 与数据传输。`privsock.h` 和 `privsock.c`
5. 系统调用工具模块：主要是一些用到的系统调用的函数封装。可见`sckutil.h` `sckutil.c`

### 安装
#### 编译
```bash?linenums=NULL
cd build/
chmod +x bulid.sh
sudo ./build.sh
```
运行
```bash?linenums=NULL
cd /bin
sudo ./tinyftpd
```

### 配置
配置文件在当前目录的`tinyftpd.conf`

|       配置参数                |    说明        |
| ------------------------------| ---------------|
|tunable_pasv_enable 	        |是否开启被动模式|
|tunable_port_enable 	        |是否开启主动模式|
|tunable_max_clients 	        |最大连接数      |
|tunable_max_per_ip 	        |每IP最大连接数  |
|tunable_listen_port	        |FTP服务器端口   |
|tunable_accept_timeout 	    |accept超时间    |
|tunable_connect_timeout	    |connect超时间   |
|tunable_idle_session_timeout	|控制时间连接超时|
|tunable_data_connection_timeout|数据连接时间超时|
|tunable_local_umask	        |掩码            |
|tunable_upload_max_rate 	    |最大上传速度（byte/s）|
|tunable_download_max_rate 	    |最大下载速度（byte/s）|
|tunable_listen_address	        |FTP服务器IP地址 |

### LICENSE
软件遵循MIT开源协议
### 致谢
在开发过程中参考了vsftpd的源码，从中学到了许多知识，特此声明，表示感谢
