#include "parseconf.h"
#include "sckutil.h"
#include "tunable.h"
#include "stdio.h"
#include "string.h"
#include "str.h"
#include "ctype.h"

/*开关型配置项*/
static struct parseconf_bool_setting
{
	const char *p_setting_name;
	int *p_variable;
}
parseconf_bool_array[] =
{
	{ "pasv_enable", &tunable_pasv_enable },
	{ "port_enable", &tunable_port_enable },
	{ NULL, NULL }
};

/*整数参数配置项*/
static struct parseconf_unit_setting
{
	const char *p_setting_name;
	unsigned int *p_variable;
}
parseconf_uint_array[] = 
{
	{ "listen_port", &tunable_listen_port },
	{ "max_clients", &tunable_max_clients },
	{ "max_per_ip",  &tunable_max_per_ip },
	{ "accept_timeout", &tunable_accept_timeout },
	{ "connect_timeout", &tunable_connect_timeout },
	{ "idle_session_timeout", &tunable_idle_session_timeout },
	{ "data_connection_timeout", &tunable_data_connection_timeout },
	{ "local_umask", &tunable_local_umask },
	{ "upload_max_rate", &tunable_upload_max_rate },
	{ "download_max_rate", &tunable_download_max_rate },
	{ NULL, NULL }
};

/*填充内容（字符串型）的配置项*/
static struct parseconf_str_setting
{
	const char *p_setting_name;
	const char **p_variable;
}
parseconf_str_array[] = 
{
	{ "listen_address", &tunable_listen_address },
	{ NULL, NULL }
};


void parseconf_load_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL)
	{
		ERR_EXIT("fopen");
	}
	
	char setting_line[1024] = {0};
	while (fgets(setting_line, sizeof(setting_line), fp) != NULL)
	{
		if (strlen(setting_line) == 0
			|| setting_line[0] == '#'
			|| str_all_space(setting_line) == 1)
		{
			continue;
		}
		/* 去除 '\r\n' */
		str_trim_crlf(setting_line);
		
		parseconf_load_setting(setting_line);
		memset(setting_line, 0, sizeof(setting_line));
	}
	
	fclose(fp);
}


void parseconf_load_setting(const char *setting)
{
	//去除左空格
	while (isspace(*setting) > 0)
	{
		setting++;
	}
	char key[128]   = {0};
	char value[128] = {0};
	str_split(setting, key, value, '=');
	if (strlen(value) == 0)
	{
		fprintf(stderr, "misong value in config file for: %s\n", key);
		exit(EXIT_FAILURE);
	}
	
	
	{
		const struct parseconf_str_setting *p_str_setting = parseconf_str_array;
		while (p_str_setting->p_setting_name != NULL)
		{
			if (strcmp(key, p_str_setting->p_setting_name) == 0)
			{
				const char **p_cur_setting = p_str_setting->p_variable;
				if (*p_cur_setting)
				{
					free((char*)(*p_cur_setting));
				}
				*p_cur_setting = strdup(value);  //strdup 申请内存在拷贝
				return;
			}
			p_str_setting++;
		}
	}
	
	{
		const struct parseconf_bool_setting *p_bool_setting = parseconf_bool_array;
		while (p_bool_setting->p_setting_name != NULL)
		{
			if (strcmp(key, p_bool_setting->p_setting_name) == 0)
			{
				str_upper(value);
				int result = yesno_to_int(value);
				
				if (result == -1)
				{
					fprintf(stderr, "value error in config file for: %s\n", key);
					exit(EXIT_FAILURE);					
				}
				
				*(p_bool_setting->p_variable) = result;
				
				return;
			}
			p_bool_setting++;
		}		
	}
	
	{
		const struct parseconf_unit_setting *p_unit_setting = parseconf_uint_array;
		while (p_unit_setting->p_setting_name != NULL)
		{
			if (strcmp(key, p_unit_setting->p_setting_name) == 0)
			{
				/*如果是八进制 如 umask 将八进制转化为 整形*/
				if (value[0] == '0')
				{
					*(p_unit_setting->p_variable) = str_octal_to_uint(value);
				}
				else
				{
					*(p_unit_setting->p_variable) = atoi(value);
				}
				
				return;
			}

			p_unit_setting++;
		}			
	}
}