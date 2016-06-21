#include "str.h"
#include "string.h"
#include "stdio.h"
#include "ctype.h"
#include "stdlib.h"

void str_trim_crlf(char *str)
{
	char *p = &(str[strlen(str)-1]);
	while (*p == '\r' || *p == '\n')
	{
		*p = '\0';
		p--;
	}
}

void str_split(const char *str, char *left, char *right, char limit)
{	
    char *p = strrchr(str, limit);
	
	if (p == NULL)
	{
		strcpy(left, str);
	}
	else
	{
		strncpy(left, str, p-str);
		strcpy(right, p+1);
	}
}

int str_all_space(char *str)
{
	while (*str)
	{
		if (!isspace(*str))
		{
			return 0;
		}
		str++;
	}

	return 1;
}

void str_upper(char *str)
{
	char *p = str;
	while (*p)
	{
		*p = toupper(*p);
		p++;
	}
	
}

long long str_tolonglong(const char *str)
{
    long long num = 0;
    const char *p = str;
	int strlength = 0;
	
	strlength = strlen(str);
	if (strlength > 15)
	{
		return 0;
	}

    while (*p)
    {
        num = num*10 + (*p-48); //ascii '0' = 48
        p++;
    }

    return num;
	//return atoll(str);
}

unsigned int str_octal_to_uint(const char *str)
{
    unsigned int num = 0;
    const char *p = str;

    while (*p)
    {
        char digit = *p;  //ascii '0' = 48
        if (!isdigit(digit) || digit > 55)  //ascii '7' = 55
        {
            break;
        }
        if (digit != '0')
        {
            num <<= 3;
            num += (digit - '0');
        }
        p++;
    }

    return num;
}

int yesno_to_int(char *str)
{
    if (strcasecmp(str,"YES") == 0
		|| strcasecmp(str,"TRUE") == 0
		|| strcasecmp(str,"1") == 0) 
	{
		return 1;
	}
    if (strcasecmp(str,"NO") == 0
		|| strcasecmp(str,"FALSE") == 0
		|| strcasecmp(str,"0") == 0) 
	{
		return 0;
	}
	
    return -1;
}