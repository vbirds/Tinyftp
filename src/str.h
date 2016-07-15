#ifndef  _STR_H_
#define _STR_H_

void str_trim_crlf(char *str);

/*提取键值对*/
void str_split(const char *str, char *left, char *right, char limit);

int str_all_space(char *str);

void str_upper(char *str);

long long str_tolonglong(const char *str);

unsigned int str_octal_to_uint(const char *str);

/* 把字符串yes或no转换成整形, 错误返回-1 */
int yesno_to_int(char *str);

#endif /*_STR_H_*/