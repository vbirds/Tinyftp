#ifndef  _PARSE_CONF_H_
#define _PARSE_CONF_H_

/*加载配置文件*/
void parseconf_load_file(const char *path);
/*将配置项加载到相应变量*/
void parseconf_load_setting(const char *setting);


#endif /*_PARSE_CONF_H_*/