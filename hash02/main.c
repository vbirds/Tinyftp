#include "hash.h"
#include "common.h"

typedef struct stu
{
	char sno[5];
	char name[32];
	int age;
}stu_t;

typedef struct stu2
{
	int sno;
	char name[32];
	int age;
}stu2_t;

unsigned int hash_str(unsigned int buckets, void *key)
{
	char *sno = (char*)key;
	unsigned int index = 0;
	
	while (*sno)
	{
		index = *sno + 4*index;
		sno++;
	}
	
	return index % buckets;
}

unsigned int hash_int(unsigned int buckets, void *key)
{
	int *sno = (int*)key;
	
	return (*sno) % buckets;
}

int main(int argc, char *argv[])
{
	stu2_t stu2_arr[] = 
	{
		{1234, "AAAA", 20},
		{4568, "BBBB", 23},
		{6279, "CCCC", 19}
	};
	hash_t* hash = hash_alloc(256, hash_int);
	
	int size = sizeof(stu2_arr) / sizeof(stu2_arr[0]);
	int i;
	for (i = 0; i < size; ++i)
	{
		hash_add_entry(hash, &stu2_arr[i].sno, sizeof(stu2_arr[i].sno),
			&stu2_arr[i], sizeof(stu2_arr[i]));
	}
	
	int num = 4568;
	stu2_t *s = (stu2_t*)hash_lookup_entry(hash, &num, sizeof(num));
	if (s != NULL)
	{
		printf("%d %s %d\n", s->sno, s->name, s->age);
	}
	else
	{
		printf("no found\n");
	}
	
	int delnum = 1234;
	hash_free_entry(hash, &delnum, sizeof(delnum));
	
	stu2_t *p = (stu2_t *)hash_lookup_entry(hash, &delnum, sizeof(delnum));
	if (p != NULL)
	{
		printf("%d %s %d\n", s->sno, s->name, s->age);
	}
	else
	{
		printf("no found\n");
	}
	
	if (s)
	{
		free(s);
	}
	if (p)
	{
		free(p);
	}
	/*
	stu_t stu_arr[] = 
	{
		{"1234", "AAAA", 20},
		{"4568", "BBBB", 23},
		{"6279", "CCCC", 19}
	};
	
	hash_t* hash = hash_alloc(256, hash_str);
	
	int size = sizeof(stu_arr) / sizeof(stu_arr[0]);
	int i;
	for (i = 0; i < size; ++i)
	{
		hash_add_entry(hash, stu_arr[i].sno, strlen(stu_arr[i].sno),
			&stu_arr[i], sizeof(stu_arr[i]));
	}
	
	stu_t *s = (stu_t*)hash_lookup_entry(hash, "4568", strlen("4568"));
	if (s != NULL)
	{
		printf("%s %s %d\n", s->sno, s->name, s->age);
	}
	else
	{
		printf("no found\n");
	}
	
	hash_free_entry(hash, "1234", strlen("1234"));
	
	stu_t *p = (stu_t*)hash_lookup_entry(hash, "1234", strlen("1234"));
	if (p != NULL)
	{
		printf("%s %s %d\n", s->sno, s->name, s->age);
	}
	else
	{
		printf("no found\n");
	}
	
	if (s)
	{
		free(s);
	}
	if (p)
	{
		free(p);
	}
	*/
	
	return 0;
}