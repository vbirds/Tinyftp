#include "hash.h"
#include "common.h"
#include "assert.h"


typedef struct hash_node
{
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;

struct hash
{
	unsigned int buckets;  //桶的个数
	hashfunc_t hash_func;  //哈希函数
	hash_node_t **nodes;   //哈希链表
};

//得到桶号
hash_node_t** hash_get_bucket(hash_t *hash, void *key)
{
	unsigned int bucket = hash->hash_func(hash->buckets, key);
	if (bucket >= hash->buckets)
	{
		fprintf(stderr, "bad bucket lookup\n");
		exit(EXIT_FAILURE);
	}
	
	return &(hash->nodes[bucket]);
}
hash_node_t* hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t **bucket = hash_get_bucket(hash, key);
	hash_node_t *node = *bucket;
	if (node == NULL)
	{
		return NULL;
	}
	
	while (node != NULL && memcmp(node->key, key, key_size) != 0)
	{
		node = node->next;
	}
	
	return node;
}

hash_t* hash_alloc(unsigned int buckets, hashfunc_t hash_func)
{
	hash_t *hash = (hash_t*)malloc(sizeof(hash));
	assert(hash != NULL);
	
	hash->buckets = buckets;
	hash->hash_func = hash_func;
	
	int size = buckets * sizeof(hash_node_t*);
	hash->nodes = (hash_node_t **)malloc(size);
	assert(hash->nodes != NULL);
	memset(hash->nodes, 0, size);
	
	return hash;
}

void* hash_lookup_entry(hash_t *hash, void* key, unsigned int key_size)
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL)
	{
		return NULL;
	}
	
	return node->value;
}

void hash_add_entry(hash_t *hash, void* key, unsigned int key_size,
	void  *value, unsigned int value_size)
{
	if (hash_lookup_entry(hash, key, key_size))
	{
		fprintf(stderr, "duplicate hash key\n");
		return;
	}
	
	hash_node_t *node = (hash_node_t*)malloc(sizeof(hash_node_t));
	node->prev = NULL;
	node->next = NULL;
	
	node->key = malloc(key_size);
	memcpy(node->key, key, key_size);
	
	node->value = malloc(value_size);
	memcpy(node->value, value, value_size);
	
	
	hash_node_t **bucket = hash_get_bucket(hash, key);
	if (*bucket == NULL)
	{
		*bucket = node;
	}
	else
	{	
		//头插法 将节点插入到链表头部
		node->next = *bucket;
		(*bucket)->prev = node;
		*bucket = node;	
	}
	
}

void hash_free_entry(hash_t *hash, void *key, unsigned int key_size)
{
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL)
	{
		return;
	}
	
	free(node->key);
	free(node->value);
	
	//判断是否头节点
	if (node->prev == NULL)
	{
		hash_node_t **head = hash_get_bucket(hash, key);
		*head = node->next;	
		free(node);
		return;
	}
	//判断是否尾节点
	if (node->next == NULL)
	{
		node->prev->next = NULL;
		free(node);
		return;
	}
	//中间节点
	node->prev->next = node->next;
	node->next->prev = node->prev;
	free(node);
	
	return;
}







