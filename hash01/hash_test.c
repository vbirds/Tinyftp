#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define BUCKETS 101

typedef unsigned int(*arrf[])(char *str);
typedef unsigned int(*hash_func)(char *str);

unsigned int SDBMHash(char *str);
unsigned int RSHash(char *str);

static	char *keywords[] =
{
    "auto", "break", "case", "char", "const", "continue",
    "default", "do", "double", "else", "enum", "float",
    "for", "goto", "if", "int", "long", "register", "return",
    "short", "signed", "sizeof", "static", "struct", "switch"
};

static arrf af =
{
    SDBMHash,
    RSHash
};

#define SIZE  (sizeof(keywords) / sizeof(keywords[0]))
#define SIZEFUNC ( sizeof(af) / sizeof(af[0]) )


unsigned int SDBMHash(char *str)
{
    unsigned int hash = 0;
    while (*str)
    {
        // equivalent to: hash = 65599 * hash (*str++)
        hash = (*str++) + (hash << 6) + (hash << 16) -hash;
    }

    return (hash & 0x7FFFFFFF) % BUCKETS; //2^31
}

unsigned int RSHash(char *str)
{
    unsigned int b = 378551;
    unsigned int a = 63689;
    unsigned int hash = 0;

    while (*str)
    {
        hash = hash * a + (*str++);
        a *= b;
    }

    return (hash & 0x7fffffff) % BUCKETS;
}

void print_array(int *count)
{

    int i = 0;
    for (i = 0; i < SIZE; ++i)
    {
        int pos = SDBMHash(keywords[i]);
        printf("%-10s: %3d %3d\n", keywords[i], pos, count[pos]);
    }


}

double cal_rate(int *count)
{
    double rate = 0.0;
    double repeat = 0.0;
    int i = 0;

    for (i = 0; i < BUCKETS; ++i)
    {
        if (count[i] > 1)
        {
            repeat++;
        }
    }

    rate = (double)(1.0 - (double)(repeat*2 / SIZE));
    return rate;
}


int do_hash(hash_func func, int *count)
{
    int i = 0;
    for (i = 0; i < SIZE; ++i)
    {
        int pos = func(keywords[i]);
        count[pos]++;
    }

    return 0;
}


void print_rate(double *rate_arry)
{
    int i = 0;
    for (i = 0; i < SIZEFUNC; ++i)
    {
        printf("%d rate: %3f\n", i+1, rate_arry[i]);
    }
}

int main(void)
{

    int count[BUCKETS] = {0};
    double rate_arry[SIZEFUNC] = {0};

    int i = 0;
    for (i = 0; i < 2; ++i)
    {
        memset(count, 0, sizeof(count));
        do_hash(af[i], count);
        rate_arry[i] = cal_rate(count);
    }

    /*
    memset(count, 0, sizeof(count));
    do_hash(af[0], count);
    rate_arry[0] = cal_rate(count);

    print_array(count);


    memset(count, 0, sizeof(count));
    do_hash(af[1], count);
    rate_arry[1] = cal_rate(count);
    */

    print_rate(rate_arry);

    return 0;
}
