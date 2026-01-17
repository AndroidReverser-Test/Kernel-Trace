#include <stdio.h>
#include <cstring>
#include <unistd.h>

#include "Headers/uprobe_trace_user.h"

int main(int argc, char const *argv[])
{
    clear_all_uprobes();
    printf("success clear all uprobes\n");


    return 0;
}