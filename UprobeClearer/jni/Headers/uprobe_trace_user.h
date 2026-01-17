#include <sys/syscall.h>
#include <unistd.h>


#define TRACE_FLAG 511
#define MAX_HOOK_NUM 2000
#define SET_TRACE_SUCCESS 1000
#define SET_TRACE_ERROR 1001

enum trace_info {
    SET_TRACE_INFO,
    SET_FUN_INFO,
    CLEAR_UPROBE,
};

struct trace_init_info {
    uid_t uid;
    unsigned long module_base;
    char* tfile_name;
    char* fix_file_name;
};

struct uprobe_item_info {
    unsigned long uprobe_offset;
    unsigned long fun_offset;
    char *fun_name;
};

int clear_all_uprobes(){
    int ret = syscall(__NR_mincore,0,TRACE_FLAG+CLEAR_UPROBE,"");
    return ret;
}

int trace_init(trace_init_info *base_info){
    clear_all_uprobes();
    int ret = syscall(__NR_mincore,0,TRACE_FLAG+SET_TRACE_INFO,base_info);
    return ret;
}

int set_fun_info(uprobe_item_info *uprobe_item){
    int ret = syscall(__NR_mincore,0,TRACE_FLAG+SET_FUN_INFO,uprobe_item);
    return ret;
}