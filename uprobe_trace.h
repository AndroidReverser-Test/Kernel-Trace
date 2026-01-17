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