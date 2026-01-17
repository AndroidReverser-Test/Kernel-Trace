#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <taskext.h>
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <hook.h>
#include "kernel_trace.h"

KPM_NAME("kernel_trace");
KPM_VERSION("6.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Test");
KPM_DESCRIPTION("use uprobe trace some fun in kpm");

pid_t (*mtask_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
int (*uprobe_register)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc) = 0;
void (*uprobe_unregister)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc) = 0;
int (*kern_path)(const char *name, unsigned int flags, struct path *path) = 0;
struct inode *(*igrab)(struct inode *inode) = 0;
void (*path_put)(const struct path *path) = 0;
void (*rcu_read_unlock)(void) = 0;
int (*trace_printk)(unsigned long ip, const char *fmt, ...) = 0;

int (*bpf_probe_read_user)(void *dst, u32 size,const void __user *unsafe_ptr) = 0;

unsigned long (*get_unmapped_area)(struct file *file, unsigned long addr, unsigned long len,unsigned long pgoff, unsigned long flags) = 0;

char *(*file_path)(struct file *filp, char *buf, int buflen) = 0;
char *(*mkstrdup)(const char *s, gfp_t gfp) = 0;
struct file *(*filp_open)(const char *filename, int flags, umode_t mode) = 0;
ssize_t (*kernel_read)(struct file *file, void *buf, size_t count, loff_t *pos) = 0;
int (*filp_close)(struct file *filp, fl_owner_t id) = 0;
void *(*vmalloc)(unsigned long size) = 0;
void (*vfree)(const void *addr) = 0;
struct page *(*vmalloc_to_page)(const void *vmalloc_addr) = 0;


void *install_special_mapping_addr;
void *create_xol_area_addr;
void *do_read_cache_page_addr;


char file_name[MAX_PATH_LEN];
uid_t target_uid = -1;
unsigned long fun_offsets[MAX_HOOK_NUM];
int hook_num = 0;
struct rb_root fun_info_tree = RB_ROOT;
struct rb_root fix_idx_tree = RB_ROOT;
static struct inode *inode;
unsigned long module_base = 0;
static struct uprobe_consumer trace_uc;
static struct file *fix_file = NULL;

void before_create_xol_area(hook_fargs1_t *args, void *udata){
    unsigned long vaddr = (unsigned long )args->arg0;

    if(!vaddr){
        vaddr = get_unmapped_area(NULL, 0,PAGE_SIZE, 0, 0);
        args->arg0 = vaddr;
        logkd("+Test-Log+ change uprobe map addr to:%llx\n",vaddr);
    }

}


void before_install_special_mapping(hook_fargs6_t *args, void *udata){
    struct vm_special_mapping *ospec;
    ospec = (struct vm_special_mapping*)args->arg4;
    if(strcmp(ospec->name,"[uprobes]")==0){
        ospec->name = "Kernel-Trace";
        logkd("+Test-Log+ create map item:Kernel-Trace\n");
    }
}

void before_do_read_cache_page(hook_fargs5_t *args, void *udata){

    char *mfile_path;
    struct file *filp = (struct file*)args->arg3;
    unsigned long index = (unsigned long)args->arg1;

    if(fix_file && filp){
        char *path_buf = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
        mfile_path = file_path(filp, path_buf, MAX_PATH_LEN);
        if (!mfile_path) {
            kfree(path_buf);
        }else{
            mfile_path = mkstrdup(mfile_path, GFP_KERNEL);
            kfree(path_buf);
            if(strcmp(mfile_path,file_name)==0){

                loff_t pos;
                struct my_key_value *fix_info;
                fix_info = search_key_value(&fix_idx_tree,index);
                if(likely(fix_info)){
                    index = *((unsigned int*)fix_info->value);
                }

                pos = (loff_t)(index*0x1000);
                char *mbytes = NULL;
                mbytes = vmalloc(PAGE_SIZE);
                if (!mbytes) {
                    logke("+Test-Log+ Failed to allocate memory with vmalloc\n");
                    return;
                }
                int rret = kernel_read(fix_file, mbytes, PAGE_SIZE, &pos);
                if (rret < 0) {
                    logke("+Test-Log+ Failed to read file: %ld at %llx\n", rret,pos);
                    return;
                }

                logkd("+Test-Log+ index:%llx,pos:%llx,file_bytes:%x %x %x %x\n",index,pos,mbytes[0],mbytes[1],mbytes[2],mbytes[3]);
                struct page *mpage = vmalloc_to_page(mbytes);
                args->ret = (uint64_t)mpage;
                args->skip_origin = 1;
                vfree(mbytes);
                return;
            }
        }

    }
}

void before_mincore(hook_fargs3_t *args, void *udata){
    int trace_flag = (int)syscall_argn(args, 1);
    if(trace_flag<TRACE_FLAG || trace_flag>TRACE_FLAG+CLEAR_UPROBE){
        return;
    }

    int trace_flag_num = trace_flag-TRACE_FLAG;
    if(trace_flag_num==SET_FUN_INFO){
        if(unlikely(hook_num==MAX_HOOK_NUM)){
            logke("+Test-Log+ MAX_HOOK_NUM:%d\n",MAX_HOOK_NUM);
            goto error_out;
        }

        if(!module_base || strlen(file_name)==0 || target_uid==-1){
            logke("+Test-Log+ module_base or file_name or target_uid not set\n");
            goto error_out;
        }

        void* uuprobe_item = (void*)syscall_argn(args, 2);
        struct uprobe_item_info *uprobe_item = NULL;
        uprobe_item = kmalloc(sizeof(struct uprobe_item_info), GFP_KERNEL);
        if(!uprobe_item){
            logke("+Test-Log+ Failed to allocate memory with kmalloc\n");
            goto error_out;
        }

        if(bpf_probe_read_user(uprobe_item,sizeof(struct uprobe_item_info),uuprobe_item)<0){
            logke("+Test-Log+ bpf_probe_read_user error\n");
            goto error_out;
        }


        unsigned long fun_offset = (unsigned long)uprobe_item->fun_offset;
        char fun_name[MAX_FUN_NAME];
        compat_strncpy_from_user(fun_name,uprobe_item->fun_name,sizeof(fun_name));

        int insert_ret = insert_key_value(&fun_info_tree,fun_offset,fun_name,strlen(fun_name));
        if(insert_ret==-1){
            logke("+Test-Log+ same fun 0x%llx set uprobe\n",fun_offset);
            goto error_out;
        }
        logkd("+Test-Log+ fun_name:%s,fun_offset:%llx\n",fun_name,fun_offset);

        unsigned long rfun_offset = uprobe_item->uprobe_offset;
        unsigned int f_idx = fun_offset >> PAGE_SHIFT;
        insert_key_value(&fix_idx_tree,rfun_offset >> PAGE_SHIFT,&f_idx,4);
        kfree(uprobe_item);

        int hret = uprobe_register(inode,rfun_offset,&trace_uc);
        if(hret<0){
            logke("+Test-Log+ set uprobe error in 0x%llx\n",rfun_offset);
            goto error_out;
        }

        fun_offsets[hook_num] = rfun_offset;
        hook_num++;

        goto success_out;
    }


    if(trace_flag_num==SET_TRACE_INFO){
        void* utrace_info = (void*)syscall_argn(args, 2);
        struct trace_init_info *base_info = NULL;
        base_info = kmalloc(sizeof(struct trace_init_info), GFP_KERNEL);
        if(!base_info){
            logke("+Test-Log+ Failed to allocate memory with kmalloc\n");
            goto error_out;
        }

        if(bpf_probe_read_user(base_info,sizeof(struct trace_init_info),utrace_info)<0){
            logke("+Test-Log+ bpf_probe_read_user error\n");
            goto error_out;
        }

        target_uid = (uid_t)base_info->uid;
        logkd("+Test-Log+ set target_uid:%d\n",target_uid);

        module_base = (unsigned long)base_info->module_base;
        logkd("+Test-Log+ set module_base:0x%llx\n",module_base);

        compat_strncpy_from_user(file_name,base_info->tfile_name,sizeof(file_name));
        logkd("+Test-Log+ set target_file_name:%s\n",file_name);
        struct path path;
        int fret = kern_path(file_name, LOOKUP_FOLLOW, &path);
        if(fret<0){
            logke("+Test-Log+ error file path:%s\n",file_name);
            goto error_out;
        }
        inode = igrab(path.dentry->d_inode);
        path_put(&path);
        logkd("+Test-Log+ success set file inode\n");

        char fix_file_name[MAX_PATH_LEN];
        compat_strncpy_from_user(fix_file_name,base_info->fix_file_name,sizeof(fix_file_name));
        if(strlen(fix_file_name)!=0){
            if (fix_file) {
                filp_close(fix_file, NULL);
            }
            fix_file = filp_open(fix_file_name, O_RDONLY | O_LARGEFILE, 0);
            if (!fix_file) {
                logke("+Test-Log+ Failed to open file:%s\n",fix_file_name);
                goto error_out;
            }
            logkd("+Test-Log+ set fix_file_name:%s\n",fix_file_name);
        }
        kfree(base_info);

        goto success_out;

    }


    if(trace_flag_num==CLEAR_UPROBE){
        for (int i = 0; i < hook_num; ++i) {
            uprobe_unregister(inode,fun_offsets[i],&trace_uc);
        }
        hook_num = 0;
        destroy_entire_tree(&fun_info_tree);
        destroy_entire_tree(&fix_idx_tree);
        logkd("+Test-Log+ success clear all uprobes\n");
        goto success_out;
    }

error_out:
    args->ret = SET_TRACE_ERROR;
    args->skip_origin = 1;
    return;

success_out:
    args->ret = SET_TRACE_SUCCESS;
    args->skip_origin = 1;
    return;
}


static int trace_handler(struct uprobe_consumer *self, struct mpt_regs *regs){
    struct task_struct *task = current;
    struct cred* cred = *(struct cred**)((uintptr_t)task + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    struct my_key_value *tfun;
    unsigned long fun_offset;
    if(uid==target_uid){
        fun_offset = regs->pc-module_base;
        tfun = search_key_value(&fun_info_tree,fun_offset);
        if(likely(tfun)){
            goto target_out;
        }
    }else{
        goto no_target_out;
    }

target_out:
//    logkd("+Test-Log+ fun_name:%s,fun_offset:0x%llx calling\n",tfun->value,fun_offset);
    int trace_printk_ret = trace_printk(0,"+Test-Log+ fun_name:%s,fun_offset:0x%llx calling\n",tfun->value,fun_offset);
    if(unlikely(trace_printk_ret<0)){
        logke("+Test-Log+ trace_printk error\n");
    }
    return 0;

no_target_out:
    return 0;
}

static unsigned long get_do_read_cache_page_addr(){
    unsigned long read_cache_page_addr = kallsyms_lookup_name("read_cache_page");
    logkd("+Test-Log+ read_cache_page_addr:%llx\n",read_cache_page_addr);
    unsigned int* ins = (unsigned int*)(read_cache_page_addr);
    for (int i = 0; i < 10; ++i) {
        unsigned int instr = ins[i];

        if ((instr >> 26) == 0x25) {
            logkd("+Test-Log+ bl ins=>i:%d,ins:%lx\n",i,instr);

            int32_t imm26 = instr & 0x03FFFFFF;
            // 符号扩展（26位有符号 → 32位有符号）
            if (imm26 & 0x02000000) {  // 检查 bit25（第 26 位的符号位）
                imm26 |= 0xFC000000;   // 负数的符号扩展
            }

            int64_t offset = (int64_t)((int32_t)imm26);
            offset *= 4;
            unsigned long bl_addr = read_cache_page_addr + i*4;
            unsigned long do_read_cache_page_addr = bl_addr + offset;
            return do_read_cache_page_addr;
        }
    }

    return 0;
}


static long kernel_trace_init(const char *args, const char *event, void *__user reserved)
{
    logkd("kpm kernel_trace init\n");
    mtask_pid_nr_ns = (typeof(mtask_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    uprobe_register = (typeof(uprobe_register))kallsyms_lookup_name("uprobe_register");
    uprobe_unregister = (typeof(uprobe_unregister))kallsyms_lookup_name("uprobe_unregister");
    kern_path = (typeof(kern_path))kallsyms_lookup_name("kern_path");
    igrab = (typeof(igrab))kallsyms_lookup_name("igrab");
    path_put = (typeof(path_put))kallsyms_lookup_name("path_put");
    rcu_read_unlock = (typeof(rcu_read_unlock))kallsyms_lookup_name("rcu_read_unlock");


    rb_erase = (typeof(rb_erase))kallsyms_lookup_name("rb_erase");
    rb_insert_color = (typeof(rb_insert_color))kallsyms_lookup_name("rb_insert_color");
    rb_first = (typeof(rb_first))kallsyms_lookup_name("rb_first");
    kmalloc = (typeof(kmalloc))kallsyms_lookup_name("__kmalloc");
    kfree = (typeof(kfree))kallsyms_lookup_name("kfree");

    trace_printk = (typeof(trace_printk))kallsyms_lookup_name("__trace_printk");
    bpf_probe_read_user = (typeof(bpf_probe_read_user))kallsyms_lookup_name("bpf_probe_read_user");

    get_unmapped_area = (typeof(get_unmapped_area))kallsyms_lookup_name("get_unmapped_area");
    file_path = (typeof(file_path))kallsyms_lookup_name("file_path");
    mkstrdup = (typeof(mkstrdup))kallsyms_lookup_name("kstrdup");
    filp_open = (typeof(filp_open))kallsyms_lookup_name("filp_open");
    kernel_read = (typeof(kernel_read))kallsyms_lookup_name("kernel_read");
    filp_close = (typeof(filp_close))kallsyms_lookup_name("filp_close");
    vmalloc = (typeof(vmalloc))kallsyms_lookup_name("vmalloc");
    vfree = (typeof(vfree))kallsyms_lookup_name("vfree");
    vmalloc_to_page = (typeof(vmalloc_to_page))kallsyms_lookup_name("vmalloc_to_page");

    install_special_mapping_addr = (void *)kallsyms_lookup_name("__install_special_mapping");

    create_xol_area_addr = (void *)kallsyms_lookup_name("__create_xol_area");

    unsigned long do_read_cache_page_num = get_do_read_cache_page_addr();
    if(do_read_cache_page_num==0){
        logke("+Test-Log+ can not get do_read_cache_page addr\n");
        return 0;
    }
    do_read_cache_page_addr = (void *)do_read_cache_page_num;

    logkd("+Test-Log+ mtask_pid_nr_ns:%llx\n",mtask_pid_nr_ns);
    logkd("+Test-Log+ uprobe_register:%llx\n",uprobe_register);
    logkd("+Test-Log+ uprobe_unregister:%llx\n",uprobe_unregister);
    logkd("+Test-Log+ kern_path:%llx\n",kern_path);
    logkd("+Test-Log+ igrab:%llx\n",igrab);
    logkd("+Test-Log+ path_put:%llx\n",path_put);
    logkd("+Test-Log+ rcu_read_unlock:%llx\n",rcu_read_unlock);

    logkd("+Test-Log+ rb_erase:%llx\n",rb_erase);
    logkd("+Test-Log+ rb_insert_color:%llx\n",rb_insert_color);
    logkd("+Test-Log+ rb_first:%llx\n",rb_first);
    logkd("+Test-Log+ kmalloc:%llx\n",kmalloc);
    logkd("+Test-Log+ kfree:%llx\n",kfree);

    logkd("+Test-Log+ trace_printk:%llx\n",trace_printk);
    logkd("+Test-Log+ bpf_probe_read_user:%llx\n",bpf_probe_read_user);

    logkd("+Test-Log+ get_unmapped_area:%llx\n",get_unmapped_area);
    logkd("+Test-Log+ file_path:%llx\n",file_path);
    logkd("+Test-Log+ kstrdup:%llx\n",mkstrdup);
    logkd("+Test-Log+ filp_open:%llx\n",filp_open);
    logkd("+Test-Log+ kernel_read:%llx\n",kernel_read);
    logkd("+Test-Log+ filp_close:%llx\n",filp_close);
    logkd("+Test-Log+ vmalloc:%llx\n",vmalloc);
    logkd("+Test-Log+ vfree:%llx\n",vfree);
    logkd("+Test-Log+ vmalloc_to_page:%llx\n",vmalloc_to_page);

    logkd("+Test-Log+ install_special_mapping_addr:%llx\n",install_special_mapping_addr);

    logkd("+Test-Log+ create_xol_area_addr:%llx\n",create_xol_area_addr);

    logkd("+Test-Log+ do_read_cache_page_addr:%llx\n",do_read_cache_page_addr);



    if(!(mtask_pid_nr_ns && uprobe_register && uprobe_unregister
    && kern_path && igrab && path_put && rcu_read_unlock
    && rb_erase && rb_insert_color && rb_first && trace_printk
    && bpf_probe_read_user && get_unmapped_area && file_path && mkstrdup && filp_open && kernel_read && filp_close && vmalloc && vfree && vmalloc_to_page
    && install_special_mapping_addr && create_xol_area_addr && do_read_cache_page_addr)){
        logke("+Test-Log+ can not find some fun addr\n");
        return -1;
    }

    trace_uc.handler = trace_handler;

    hook_err_t err = inline_hook_syscalln(__NR_mincore, 3, before_mincore, 0, 0);
    if(err){
        logke("+Test-Log+ hook __NR_mincore error\n");
        return -1;
    }

    err = hook_wrap6(install_special_mapping_addr, before_install_special_mapping, NULL, 0);
    if(err){
        logke("+Test-Log+ hook install_special_mapping_addr error\n");
        return -1;
    }

    err = hook_wrap2(create_xol_area_addr, before_create_xol_area, NULL, 0);
    if(err){
        logke("+Test-Log+ hook create_xol_area_addr error\n");
        return -1;
    }

    err = hook_wrap5(do_read_cache_page_addr, before_do_read_cache_page, NULL, 0);
    if(err){
        logke("+Test-Log+ hook do_read_cache_page error\n");
        return -1;
    }


    logkd("+Test-Log+ success init\n");
    return 0;
}

static long kernel_trace_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kernel_trace control, args: %s\n", args);

    return 0;
}

static long kernel_trace_exit(void *__user reserved)
{
    inline_unhook_syscalln(__NR_mincore, before_mincore, 0);
    unhook(install_special_mapping_addr);
    unhook(create_xol_area_addr);
    unhook(do_read_cache_page_addr);
    rcu_read_unlock();//解锁，不然内核会崩
    for (int i = 0; i < hook_num; ++i) {
        uprobe_unregister(inode,fun_offsets[i],&trace_uc);
    }
    logkd("+Test-Log+ success clear all uprobes\n");
    destroy_entire_tree(&fun_info_tree);
    destroy_entire_tree(&fix_idx_tree);
    if(fix_file){
        filp_close(fix_file, NULL);
    }
    logkd("kpm kernel_trace  exit\n");
}

KPM_INIT(kernel_trace_init);
KPM_CTL0(kernel_trace_control0);
KPM_EXIT(kernel_trace_exit);