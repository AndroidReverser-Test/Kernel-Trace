#include <asm/ptrace.h>
#include <linux/spinlock.h>
#include "uprobe_trace.h"
#include "mrbtree.h"

//#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define MAX_PATH_LEN 300
#define MAX_FUN_NAME 150
#define INS_LEN 4
#define LOOKUP_FOLLOW		0x0001
#define HASH_LEN_DECLARE u32 hash; u32 len
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12


#define O_LARGEFILE 00100000
#define O_RDONLY 00000000


struct file;
struct inode;
struct mm_struct;
struct vfsmount;
struct seq_file;
struct page;

typedef __bitwise unsigned int vm_fault_t;
struct vm_fault;

struct address_space {
	struct inode		*host;
};

struct hlist_bl_node {
    struct hlist_bl_node *next, **pprev;
 };


struct qstr {
    union {
        struct {
            HASH_LEN_DECLARE;
        };
        u64 hash_len;
    };
    const unsigned char *name;
};

struct dentry {
    /* RCU lookup touched fields */
    unsigned int d_flags;		/* protected by d_lock */
    spinlock_t d_seq;	/* per dentry seqlock */
    struct hlist_bl_node d_hash;	/* lookup hash list */
    struct dentry *d_parent;	/* parent directory */
    struct qstr d_name;
    struct inode *d_inode;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __randomize_layout;

enum uprobe_filter_ctx {
    UPROBE_FILTER_REGISTER,
    UPROBE_FILTER_UNREGISTER,
    UPROBE_FILTER_MMAP,
};

struct mpt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
};

struct uprobe_consumer {
    int (*handler)(struct uprobe_consumer *self, struct mpt_regs *regs);
    int (*ret_handler)(struct uprobe_consumer *self,
                       unsigned long func,
                       struct mpt_regs *regs);
    bool (*filter)(struct uprobe_consumer *self,
                   enum uprobe_filter_ctx ctx,
                   struct mm_struct *mm);

    struct uprobe_consumer *next;
};

struct vm_area_struct {
    /* The first cache line has the info for VMA tree walking. */

    unsigned long vm_start;		/* Our start address within vm_mm. */
    unsigned long vm_end;
};


struct vm_special_mapping {
	const char *name;	/* The name, e.g. "[vdso]". */

	/*
	 * If .fault is not provided, this points to a
	 * NULL-terminated array of pages that back the special mapping.
	 *
	 * This must not be NULL unless .fault is provided.
	 */
	struct page **pages;

	/*
	 * If non-NULL, then this is called to resolve page faults
	 * on the special mapping.  If used, .pages is not checked.
	 */
	vm_fault_t (*fault)(const struct vm_special_mapping *sm,
				struct vm_area_struct *vma,
				struct vm_fault *vmf);

	int (*mremap)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *new_vma);
};


struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};
typedef struct wait_queue_head wait_queue_head_t;


struct xol_area {
	wait_queue_head_t 		wq;		/* if all slots are busy */
	atomic_t 			slot_count;	/* number of in-use slots */
	unsigned long 			*bitmap;	/* 0 = free slot */

	struct vm_special_mapping	xol_mapping;
	struct page 			*pages[2];
	/*
	 * We keep the vma's vm_start rather than a pointer to the vma
	 * itself.  The probed process or a naughty kernel module could make
	 * the vma go away, and we must handle that reasonably gracefully.
	 */
	unsigned long 			vaddr;		/* Page(s) of instruction slots */
};

typedef void *fl_owner_t;

struct pid_namespace;