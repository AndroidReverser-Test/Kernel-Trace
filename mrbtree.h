#define RB_ROOT (struct rb_root) { NULL, }
# define GFP_KERNEL	0
typedef unsigned int __bitwise gfp_t;

struct rb_node {
    unsigned long  __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
    struct rb_node *rb_node;
};

struct my_key_value {
    unsigned long key;                // 键 - 整型
    void *value;            // 值
    struct rb_node node;    // 红黑树节点
};

void (*rb_erase)(struct rb_node *node, struct rb_root *root) = 0;
void (*rb_insert_color)(struct rb_node *node, struct rb_root *root) = 0;
struct rb_node *(*rb_first)(const struct rb_root *root) = 0;
void *(*kmalloc)(size_t size, gfp_t flags) = 0;
void (*kfree)(const void *objp) = 0;


static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,struct rb_node **rb_link)
{
    node->__rb_parent_color = (unsigned long)parent;
    node->rb_left = node->rb_right = NULL;
    *rb_link = node;
}


int insert_key_value(struct rb_root *root, unsigned long key, const void *value, int value_len)
{
    struct rb_node **new = &(root->rb_node);
    struct rb_node *parent = NULL;
    struct my_key_value *this;

    // 查找插入位置
    while (*new) {
        this = container_of(*new, struct my_key_value, node);
        parent = *new;

        if (key < this->key)
            new = &((*new)->rb_left);
        else if (key > this->key)
            new = &((*new)->rb_right);
        else
            return -1; // 键已存在
    }

    // 分配新节点内存
    struct my_key_value *data = kmalloc(sizeof(struct my_key_value), GFP_KERNEL);
    if (!data)
        return -1;

    // 分配字符串内存并复制值
    data->value = kmalloc(value_len + 1, GFP_KERNEL);
    if (!data->value) {
        kfree(data);
        return -1;
    }
//    strcpy(data->value, value);
    memcpy(data->value,value,value_len);
    // 设置键值
    data->key = key;

    // 添加到红黑树
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);

    return 0;
}


void destroy_entire_tree(struct rb_root *root)
{
    struct rb_node *node;
    struct my_key_value *data;

    // 循环删除所有节点
    while (node = rb_first(root)) {
        data = container_of(node, struct my_key_value, node);

        // 从树中移除节点
        rb_erase(node, root);

        // 释放字符串内存
        if (data->value) {
            kfree(data->value);
            data->value = NULL;
        }

        // 释放节点内存
        kfree(data);
    }

    // 重置根节点
    *root = RB_ROOT;
}


struct my_key_value *search_key_value(struct rb_root *root, unsigned long key)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct my_key_value *this = container_of(node, struct my_key_value, node);

        if (key < this->key)
            node = node->rb_left;
        else if (key > this->key)
            node = node->rb_right;
        else
            return this;
    }
    return NULL;
}