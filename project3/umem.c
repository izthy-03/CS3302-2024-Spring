#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h>
#include "umem.h"

MODULE_LICENSE("GPL");

// TODO: data structure definition
struct umem_pool_t {
    struct page* head;
    unsigned int order;

    struct pginfo_t {
        struct task_struct* owner;
    } pginfo[UMEM_POOL_SIZE];

};

/* Malloc block info */
struct umem_block_t {
    struct list_head blocklist;
    struct page* page;
    unsigned long vaddr;
    unsigned long size;
    unsigned int pool;
};

struct userinfo_t {
    struct list_head list;
    struct task_struct* user;
    struct list_head block_head;
};

struct umem_pool_t umem_pool[UMEM_NUM_POOL];
struct list_head userinfo_head;
      spinlock_t userinfo_lock;


static int umem_open(struct inode *inode, struct file *filp)
{
    // TODO
    pr_info("Process %p opened\n", current);
    struct userinfo_t* userinfo = kmalloc(sizeof(struct userinfo_t), GFP_KERNEL);
    userinfo->user = current;
    INIT_LIST_HEAD(&userinfo->block_head);
    spin_lock(&userinfo_lock);
    list_add(&userinfo->list, &userinfo_head);
    spin_unlock(&userinfo_lock);

    filp->private_data = userinfo;
    return 0;
}

static int umem_release(struct inode *inode, struct file *filp)
{
    // TODO
    pr_info("Process %p released\n", current);
    spin_lock(&userinfo_lock);
    struct userinfo_t* userinfo = filp->private_data;

    /* Release unfreed pages in pool */
    struct list_head *block;
    list_for_each(block, &userinfo->block_head) {
        struct umem_block_t* umemblock = list_entry(block, struct umem_block_t, blocklist);
        vm_munmap(umemblock->vaddr, umemblock->size);
        list_del(block);
        kfree(umemblock);
    }

    list_del(&userinfo->list);
    kfree(userinfo);
    spin_unlock(&userinfo_lock);
    return 0;
}

/* 
 * Find specified user's info 
 * return NULL if not found
 */
static struct userinfo_t* 
find_userinfo(struct task_struct* user) {
    struct list_head* node;
    list_for_each(node, &userinfo_head) {
        struct userinfo_t* userinfo = list_entry(node, struct userinfo_t, list);
        if (userinfo->user == user) {
            return userinfo;
        }
    }
    return NULL;
}

static struct umem_block_t* 
find_blockinfo(struct userinfo_t* userinfo, unsigned long addr) {
    struct list_head* node;
    list_for_each(node, &userinfo->block_head) {
        struct umem_block_t* block = list_entry(node, struct umem_block_t, blocklist);
        if (block->vaddr == addr) {
            return block;
        }
    }
    return NULL;
}

/*
 * Linear scan to find continuous pages
 * return NULL if no enough pages
 * return the head of the pages if found
 */
static struct page* 
alloc_pool_pages(const int poolid, const int pagenum, struct task_struct* user) {
    if (poolid >= UMEM_NUM_POOL) {
        pr_warn("Invalid pool id\n");
        return NULL;
    }
    if (pagenum > UMEM_POOL_SIZE) {
        pr_warn("Too many pages\n");
        return NULL;
    }

    struct page* page = umem_pool[poolid].head;
    int cnt = 0, pgid = 0;
    while (pgid < UMEM_POOL_SIZE &&  cnt < pagenum) {
        if (page == NULL) {
            pr_warn("Unallocated pool pages\n");
            return NULL;
        }
        if (umem_pool[poolid].pginfo[pgid].owner == NULL) {
            cnt++;
        } else {
            cnt = 0;
        }
        pgid++, page++;
    }

    /* No enough continuous pages */
    if (cnt < pagenum) {
        pr_warn("No enough pages in pool %d\n", poolid);
        return NULL;
    }

    /* Mark the pages */
    pgid -= pagenum;
    for (int i = 0; i < pagenum; i++) {
        umem_pool[poolid].pginfo[pgid + i].owner = user;
    }

    return (struct page*)(page - pagenum);
}

void free_pool_pages(const int poolid, const int pagenum, const int offset) {
    if (poolid >= UMEM_NUM_POOL) {
        pr_warn("Invalid pool id\n");
        return;
    }
    if (pagenum > UMEM_POOL_SIZE) {
        pr_warn("Too many pages\n");
        return;
    }

    for (int i = 0; i < pagenum; i++) {
        umem_pool[poolid].pginfo[offset + i].owner = NULL;
    }
}

static long umem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long err;
    struct umem_info kern_umem_info;
    struct userinfo_t* userinfo;
    struct umem_block_t* blockinfo;

    pr_info("umem_ioctl cmd: %u\n", cmd);

    switch (cmd)
    {
    case UMEM_IOC_MALLOC:
        err = get_user(kern_umem_info.umem_size, &((struct umem_info __user *)arg)->umem_size);
        if (err)
        {
            pr_info("umem_ioctl cmd malloc: failed to get umem_size\n");
            return err;
        }
        err = get_user(kern_umem_info.umem_pool, &((struct umem_info __user *)arg)->umem_pool);
        if (err)
        {
            pr_info("umem_ioctl cmd malloc: failed to get umem_pool\n");
            return err;
        }
        pr_info("umem_ioctl cmd malloc: %llu %llu\n", kern_umem_info.umem_size, kern_umem_info.umem_pool);
        if (kern_umem_info.umem_pool >= UMEM_NUM_POOL)
        {
            pr_info("umem_ioctl cmd malloc: invalid pool\n");
            return -EINVAL;
        }
        // TODO
        pr_info("todo\n");
        spin_lock(&userinfo_lock);

        /* Find or create userinfo of current process */
        userinfo = find_userinfo(current);
        if (userinfo == NULL) {
            userinfo = kmalloc(sizeof(struct userinfo_t), GFP_KERNEL);
            userinfo->user = current;
            INIT_LIST_HEAD(&userinfo->block_head);
            list_add(&userinfo->list, &userinfo_head);
        }

        /* Add new blockinfo to blocklist */
        struct umem_block_t* block = kmalloc(sizeof(struct umem_block_t), GFP_KERNEL);
        block->pool = kern_umem_info.umem_pool;
        block->size = kern_umem_info.umem_size;
        block->vaddr = vm_mmap(NULL, 0, kern_umem_info.umem_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
        pr_info("umem_ioctl cmd malloc: %p\n", (void *)block->vaddr);
        block->page = NULL;
        list_add(&block->blocklist, &userinfo->block_head);

        spin_unlock(&userinfo_lock);

        return block->vaddr;


    case UMEM_IOC_FREE:
        err = get_user(kern_umem_info.umem_addr, &((struct umem_info __user *)arg)->umem_addr);
        if (err)
        {
            pr_info("umem_ioctl cmd free: failed to get umem_addr\n");
            return err;
        }
        pr_info("umem_ioctl cmd free: %px\n", (void *)kern_umem_info.umem_addr);
        // TODO
        pr_info("todo\n");
        spin_lock(&userinfo_lock);

        /* Find current userinfo */
        userinfo = find_userinfo(current);
        if (userinfo == NULL) {
            pr_info("umem_ioctl cmd free: failed to find current userinfo\n");
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }

        /* Locate the block to be freed */
        blockinfo = find_blockinfo(userinfo, kern_umem_info.umem_addr);
        if (blockinfo == NULL) {
            pr_info("umem_ioctl cmd free: failed to find blockinfo\n");
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }

        vm_munmap(blockinfo->vaddr, blockinfo->size);
        pr_info("umem_ioctl cmd free: free blockinfo\n");

        spin_unlock(&userinfo_lock);
        return 0;


    case UMEM_IOC_PAGE_FAULT:
        err = get_user(kern_umem_info.umem_addr, &((struct umem_info __user *)arg)->umem_addr);
        if (err)
        {
            pr_info("umem_ioctl cmd page_fault: failed to get umem_addr\n");
            return err;
        }
        pr_info("umem_ioctl cmd page_fault: %px\n", (void *)kern_umem_info.umem_addr);
        // TODO
        pr_info("todo\n");
        spin_lock(&userinfo_lock);

        /* Find the specified block and check validity */
        userinfo = find_userinfo(current);
        if (userinfo == NULL) {
            pr_info("umem_ioctl cmd page_fault: failed to find current userinfo\n");
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }
        blockinfo = find_blockinfo(userinfo, kern_umem_info.umem_addr);
        if (blockinfo == NULL) {
            pr_info("umem_ioctl cmd page_fault: failed to find blockinfo at %p\n", (void *)kern_umem_info.umem_addr);
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }

        /* Allocate required page for the block */
        int pagenum = (blockinfo->size - 1) / PAGE_SIZE + 1;
        struct page* page = alloc_pool_pages(blockinfo->pool, pagenum, current);
        if (page == NULL) {
            pr_info("umem_ioctl cmd page_fault: failed to allocate pages\n");
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }
        /* Remap vaddr to physical pages */
        struct vm_area_struct* vma = find_vma(current->mm, blockinfo->vaddr);
        // Modify vm prot 
        vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
        int ret = remap_pfn_range(vma, blockinfo->vaddr, page_to_pfn(page), blockinfo->size, vma->vm_page_prot);
        if (ret) {
            pr_info("umem_ioctl cmd page_fault: failed to remap pages\n");
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }

        spin_unlock(&userinfo_lock);

        return 0;
    }

    return -EINVAL;
}

static dev_t devt;
static struct cdev cdev;
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = umem_open,
    .release = umem_release,
    .unlocked_ioctl = umem_ioctl,
    .compat_ioctl = umem_ioctl,
};
static struct class *cls;
static struct device *dev;

static void umem_pool_init(void)
{
    // TODO
    unsigned int order = 0;

    pr_info("Initializing umem pools\n");

    INIT_LIST_HEAD(&userinfo_head);
    spin_lock_init(&userinfo_lock);

    /* Round up to 2's order */
    while ((1 << order) < UMEM_POOL_SIZE) {
        order++;
    }    
    
    for (int i = 0; i < UMEM_NUM_POOL; i++) {
        umem_pool[i].order = order;
        umem_pool[i].head = alloc_pages(0, order);
        if (umem_pool[i].head == NULL) {
            pr_warn("No enougn mem\n");
        }
        memset(umem_pool[i].pginfo, 0 ,sizeof(umem_pool[i].pginfo));
    }
}

static void umem_pool_destroy(void)
{
    // TODO
    pr_info("Freeing umem pools\n");

    struct list_head *node, *block;
    list_for_each(node, &userinfo_head) {
        struct userinfo_t* userinfo = list_entry(node, struct userinfo_t, list);

        list_for_each(block, &userinfo->block_head) {
            struct umem_block_t* umemblock = list_entry(block, struct umem_block_t, blocklist);
            list_del(block);
            kfree(umemblock);
        }
        list_del(node);
        kfree(userinfo);
    }

    for (int i = 0; i < UMEM_NUM_POOL; i++) {
        __free_pages(umem_pool[i].head, umem_pool[i].order);
    }
}


static int __init umem_init(void)
{
    int err;

    err = alloc_chrdev_region(&devt, 0, 1, UMEM_NAME);
    if (err)
    {
        goto err_alloc_chrdev_region;
    }

    cdev_init(&cdev, &fops);
    err = cdev_add(&cdev, devt, 1);
    if (err)
    {
        goto err_cdev_add;
    }

    cls = class_create(UMEM_NAME);
    if (IS_ERR(cls))
    {
        err = PTR_ERR(cls);
        goto err_class_create;
    }
    dev = device_create(cls, NULL, devt, NULL, UMEM_NAME);
    if (IS_ERR(dev))
    {
        err = PTR_ERR(dev);
        goto err_device_create;
    }
    pr_info("umem installed\n");
    umem_pool_init();
    return 0;
err_device_create:
    class_destroy(cls);
err_class_create:
err_cdev_add:
    cdev_del(&cdev);
    unregister_chrdev_region(devt, 1);
err_alloc_chrdev_region:
    return err;
}

static void __exit umem_exit(void)
{
    umem_pool_destroy();
    device_destroy(cls, devt);
    class_destroy(cls);
    cdev_del(&cdev);
    unregister_chrdev_region(devt, 1);
    pr_info("umem removed\n");
}

module_init(umem_init);
module_exit(umem_exit);