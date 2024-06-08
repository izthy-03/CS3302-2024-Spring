# CS3302 Project 3 - umem kernel module

## 1. 框架

### 元数据结构

#### umem_pool_t 内存池结构
每片内存池结构如下
`head`-该内存池物理页页框起始地址
`order`-向buddy sys申请的连续页阶次，也就是该内存池有$2^{order}$个物理页
`pginfo_t`-保存每个物理页的额外信息

```c
struct umem_pool_t {
    struct page* head;
    unsigned int order;

    struct pginfo_t {
        struct task_struct* owner;
    } pginfo[UMEM_POOL_SIZE];
};
```
#### umem_block_t 内存块结构
对每个`umem_malloc()`请求都保存一个`umem_block_t`结构

Fields: 
`list_head blocklist` - "继承"Linux链表结构，使其作为一个节点，与其他相同进程所申请的内存块串成一个链表
`struct page* page` - 该块起始物理页的页框地址，未实际分配物理页时为NULL
`unsigned long vaddr` - 该块的用户空间虚拟地址
`unsigned long size` - 块大小
`unsigned int pool` - 块所属内存池编号

```c
/* Malloc block info */
struct umem_block_t {
    struct list_head blocklist;
    struct page* page;
    unsigned long vaddr;
    unsigned long size;
    unsigned int pool;
};
```

#### userinfo_t 用户进程信息
为每个调用该模块的进程都维护一个`userinfo_t`

Fields:
`struct list_head list` - 将每个`userinfo_t`串作链表
`struct task_struct* user` - 该用户进程的`task_struct`指针
`struct list_head block_head` - 该用户进程所请求内存块的链表头节点


```c
struct userinfo_t {
    struct list_head list;
    struct task_struct* user;
    struct list_head block_head;
};
```

#### 实例
`userinfo_lock`用来保护上述数据结构同步读写
```c
struct umem_pool_t umem_pool[UMEM_NUM_POOL];
struct list_head userinfo_head;
spinlock_t userinfo_lock;
```

组织如下
![img](1.png)

### 流程
![img](2.png)


## 2. 具体实现

### umem_pool_init()
用`alloc_pages()`为每个内存池各自分配`UMEM_POOL_SIZE`个连续物理页
并初始化userinfo链表头节点`userinfo_head`和自旋锁`userinfo_lock`
```c
static void umem_pool_init(void)
{
    pr_info("Initializing umem pools\n");

    unsigned int order = 0;

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
```

### umem_pool_destroy()
首先遍历userinfo链表和每个节点的blockinfo链表
删除所有节点并释放由`kalloc()`申请的数据结构，防止内核内存泄漏
最后调用`__free_pages()`释放每个内存池在初始化阶段所申请的物理页
```c
static void umem_pool_destroy(void)
{
    pr_info("Freeing umem pools\n");

    struct list_head *node, *block, *nn, *nb;
    list_for_each_safe(node, nn, &userinfo_head) {
        struct userinfo_t* userinfo = list_entry(node, struct userinfo_t, list);

        list_for_each_safe(block, nb, &userinfo->block_head) {
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
```
### umem_open()
用户进程在`umem_user_init()`中会打开字符设备`/dev/umem`，然后进入内核模块中注册的`fops.open`方法，也就是`umem_open()`
为这个新进程创建一个userinfo节点，维护进链表。同时把这个节点地址存入对应的`filp->private_data`中备用

```c
static int umem_open(struct inode *inode, struct file *filp)
{
    // TODO
    pr_info("umem_open: Process %px opened\n", current);
    struct userinfo_t* userinfo = kmalloc(sizeof(struct userinfo_t), GFP_KERNEL);
    userinfo->user = current;
    INIT_LIST_HEAD(&userinfo->block_head);

    spin_lock(&userinfo_lock);
    list_add(&userinfo->list, &userinfo_head);
    spin_unlock(&userinfo_lock);

    filp->private_data = userinfo;
    return 0;
}
```

### umem_release()
用户进程在退出时会关闭字符设备`/dev/umem`，然后进入内核模块中注册的`fops.release`方法，也就是`umem_release()`
首先将保存在`filp->private_data`中的userinfo指针取出，然后遍历该进程的blockinfo链表，删除所有节点，释放所有未主动free的块

**血与泪的教训**
Linux的`list_del`宏在删除时会将被删除节点的`next`和`prev`改成LIST_POISON1和 LIST_POISON2，如果此时在用`list_for_each(pos, head)`遍历该链表，就会导致`pos->next`变为野指针，在下个循环将直接产生内核的`Null pointer dereference`导致**kernel panic**

为了解决这个问题，改用`list_for_each_safe(pos, n, head)`，这个宏引入了`struct list_head* n`来暂存`pos->next`，避免了删除pos产生的副作用

```c
static int umem_release(struct inode *inode, struct file *filp)
{
    pr_info("umem_release: Process %px released\n", current);
    spin_lock(&userinfo_lock);
    struct userinfo_t* userinfo = filp->private_data;

    /* Release unfreed pages in pool */
    struct list_head *block, *nb;
    list_for_each_safe(block, nb, &userinfo->block_head) {
        // MUST USE list_for_each_SAFE here, to avoid side-effects caused by list_del()
        struct umem_block_t* umemblock = list_entry(block, struct umem_block_t, blocklist);
        pr_info("umem_release: now at block %px", (void *)umemblock);
        if (umemblock->page != NULL) {
            int pagenum = (umemblock->size - 1) / PAGE_SIZE + 1;
            int offset = umemblock->page - umem_pool[umemblock->pool].head;
            free_pool_pages(umemblock->pool, pagenum, offset);
            pr_info("umem_release: free pages %px\n", (void *)umemblock->page);
        }
        list_del(block);
        pr_info("umem_release: free block %px\n", (void *)umemblock);
        kfree(umemblock);
    }

    list_del(&userinfo->list);
    kfree(userinfo);
    spin_unlock(&userinfo_lock);
    return 0;
}
```

### umem_ioctl()
先定义所需信息
```c
static long umem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long err;
    struct umem_info kern_umem_info;

    struct userinfo_t* userinfo;
    struct umem_block_t* blockinfo;
```

#### case UMEM_IOC_MALLOC:
创建一个blockinfo节点，并插入当前进程的block_head链表中
由于是on-demand paging, 因此在这无需分配物理页，只要用`vm_mmap()`申请一个虚拟地址就好了

需要注意的是本模块由于没有实现COW机制，因此在申请虚拟地址时应作为共享对象来申请`MAP_SHARED`，否则在后续remap时`PROT_WRITE`位不会被设置，会造成写时segment fault

最后用`put_user`宏将申请到的`vaddr`放到用户空间的缓冲区中

```c
    switch (cmd)
    {
    case UMEM_IOC_MALLOC:
        err = get_user(kern_umem_info.umem_size, &((struct umem_info __user *)arg)->umem_size);
        if (err) {}
        err = get_user(kern_umem_info.umem_pool, &((struct umem_info __user *)arg)->umem_pool);
        if (err) {}
        pr_info("umem_ioctl cmd malloc: %llu %llu\n", kern_umem_info.umem_size, kern_umem_info.umem_pool);
        
        if (kern_umem_info.umem_pool >= UMEM_NUM_POOL)
        {
            pr_info("umem_ioctl cmd malloc: invalid pool\n");
            return -EINVAL;
        }
        // TODO
        pr_info("umem_ioctl cmd malloc: mallocing new block\n");
        spin_lock(&userinfo_lock);

        /* Find or create userinfo of current process */
        userinfo = find_userinfo(current);
        if (userinfo == NULL) {
            userinfo = kmalloc(sizeof(struct userinfo_t), GFP_KERNEL);
            userinfo->user = current;
            INIT_LIST_HEAD(&userinfo->block_head);
            list_add(&userinfo->list, &userinfo_head);
        }
        pr_info("umem_ioctl cmd malloc: userinfo %px\n", (void *)userinfo);

        /* Add new blockinfo to blocklist */
        struct umem_block_t* block = kmalloc(sizeof(struct umem_block_t), GFP_KERNEL);
        block->pool = kern_umem_info.umem_pool;
        block->size = kern_umem_info.umem_size;
        block->vaddr = vm_mmap(NULL, 0, kern_umem_info.umem_size, PROT_NONE, MAP_SHARED | MAP_ANONYMOUS, 0);
        block->page = NULL;
        pr_info("umem_ioctl cmd malloc: vm_mmap %px\n", (void *)block->vaddr);
        pr_info("umem_ioctl cmd malloc: block %px\n", (void *)block);

        list_add(&block->blocklist, &userinfo->block_head);
        pr_info("umem_ioctl cmd malloc: add block to blocklist\n");

        spin_unlock(&userinfo_lock);

        put_user(block->vaddr, &((struct umem_info __user *)arg)->umem_addr);
        return 0;
```

#### case UMEM_IOC_FREE:

先在维护的blockinfo链表中寻找用户空间传进来的`umem_addr`所对应的块
用`vm_munmap()`删除用户页表上的这一条目
如果这个块有分配物理页，那么把这些内存池中的页取消标记一下

```c
    case UMEM_IOC_FREE:
        err = get_user(kern_umem_info.umem_addr, &((struct umem_info __user *)arg)->umem_addr);
        if (err) {}
        pr_info("umem_ioctl cmd free: %px\n", (void *)kern_umem_info.umem_addr);
        // TODO
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

        /* Free blockinfo and reset umem_pool pages */
        if (blockinfo->page != NULL) {
            int pagenum = (blockinfo->size - 1) / PAGE_SIZE + 1;
            int offset = blockinfo->page - umem_pool[blockinfo->pool].head;
            free_pool_pages(blockinfo->pool, pagenum, offset);
            pr_info("umem_ioctl cmd free: free pages %px\n", (void *)blockinfo->page);
        }
        list_del(&blockinfo->blocklist);
        kfree(blockinfo);
        pr_info("umem_ioctl cmd free: free blockinfo\n");

        spin_unlock(&userinfo_lock);
        return 0;
```

#### case UMEM_IOC_PAGE_FAULT:
首先找到引起page fault的地址所属的block，如果没有，那么就是用户恶意读写未申请的非法区域

再为这个block分配物理内存，在其所属的内存池中寻找连续的$\lfloor \frac{blockinfo->size-1}{PAGE\_SIZE} \rfloor + 1$张物理页，没有就返回`-ENOMEM`

随后用`find_vma()`定位vaddr所属的`vm_area_struct`
修改其权限`vm_page_prot`，添加读写权限`VM_READ | VM_WRITE`位

最后再调用`remap_pfn_page()`来完成物理地址映射

```c
    case UMEM_IOC_PAGE_FAULT:
        err = get_user(kern_umem_info.umem_addr, &((struct umem_info __user *)arg)->umem_addr);
        if (err) {}
        pr_info("umem_ioctl cmd page_fault: %px\n", (void *)kern_umem_info.umem_addr);
        // TODO
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
            pr_info("umem_ioctl cmd page_fault: failed to find blockinfo at %px\n", (void *)kern_umem_info.umem_addr);
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }
        if (blockinfo->page != NULL) {
            pr_info("umem_ioctl cmd page_fault: page already allocated\n");
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }

        /* Allocate required page for the block */
        int pagenum = (blockinfo->size - 1) / PAGE_SIZE + 1;
        struct page* page = alloc_pool_pages(blockinfo->pool, pagenum, current);
        if (page == NULL) {
            pr_info("umem_ioctl cmd page_fault: failed to allocate pages\n");
            spin_unlock(&userinfo_lock);
            return -ENOMEM;
        }
        pr_info("umem_ioctl cmd page_fault: allocated pages %px\n", (void *)page);

        /* Remap vaddr to physical pages */
        struct vm_area_struct* vma = find_vma(current->mm, blockinfo->vaddr);
        // Modify vm_prot to RW 
        vma->vm_page_prot = vm_get_page_prot(vma->vm_flags | VM_READ | VM_WRITE);
        // pr_info("vm_page_prot: %lx\n", vma->vm_page_prot);

        int ret = remap_pfn_range(vma, blockinfo->vaddr, page_to_pfn(page), blockinfo->size, vma->vm_page_prot);
        if (ret) {
            pr_info("umem_ioctl cmd page_fault: failed to remap pages\n");
            free_pool_pages(blockinfo->pool, pagenum, page - umem_pool[blockinfo->pool].head);
            spin_unlock(&userinfo_lock);
            return -EINVAL;
        }
        blockinfo->page = page;
        pr_info("umem_ioctl cmd page_fault: remapped pages\n");

        spin_unlock(&userinfo_lock);

        return 0;
    }
```

## 3. 问题
这个版本实现的内存池分配的内存最小粒度是一整页，内部碎片问题十分严重
每一个`umem_malloc()`都会被分配到未被使用的物理页上

可以考虑复用物理页，但这样就需要引入页内内存管理策略，例如slab，隐式空闲链表等，问题可能会略显复杂
