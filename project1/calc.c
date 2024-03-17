#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kstrtox.h>

#define MAX_SIZE 128
#define ID "521021911101"

static int operand1;
module_param(operand1, int, 0);
static char *operator;
module_param(operator, charp, 0);
static int operand2[MAX_SIZE];
static int ninp;
module_param_array(operand2, int, &ninp, 0);

static struct proc_dir_entry *proc_ent;
static struct proc_dir_entry *proc_dir;
static char output[MAX_SIZE];
int out_len;

static ssize_t proc_read(struct file *fp, char __user *ubuf, size_t len, loff_t *pos)
{
    /* TODO */
    out_len = 0;
    memset(output, 0 ,sizeof(output));
    if (*pos > 0) return 0;
    if (len < MAX_SIZE) return -EFAULT;

    pr_info("procfile read %s\n", fp->f_path.dentry->d_name.name);
    char tmpbuf[16];   // temporary buffer to store each int
    for (int i = 0; i < ninp; i++) {
        /* Calculated each number */
        char delimiter = (i < ninp - 1) ? ',' : '\n';
        if (strcmp(operator, "add") == 0) {
            out_len += sprintf(tmpbuf, "%d%c", operand1 + operand2[i], delimiter);
        } else if (strcmp(operator, "mul") == 0) {
            out_len += sprintf(tmpbuf, "%d%c", operand1 * operand2[i], delimiter);
        } else {
            out_len += sprintf(output, "Unknown operator\n");
            break;
        }

        /* Check buffer overflow */
        if (out_len > MAX_SIZE) {
            pr_info("inner buffer overflow, stop reading\n");
            break;
        }

        /* Append to output buffer */
        strcat(output, tmpbuf);
    }

    if (copy_to_user(ubuf, output, out_len)) return -EFAULT;
    *pos = out_len;
    return out_len;

}

static ssize_t proc_write(struct file *fp, const char __user *ubuf, size_t len, loff_t *pos)
{
    /* TODO */
    char buf[MAX_SIZE];

    if (*pos > 0 || len > MAX_SIZE) return -EFAULT;
    if (copy_from_user(buf, ubuf, len)) return -EFAULT;
 
    operand1 = simple_strtol(buf, NULL, 0);
    pr_info("change operand1 to %d\n", operand1);

    return len;
}

static const struct proc_ops proc_ops = {
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int __init proc_init(void)
{
    /* TODO */
    // remove_proc_entry(ID, NULL);
    proc_dir = proc_mkdir(ID, NULL);
    proc_ent = proc_create("calc", 0666, proc_dir, &proc_ops);

    if (proc_dir == NULL || proc_ent == NULL) {
        proc_remove(proc_dir);
        proc_remove(proc_ent);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", ID);
        return -ENOMEM;
    }
    printk(KERN_INFO "/proc/%s created\n", ID);
    return 0;
}

static void __exit proc_exit(void)
{
    /* TODO */
    proc_remove(proc_dir);
    proc_remove(proc_ent);
    printk(KERN_INFO "/proc/%s removed\n", ID);
    return;
}

module_init(proc_init);
module_exit(proc_exit);
MODULE_LICENSE("GPL");