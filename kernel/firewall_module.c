#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init firewall_init(void)
{
    printk(KERN_INFO "firewall_module: loaded\n");
    printk(KERN_INFO "Hello World\n");
    return 0;
}

static void __exit firewall_exit(void)
{
    printk(KERN_INFO "firewall_module: unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romi");
MODULE_DESCRIPTION("Basic firewall kernel module");
