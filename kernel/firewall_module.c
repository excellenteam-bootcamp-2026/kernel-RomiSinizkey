#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops firewall_hook;

static unsigned int firewall_hook_fn(
    void *priv,
    struct sk_buff *skb, 
    const struct  nf_hook_state *state)
{
    struct iphdr *ip_header;

    if(!skb)
       return NF_ACCEPT;
      
     ip_header = ip_hdr(skb);

    if (!ip_header)
        return NF_ACCEPT;

    pr_info_ratelimited(
        "firewall_module: src=%pI4 dst=%pI4\n",
        &ip_header->saddr,
        &ip_header->daddr
    );
    
    return NF_ACCEPT;
}
    


static int __init firewall_init(void)
{
    int result;

    printk(KERN_INFO "firewall_module: loaded\n");
    printk(KERN_INFO "Hello World\n");

    firewall_hook.hook = firewall_hook_fn;
    firewall_hook.pf = NFPROTO_IPV4;
    firewall_hook.hooknum = NF_INET_PRE_ROUTING;
    firewall_hook.priority = NF_IP_PRI_FIRST;

    result = nf_register_net_hook(&init_net, &firewall_hook);

    if(result != 0){
        printk(KERN_ERR "firewall_module: failed to register Netfilter hook\n");
        return result;
    }
    return 0;
}

static void __exit firewall_exit(void)
{
    nf_unregister_net_hook(&init_net, &firewall_hook);


    printk(KERN_INFO "firewall_module: unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romi");
MODULE_DESCRIPTION("Basic firewall kernel module");
