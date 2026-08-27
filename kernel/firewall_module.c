#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/inet.h>

static struct nf_hook_ops firewall_hook;

#define MAX_BLOCKED_IPS 32

static __be32 blocked_sources[MAX_BLOCKED_IPS];
static unsigned int blocked_sources_count = 0;

static __be32 blocked_destinations[MAX_BLOCKED_IPS];
static unsigned int blocked_destinations_count = 0;

static bool is_ip_in_list(
    __be32 ip,
    const __be32 *list,
    unsigned int count)
{
    unsigned int i;

    for (i = 0; i < count; i++) {
        if (ip == list[i])
            return true;
    }

    return false;
}

static bool is_blocked_source(__be32 ip)
{
    return is_ip_in_list(
        ip,
        blocked_sources,
        blocked_sources_count
    );
}

static bool is_blocked_destination(__be32 ip)
{
    return is_ip_in_list(
        ip,
        blocked_destinations,
        blocked_destinations_count
    );
}


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
    
    if (is_blocked_source(ip_header->saddr)) {
        pr_info_ratelimited(
            "firewall_module: dropping packet from %pI4\n",
            &ip_header->saddr
        );

        return NF_DROP;
    }

    if (is_blocked_destination(ip_header->daddr)) {
        pr_info_ratelimited(
            "firewall_module: dropping packet to %pI4\n",
            &ip_header->daddr
        );

        return NF_DROP;
    }

    return NF_ACCEPT;
}
    


static int __init firewall_init(void)
{
    int result;

    printk(KERN_INFO "firewall_module: loaded\n");
    printk(KERN_INFO "Hello World\n");

    blocked_sources[0] = in_aton("8.8.8.8");
    blocked_sources[1] = in_aton("1.1.1.1");
    blocked_sources_count = 2;

    blocked_destinations[0] = in_aton("10.0.2.15");
    blocked_destinations_count = 1;

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
