#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "firewall_protocol.h"

static struct nf_hook_ops firewall_hook;

struct firewall_ruleset {
    __be32 blocked_ips[FIREWALL_MAX_RULES];
    unsigned int count;
};

/* Active ruleset enforced by the Netfilter hook. Starts empty (all-zero)
 * until a future Generic Netlink handler calls firewall_replace_ruleset().
 * Until then, every packet is accepted - this is expected.
 */
static struct firewall_ruleset active_ruleset;
static DEFINE_RWLOCK(ruleset_lock);

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

static unsigned int firewall_hook_fn(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    bool matched;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);

    if (!ip_header)
        return NF_ACCEPT;

    read_lock_bh(&ruleset_lock);
    matched = is_ip_in_list(ip_header->saddr, active_ruleset.blocked_ips, active_ruleset.count) ||
              is_ip_in_list(ip_header->daddr, active_ruleset.blocked_ips, active_ruleset.count);
    read_unlock_bh(&ruleset_lock);

    if (matched) {
        pr_info_ratelimited(
            "firewall_module: dropping packet (src %pI4, dst %pI4)\n",
            &ip_header->saddr,
            &ip_header->daddr
        );

        return NF_DROP;
    }

    return NF_ACCEPT;
}

/*
 * Install a complete replacement ruleset, to be called by the future
 * Generic Netlink REPLACE_RULES handler once rule type/mode validation
 * has already happened. This helper only enforces the count bound and
 * performs the atomic swap - it does not parse or validate rule fields.
 *
 * The replacement is built up locally first and only copied into the
 * active ruleset while holding the write lock, so readers never observe
 * a partially updated ruleset and a rejected call leaves the previously
 * active ruleset completely untouched.
 *
 * Returns 0 on success, -EINVAL if count exceeds FIREWALL_MAX_RULES.
 */
static int __maybe_unused firewall_replace_ruleset(const __be32 *ips, unsigned int count)
{
    struct firewall_ruleset new_ruleset;

    if (count > FIREWALL_MAX_RULES)
        return -EINVAL;

    memcpy(new_ruleset.blocked_ips, ips, count * sizeof(*ips));
    new_ruleset.count = count;

    write_lock_bh(&ruleset_lock);
    active_ruleset = new_ruleset;
    write_unlock_bh(&ruleset_lock);

    return 0;
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
