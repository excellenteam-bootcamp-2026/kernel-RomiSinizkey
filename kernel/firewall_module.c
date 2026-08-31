#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <net/genetlink.h>

#include "firewall_protocol.h"

static struct nf_hook_ops firewall_hook;

struct firewall_ruleset {
    __be32 blocked_ips[FIREWALL_MAX_RULES];
    unsigned int count;
};

/* Active ruleset enforced by the Netfilter hook. Starts empty (all-zero)
 * until the Generic Netlink REPLACE_RULES handler calls
 * firewall_replace_ruleset(). Until a valid message arrives, every
 * packet is accepted - this is expected.
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
 * Install a complete replacement ruleset, called only after the caller
 * has already validated every rule (type == IP, mode == blacklist).
 * This helper enforces the count bound and performs the atomic swap.
 *
 * The replacement is built up locally first and only copied into the
 * active ruleset while holding the write lock, so readers never observe
 * a partially updated ruleset and a rejected call leaves the previously
 * active ruleset completely untouched.
 *
 * count == 0 installs an empty ruleset (ips may be NULL in that case).
 * Returns 0 on success, -EINVAL if count exceeds FIREWALL_MAX_RULES or
 * if count > 0 but ips is NULL.
 */
static int firewall_replace_ruleset(const __be32 *ips, unsigned int count)
{
    struct firewall_ruleset new_ruleset = { 0 };

    if (count > FIREWALL_MAX_RULES)
        return -EINVAL;

    if (count > 0) {
        if (!ips)
            return -EINVAL;

        memcpy(new_ruleset.blocked_ips, ips, count * sizeof(*ips));
    }

    new_ruleset.count = count;

    write_lock_bh(&ruleset_lock);
    active_ruleset = new_ruleset;
    write_unlock_bh(&ruleset_lock);

    return 0;
}

/* Top-level Generic Netlink attribute policy for this family.
 * FIREWALL_A_RULE_LIST is a nested attribute; each nested child is
 * itself parsed against firewall_rule_policy below.
 */
static const struct nla_policy firewall_genl_policy[FIREWALL_A_MAX + 1] = {
    [FIREWALL_A_RULE_LIST] = { .type = NLA_NESTED },
};

/* Per-rule attribute policy, used to parse each nested rule entry. */
static const struct nla_policy firewall_rule_policy[FIREWALL_RULE_A_MAX + 1] = {
    [FIREWALL_RULE_A_ID]    = { .type = NLA_U32 },
    [FIREWALL_RULE_A_TYPE]  = { .type = NLA_U8 },
    [FIREWALL_RULE_A_MODE]  = { .type = NLA_U8 },
    [FIREWALL_RULE_A_VALUE] = { .type = NLA_U32 },
};

/*
 * Handler for FIREWALL_CMD_REPLACE_RULES.
 *
 * Parses FIREWALL_A_RULE_LIST as a nested list of rules, validating each
 * one against the fields this stage supports (IPv4 blacklist only). The
 * entire message is rejected - and the active ruleset left untouched -
 * if any rule is missing a required field, uses an unsupported type or
 * mode, is malformed, or the total count exceeds FIREWALL_MAX_RULES.
 *
 * The validated addresses are collected into a local array first; only
 * once every rule has passed validation is firewall_replace_ruleset()
 * called to publish the new snapshot.
 */
static int firewall_genl_replace_rules(struct sk_buff *skb, struct genl_info *info)
{
    struct nlattr *rule_list_attr = info->attrs[FIREWALL_A_RULE_LIST];
    struct nlattr *rule_tb[FIREWALL_RULE_A_MAX + 1];
    struct nlattr *rule_attr;
    __be32 new_ips[FIREWALL_MAX_RULES];
    unsigned int new_count = 0;
    int rem;
    int err;

    if (!rule_list_attr)
        return -EINVAL;

    nla_for_each_nested(rule_attr, rule_list_attr, rem) {
        u8 type;
        u8 mode;
        u32 value;

        if (new_count >= FIREWALL_MAX_RULES)
            return -E2BIG;

        err = nla_parse_nested(rule_tb, FIREWALL_RULE_A_MAX, rule_attr,
                    firewall_rule_policy, NULL);
        if (err)
            return err;

        if (!rule_tb[FIREWALL_RULE_A_TYPE] ||
            !rule_tb[FIREWALL_RULE_A_MODE] ||
            !rule_tb[FIREWALL_RULE_A_VALUE])
            return -EINVAL;

        type = nla_get_u8(rule_tb[FIREWALL_RULE_A_TYPE]);
        mode = nla_get_u8(rule_tb[FIREWALL_RULE_A_MODE]);
        value = nla_get_u32(rule_tb[FIREWALL_RULE_A_VALUE]);

        if (type != FIREWALL_RULE_TYPE_IP || mode != FIREWALL_RULE_MODE_BLACKLIST)
            return -EINVAL;

        new_ips[new_count] = (__be32)value;
        new_count++;
    }

    err = firewall_replace_ruleset(new_ips, new_count);
    if (err)
        return err;

    pr_info("firewall_module: replaced active ruleset (%u IP rule(s) active)\n", new_count);

    return 0;
}

static const struct genl_ops firewall_genl_ops[] = {
    {
        .cmd = FIREWALL_CMD_REPLACE_RULES,
        .doit = firewall_genl_replace_rules,
        .flags = GENL_ADMIN_PERM,
    },
};

static struct genl_family firewall_genl_family = {
    .name = FIREWALL_GENL_FAMILY_NAME,
    .version = FIREWALL_GENL_VERSION,
    .maxattr = FIREWALL_A_MAX,
    .policy = firewall_genl_policy,
    .module = THIS_MODULE,
    .ops = firewall_genl_ops,
    .n_ops = ARRAY_SIZE(firewall_genl_ops),
};

static int __init firewall_init(void)
{
    int result;

    printk(KERN_INFO "firewall_module: loaded\n");
    printk(KERN_INFO "Hello World\n");

    result = genl_register_family(&firewall_genl_family);

    if (result != 0) {
        printk(KERN_ERR "firewall_module: failed to register Generic Netlink family\n");
        return result;
    }

    firewall_hook.hook = firewall_hook_fn;
    firewall_hook.pf = NFPROTO_IPV4;
    firewall_hook.hooknum = NF_INET_PRE_ROUTING;
    firewall_hook.priority = NF_IP_PRI_FIRST;

    result = nf_register_net_hook(&init_net, &firewall_hook);

    if(result != 0){
        printk(KERN_ERR "firewall_module: failed to register Netfilter hook\n");
        genl_unregister_family(&firewall_genl_family);
        return result;
    }
    return 0;
}

static void __exit firewall_exit(void)
{
    nf_unregister_net_hook(&init_net, &firewall_hook);
    genl_unregister_family(&firewall_genl_family);

    printk(KERN_INFO "firewall_module: unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romi");
MODULE_DESCRIPTION("Basic firewall kernel module");
