#ifndef FIREWALL_PROTOCOL_H
#define FIREWALL_PROTOCOL_H

/*
 * Shared Generic Netlink protocol between firewall-agent (user space)
 * and firewall_module.c (kernel space).
 *
 * <linux/types.h> is used instead of <stdint.h> because it is safe to
 * include from both kernel code and normal user-space C code on Linux.
 *
 * This header defines the wire contract only: family/version/limits,
 * commands, attributes, and rule field enums. It intentionally contains
 * no nla_policy tables (kernel-only) and no Netlink socket code.
 */

#include <linux/types.h>

/* Generic Netlink family identity */
#define FIREWALL_GENL_FAMILY_NAME "firewall"
#define FIREWALL_GENL_VERSION     1

/* Upper bound on the number of rules carried in one REPLACE_RULES message */
#define FIREWALL_MAX_RULES 128

/* Commands */
enum firewall_commands {
    FIREWALL_CMD_UNSPEC,
    FIREWALL_CMD_REPLACE_RULES, /* replace the complete active ruleset */
    __FIREWALL_CMD_MAX,
};
#define FIREWALL_CMD_MAX (__FIREWALL_CMD_MAX - 1)

/* Top-level message attributes */
enum firewall_attrs {
    FIREWALL_A_UNSPEC,
    FIREWALL_A_RULE_LIST, /* nested: zero or more FIREWALL_RULE_A_* entries */
    __FIREWALL_A_MAX,
};
#define FIREWALL_A_MAX (__FIREWALL_A_MAX - 1)

/* Per-rule attributes, nested inside each entry of FIREWALL_A_RULE_LIST */
enum firewall_rule_attrs {
    FIREWALL_RULE_A_UNSPEC,
    FIREWALL_RULE_A_ID,    /* __u32, database id; optional, logging/debugging only */
    FIREWALL_RULE_A_TYPE,  /* __u8, enum firewall_rule_type */
    FIREWALL_RULE_A_MODE,  /* __u8, enum firewall_rule_mode */
    FIREWALL_RULE_A_VALUE, /* __u32, meaning depends on FIREWALL_RULE_A_TYPE */
    __FIREWALL_RULE_A_MAX,
};
#define FIREWALL_RULE_A_MAX (__FIREWALL_RULE_A_MAX - 1)

/*
 * Rule types. For FIREWALL_RULE_TYPE_IP, FIREWALL_RULE_A_VALUE holds an
 * IPv4 address in network byte order, matched against both the source
 * and destination address of a packet.
 *
 * FIREWALL_RULE_TYPE_PORT is reserved for future use. It must not be
 * enforced or interpreted by the kernel module yet.
 */
enum firewall_rule_type {
    FIREWALL_RULE_TYPE_UNSPEC = 0,
    FIREWALL_RULE_TYPE_IP     = 1,
    FIREWALL_RULE_TYPE_PORT   = 2, /* reserved, not implemented yet */
};

/*
 * Rule modes. Only blacklist is implemented for now: a match causes
 * NF_DROP, and anything unmatched falls through to NF_ACCEPT.
 */
enum firewall_rule_mode {
    FIREWALL_RULE_MODE_UNSPEC    = 0,
    FIREWALL_RULE_MODE_BLACKLIST = 1,
};

#endif /* FIREWALL_PROTOCOL_H */
