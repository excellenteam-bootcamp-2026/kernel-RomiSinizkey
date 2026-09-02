#include <stdio.h>
#include <arpa/inet.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>

#include "firewall_protocol.h"

/* Temporary hardcoded test rule. Not read from Node.js yet - this step
 * only proves that a message built here reaches firewall_module.c and
 * ends up enforced by Netfilter.
 */
#define TEST_RULE_IP "8.8.8.8"

/*
 * Allocates a libnl socket, connects it to the kernel's Generic Netlink
 * bus, and resolves the "firewall" family's numeric id. The family id
 * is assigned dynamically by the kernel when firewall_module.ko
 * registers it, so it must be looked up by name at runtime rather than
 * hardcoded.
 *
 * On success, returns 0 with the connected socket in *sock_out and the
 * resolved family id in *family_id_out. On failure, returns a negative
 * value and leaves *sock_out as NULL.
 */
static int connect_netlink(struct nl_sock **sock_out, int *family_id_out)
{
    struct nl_sock *sock;
    int family_id;

    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "firewall-agent: failed to allocate netlink socket\n");
        return -1;
    }

    if (genl_connect(sock) != 0) {
        fprintf(stderr, "firewall-agent: failed to connect to Generic Netlink\n");
        nl_socket_free(sock);
        return -1;
    }

    family_id = genl_ctrl_resolve(sock, FIREWALL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr,
            "firewall-agent: could not resolve Generic Netlink family \"%s\" "
            "(is firewall_module.ko loaded?): %s\n",
            FIREWALL_GENL_FAMILY_NAME, nl_geterror(family_id));
        nl_socket_free(sock);
        return family_id;
    }

    *sock_out = sock;
    *family_id_out = family_id;
    return 0;
}

/*
 * Builds one FIREWALL_CMD_REPLACE_RULES message containing a single
 * hardcoded test rule (IP blacklist, TEST_RULE_IP), sends it, and waits
 * for the kernel's ACK or error reply.
 *
 * Byte order: inet_pton() writes addr.s_addr in network byte order -
 * the same __be32 representation the kernel already uses for
 * ip_header->saddr/daddr (see firewall_hook_fn in firewall_module.c).
 * Generic Netlink attributes are plain byte containers: nla_put_u32()
 * and the kernel's nla_get_u32() do not perform any byte-order
 * conversion of their own, they just copy/read the 4 bytes as-is. So
 * addr.s_addr is passed into FIREWALL_RULE_A_VALUE unchanged, with no
 * extra htonl()/ntohl() call - adding one would re-swap bytes that are
 * already in exactly the representation the kernel expects, and would
 * silently send the wrong address on a little-endian machine (which
 * this project's VM is).
 */
static int send_test_ruleset(struct nl_sock *sock, int family_id)
{
    struct nl_msg *msg;
    struct nlattr *rule_list;
    struct nlattr *rule;
    struct in_addr addr;
    int err;

    if (inet_pton(AF_INET, TEST_RULE_IP, &addr) != 1) {
        fprintf(stderr, "firewall-agent: invalid test IPv4 address\n");
        return -1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "firewall-agent: failed to allocate netlink message\n");
        return -1;
    }

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id, 0,
              NLM_F_REQUEST | NLM_F_ACK, FIREWALL_CMD_REPLACE_RULES,
              FIREWALL_GENL_VERSION)) {
        fprintf(stderr, "firewall-agent: failed to build message header\n");
        nlmsg_free(msg);
        return -1;
    }

    rule_list = nla_nest_start(msg, FIREWALL_A_RULE_LIST);
    if (!rule_list) {
        fprintf(stderr, "firewall-agent: failed to start rule list attribute\n");
        nlmsg_free(msg);
        return -1;
    }

    /* One rule entry inside the list. The type tag passed here (1) is
     * only a per-entry index inside the nested list; the kernel walks
     * this list with nla_for_each_nested(), which does not inspect it.
     */
    rule = nla_nest_start(msg, 1);
    if (!rule) {
        fprintf(stderr, "firewall-agent: failed to start rule entry\n");
        nlmsg_free(msg);
        return -1;
    }

    err = nla_put_u8(msg, FIREWALL_RULE_A_TYPE, FIREWALL_RULE_TYPE_IP);
    err = err ? err : nla_put_u8(msg, FIREWALL_RULE_A_MODE, FIREWALL_RULE_MODE_BLACKLIST);
    err = err ? err : nla_put_u32(msg, FIREWALL_RULE_A_VALUE, addr.s_addr);
    if (err) {
        fprintf(stderr, "firewall-agent: failed to add rule attributes: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        return err;
    }

    nla_nest_end(msg, rule);
    nla_nest_end(msg, rule_list);

    printf("firewall-agent: sending REPLACE_RULES (1 rule: blacklist %s)\n", TEST_RULE_IP);

    err = nl_send_sync(sock, msg); /* sends msg and waits for ACK/error; frees msg either way */
    if (err < 0) {
        fprintf(stderr, "firewall-agent: kernel rejected REPLACE_RULES: %s\n", nl_geterror(err));
        return err;
    }

    printf("firewall-agent: kernel acknowledged REPLACE_RULES\n");
    return 0;
}

int main(void)
{
    struct nl_sock *sock = NULL;
    int family_id;
    int err;

    printf("firewall-agent started\n");

    err = connect_netlink(&sock, &family_id);
    if (err != 0)
        return 1;

    err = send_test_ruleset(sock, family_id);

    nl_socket_free(sock);

    if (err != 0)
        return 1;

    return 0;
}
